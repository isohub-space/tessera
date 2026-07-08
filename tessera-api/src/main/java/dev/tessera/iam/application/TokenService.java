package dev.tessera.iam.application;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.in.TokenUseCase;
import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.port.out.TokenSignerPort;
import dev.tessera.iam.application.refresh.RefreshTokenCodec;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.authcode.IssuedTokenClaims;
import dev.tessera.iam.domain.authcode.PkceVerifier;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.client.grant.RefreshToken;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.token.ClaimSet;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

/**
 * Application service for the token endpoint: redeems a single-use authorization code for
 * a signed RFC 9068 access token (and an OIDC ID token for an {@code openid} request),
 * enforcing the Authorization Code + PKCE bindings of RFC 6749 §4.1.3.
 *
 * <p>Framework-free; the reactive fold is the only control flow. The security checks run
 * in a fixed order, and the {@code invalid_grant} collapse (RFC 6749) keeps a client from
 * learning <em>which</em> check failed:
 * <ol>
 *   <li><strong>consume the code exactly once</strong> (replay defence) — done first, so a
 *       replay is rejected even if a later check would also fail;</li>
 *   <li>the code has not expired;</li>
 *   <li>the requesting {@code client_id} equals the code's client;</li>
 *   <li>the client authenticates (Argon2id, off-loop, for a confidential client);</li>
 *   <li>the {@code redirect_uri} <strong>exactly</strong> matches the code's;</li>
 *   <li>the PKCE {@code code_verifier} satisfies the stored S256 challenge.</li>
 * </ol>
 * Only then are the tokens assembled (pure) and signed (off-loop, via the signer port).
 */
public final class TokenService implements TokenUseCase {

    private final ClientRepositoryPort clients;
    private final AuthorizationCodeStorePort codeStore;
    private final ClientSecretVerifierPort secretVerifier;
    private final TokenSignerPort signer;
    private final OpaqueIdentifierPort identifiers;
    private final RefreshTokenStorePort refreshStore;
    private final Clock clock;
    private final String issuer;
    private final Duration accessTokenTtl;
    private final Duration idTokenTtl;
    private final Duration refreshTokenTtl;
    private final boolean refreshEnabled;

    public TokenService(
            ClientRepositoryPort clients,
            AuthorizationCodeStorePort codeStore,
            ClientSecretVerifierPort secretVerifier,
            TokenSignerPort signer,
            OpaqueIdentifierPort identifiers,
            RefreshTokenStorePort refreshStore,
            Clock clock,
            String issuer,
            Duration accessTokenTtl,
            Duration idTokenTtl,
            Duration refreshTokenTtl,
            boolean refreshEnabled) {
        this.clients = requireNonNull(clients, "clients");
        this.codeStore = requireNonNull(codeStore, "codeStore");
        this.secretVerifier = requireNonNull(secretVerifier, "secretVerifier");
        this.signer = requireNonNull(signer, "signer");
        this.identifiers = requireNonNull(identifiers, "identifiers");
        this.refreshStore = requireNonNull(refreshStore, "refreshStore");
        this.clock = requireNonNull(clock, "clock");
        this.issuer = requireText(issuer, "issuer");
        this.accessTokenTtl = requirePositive(accessTokenTtl, "accessTokenTtl");
        this.idTokenTtl = requirePositive(idTokenTtl, "idTokenTtl");
        this.refreshTokenTtl = requirePositive(refreshTokenTtl, "refreshTokenTtl");
        this.refreshEnabled = refreshEnabled;
    }

    @Override
    public Uni<TokenResult> redeemAuthorizationCode(TokenRequestCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        // (1) Consume the code exactly once — the sole replay defence. A second redemption
        // (or a concurrent one) misses here and is rejected as invalid_grant.
        return codeStore.consume(command.realm(), command.code())
                .flatMap(grant -> grant == null
                        ? invalidGrant("authorization code is invalid or already used")
                        : validateAndIssue(command, grant));
    }

    private Uni<TokenResult> validateAndIssue(TokenRequestCommand command, AuthorizationGrant grant) {
        // (2) Expiry.
        if (grant.isExpired(clock.instant())) {
            return invalidGrant("authorization code has expired");
        }
        // (5) Exact redirect_uri match (RFC 6749 §4.1.3). Checked before the client lookup
        // because it needs no I/O; client identity (3) and authentication (4) follow.
        if (!grant.redirectUriMatches(command.redirectUri())) {
            return invalidGrant("redirect_uri does not match the authorization request");
        }
        // (6) PKCE proof of possession.
        if (!PkceVerifier.verifies(grant.codeChallenge(), command.codeVerifier())) {
            return invalidGrant("PKCE verification failed");
        }
        // Resolve the client to confirm identity (3) and authenticate (4).
        return clients.findByClientId(command.realm(), command.clientId())
                .flatMap(client -> {
                    if (client == null || !client.id().equals(grant.clientId())) {
                        return invalidGrant("authorization code was issued to a different client");
                    }
                    return authenticateClient(command, client)
                            .flatMap(authenticated -> authenticated
                                    ? issueTokens(command, grant, client)
                                    : invalidClient("client authentication failed"));
                });
    }

    /**
     * Authenticates the client per its kind: a public client is PKCE-only (no secret), a
     * confidential client must present a valid secret (verified Argon2id, off-loop).
     */
    private Uni<Boolean> authenticateClient(TokenRequestCommand command, Client client) {
        return switch (client) {
            case PublicClient ignored ->
                    // Public clients hold no secret; PKCE is their proof and was already checked.
                    Uni.createFrom().item(Boolean.TRUE);
            case ConfidentialClient confidential -> {
                if (command.clientSecret() == null || command.clientSecret().isBlank()) {
                    yield Uni.createFrom().item(Boolean.FALSE);
                }
                yield secretVerifier.verifySecret(
                        command.realm(), confidential.id(), command.clientSecret());
            }
        };
    }

    private Uni<TokenResult> issueTokens(
            TokenRequestCommand command, AuthorizationGrant grant, Client client) {
        Instant now = clock.instant();
        Set<String> scopes = grant.scopes();
        ClaimSet accessClaims = IssuedTokenClaims.accessToken(
                issuer,
                grant.subjectId(),
                command.clientId(),
                Set.of(issuer),
                scopes,
                identifiers.newTokenId(),
                now,
                now.plus(accessTokenTtl));

        Uni<String> accessUni = signer.sign(command.realm(), "at+jwt", accessClaims);

        boolean openId = scopes.contains("openid");
        Uni<String> idUni = openId
                ? signer.sign(command.realm(), "JWT", IssuedTokenClaims.idToken(
                        issuer, grant.subjectId(), command.clientId(), grant.nonce(),
                        now, now.plus(idTokenTtl)))
                : Uni.createFrom().nullItem();

        Uni<String> refreshUni = mintRefreshToken(command, grant, client, now);

        String scope = String.join(" ", scopes);
        return Uni.combine().all().unis(accessUni, idUni, refreshUni).asTuple()
                .map(tuple -> new TokenResult.Issued(
                        tuple.getItem1(),
                        tuple.getItem2(),
                        accessTokenTtl.toSeconds(),
                        scope,
                        tuple.getItem3()));
    }

    /**
     * Mints an initial refresh token — and creates its single-use rotation family — only when the
     * grant is enabled, the client is permitted the refresh grant, and the request carried the OIDC
     * {@code offline_access} scope. Otherwise it emits {@code null} (no refresh token), leaving the
     * response identical to before. This adds no new failure branch: it runs on the already-successful
     * issuance path.
     */
    private Uni<String> mintRefreshToken(
            TokenRequestCommand command, AuthorizationGrant grant, Client client, Instant now) {
        boolean issue = refreshEnabled
                && allowsRefresh(client)
                && grant.scopes().contains("offline_access")
                && isUuid(grant.subjectId());
        if (!issue) {
            return Uni.createFrom().nullItem();
        }
        UUID familyUuid = identifiers.newFamilyId();
        FamilyId familyId = new FamilyId(familyUuid);
        String secret = identifiers.newRefreshToken();
        String wire = RefreshTokenCodec.assemble(familyId, secret);
        RefreshTokenFamily family = new RefreshTokenFamily(
                familyId, command.realm(), grant.subjectId(), grant.clientId(),
                RefreshTokenCodec.sha256(secret), null, 0, false, now, now.plus(refreshTokenTtl));
        return refreshStore.createFamily(family).replaceWith(wire);
    }

    private static boolean allowsRefresh(Client client) {
        for (GrantType allowed : client.allowedGrants()) {
            if (allowed instanceof RefreshToken) {
                return true;
            }
        }
        return false;
    }

    /**
     * The refresh family's user id is persisted as a UUID, so only a UUID subject can anchor one. A
     * non-UUID subject therefore skips refresh issuance — the client still receives its access and ID
     * tokens rather than the whole response failing — leaving the deployment's subject-identifier
     * shape (a user UUID) as the effective precondition for durable credentials.
     */
    private static boolean isUuid(String subject) {
        try {
            UUID.fromString(subject);
            return true;
        } catch (IllegalArgumentException notUuid) {
            return false;
        }
    }

    // ------------------------------------------------------------------ helpers

    private static Uni<TokenResult> invalidGrant(String description) {
        return Uni.createFrom().item(
                new TokenResult.Failed(AuthorizationError.INVALID_GRANT, description));
    }

    private static Uni<TokenResult> invalidClient(String description) {
        return Uni.createFrom().item(
                new TokenResult.Failed(AuthorizationError.INVALID_CLIENT, description));
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }

    private static Duration requirePositive(Duration value, String name) {
        requireNonNull(value, name);
        if (value.isZero() || value.isNegative()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return value;
    }
}
