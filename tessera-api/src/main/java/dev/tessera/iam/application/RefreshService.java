package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.RefreshUseCase;
import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.OpaqueIdentifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort.RefreshConsumeOutcome;
import dev.tessera.iam.application.port.out.RefreshTokenTenantResolverPort;
import dev.tessera.iam.application.port.out.TokenSignerPort;
import dev.tessera.iam.application.refresh.RefreshTokenCodec;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.IssuedTokenClaims;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.client.grant.RefreshToken;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshDecision;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.token.ClaimSet;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

/**
 * Application service for the refresh-token grant ({@code grant_type=refresh_token}). Rotates a
 * single-use refresh token — issuing a new access + refresh token and invalidating the presented one
 * — with family reuse-detection.
 *
 * <p>Framework-free; the reactive fold is the only control flow. Two invariants govern the tenant
 * handling and are deliberately asymmetric:
 * <ul>
 *   <li><strong>Fail-safe revocation.</strong> The family's authoritative realm is resolved from
 *       server-stored state ({@link RefreshTokenTenantResolverPort}), and rotation/replay-detection
 *       always runs against <em>that</em> realm — so a replayed or stolen token is detected and its
 *       family burned even when the caller sends a wrong or absent tenant header.</li>
 *   <li><strong>Fail-closed issuance.</strong> A new token is minted only when the request's header
 *       tenant equals the authoritative realm, and only when the family belongs to the authenticating
 *       client. Both checks run <em>after</em> {@code consumeAndRotate}, so a mismatched presentation
 *       of the live token still rotates (consumes) it but issues nothing — a self-inflicted denial
 *       that grants no capability, since reaching the rotate branch already required possessing the
 *       live secret. This ordering is deliberate: it keeps fail-safe family revocation working on any
 *       replay signal regardless of who presents the token, at the cost that a party already holding
 *       a stolen token can force its consumption (but obtains no tokens).</li>
 * </ul>
 * Every failure collapses to {@code invalid_grant} (client-auth failure to {@code invalid_client}),
 * so a caller cannot probe which check failed.
 */
public final class RefreshService implements RefreshUseCase {

    private final ClientRepositoryPort clients;
    private final ClientSecretVerifierPort secretVerifier;
    private final TokenSignerPort signer;
    private final OpaqueIdentifierPort identifiers;
    private final RefreshTokenStorePort refreshStore;
    private final RefreshTokenTenantResolverPort tenantResolver;
    private final Clock clock;
    private final String issuer;
    private final Duration accessTokenTtl;
    private final boolean enabled;

    public RefreshService(
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            TokenSignerPort signer,
            OpaqueIdentifierPort identifiers,
            RefreshTokenStorePort refreshStore,
            RefreshTokenTenantResolverPort tenantResolver,
            Clock clock,
            String issuer,
            Duration accessTokenTtl,
            boolean enabled) {
        this.clients = requireNonNull(clients, "clients");
        this.secretVerifier = requireNonNull(secretVerifier, "secretVerifier");
        this.signer = requireNonNull(signer, "signer");
        this.identifiers = requireNonNull(identifiers, "identifiers");
        this.refreshStore = requireNonNull(refreshStore, "refreshStore");
        this.tenantResolver = requireNonNull(tenantResolver, "tenantResolver");
        this.clock = requireNonNull(clock, "clock");
        this.issuer = requireText(issuer, "issuer");
        this.accessTokenTtl = requirePositive(accessTokenTtl, "accessTokenTtl");
        this.enabled = enabled;
    }

    @Override
    public Uni<TokenResult> redeem(RefreshCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        if (!enabled) {
            return invalidGrant("refresh grant is not enabled");
        }
        // (1) Parse the opaque token — a malformed token is a non-match, never an error.
        Optional<RefreshTokenCodec.Parsed> parsed = RefreshTokenCodec.parse(command.refreshToken());
        if (parsed.isEmpty()) {
            return invalidGrant("refresh token is invalid");
        }
        FamilyId fid = parsed.get().id();
        String presentedSecret = parsed.get().secret();

        // (2) Resolve the family's authoritative realm from server-stored state (header-independent).
        return tenantResolver.resolveOwningRealm(fid).flatMap(owner -> {
            if (owner.isEmpty()) {
                return invalidGrant("refresh token is invalid");
            }
            RealmKey authoritativeRealm = owner.get();

            // (3) Authenticate the client within the authoritative realm.
            return clients.findByClientId(authoritativeRealm, command.clientId()).flatMap(client -> {
                if (client == null || !allowsRefresh(client)) {
                    return invalidGrant("refresh token is invalid");
                }
                return authenticate(authoritativeRealm, client, command.clientSecret()).flatMap(ok -> {
                    if (!ok) {
                        return invalidClient("client authentication failed");
                    }
                    // (4) Mint the replacement and rotate atomically against the authoritative realm.
                    Instant now = clock.instant();
                    String presentedHash = RefreshTokenCodec.sha256(presentedSecret);
                    String newSecret = identifiers.newRefreshToken();
                    String newHash = RefreshTokenCodec.sha256(newSecret);
                    return refreshStore
                            .consumeAndRotate(fid, authoritativeRealm, presentedHash, newHash, now)
                            .flatMap(outcome -> onOutcome(
                                    command, client, authoritativeRealm, fid, newSecret, outcome, now));
                });
            });
        });
    }

    private Uni<TokenResult> onOutcome(
            RefreshCommand command, Client client, RealmKey authoritativeRealm, FamilyId fid,
            String newSecret, RefreshConsumeOutcome outcome, Instant now) {
        return switch (outcome.decision()) {
            case RefreshDecision.Rotate rotate -> {
                RefreshTokenFamily family = outcome.family();
                // The presented token must belong to the authenticating client.
                if (family == null || !family.clientId().equals(client.id())) {
                    yield invalidGrant("refresh token is invalid");
                }
                // Fail-closed issuance: mint only when the header tenant is the family's own.
                if (!command.requestRealm().equals(authoritativeRealm)) {
                    yield invalidGrant("refresh token is invalid");
                }
                // Scope is not persisted on the family yet, so the refreshed access token carries no
                // scope (echoing the request scope would be an unbounded escalation). No ID token is
                // re-issued (the family stores no nonce). Both are named follow-ups.
                ClaimSet accessClaims = IssuedTokenClaims.accessToken(
                        issuer, family.userId(), command.clientId(), Set.of(issuer), Set.of(),
                        identifiers.newTokenId(), now, now.plus(accessTokenTtl));
                yield signer.sign(authoritativeRealm, "at+jwt", accessClaims)
                        .map(jwt -> new TokenResult.Issued(
                                jwt, null, accessTokenTtl.toSeconds(), "",
                                RefreshTokenCodec.assemble(fid, newSecret)));
            }
            // Replay: the store already burned the family inside the CAS; revoke again (idempotent)
            // as a belt-and-braces fail-safe, then refuse.
            case RefreshDecision.Replay replay -> refreshStore.revokeFamily(fid, authoritativeRealm)
                    .chain(() -> invalidGrant("refresh token is invalid"));
            case RefreshDecision.Unknown unknown -> invalidGrant("refresh token is invalid");
            case RefreshDecision.Expired expired -> invalidGrant("refresh token is invalid");
        };
    }

    private Uni<Boolean> authenticate(RealmKey realm, Client client, String presentedSecret) {
        return switch (client) {
            case PublicClient ignored ->
                    // A public client holds no secret; possession of the refresh token is the proof.
                    Uni.createFrom().item(Boolean.TRUE);
            case ConfidentialClient confidential -> {
                if (presentedSecret == null || presentedSecret.isBlank()) {
                    yield Uni.createFrom().item(Boolean.FALSE);
                }
                yield secretVerifier.verifySecret(realm, confidential.id(), presentedSecret);
            }
        };
    }

    private static boolean allowsRefresh(Client client) {
        for (GrantType grant : client.allowedGrants()) {
            if (grant instanceof RefreshToken) {
                return true;
            }
        }
        return false;
    }

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
