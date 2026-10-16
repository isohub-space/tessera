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
 *
 * <p><strong>ID token on refresh.</strong> When the grant the family was issued under included
 * {@code openid}, a refresh also returns a fresh ID token for the same subject and client, without a
 * {@code nonce} (OpenID Connect Core 1.0 §12.2), so a relying party can keep its session on a token
 * the issuer signed.
 *
 * <p><strong>Reuse grace (optional, confidential clients only).</strong> A confidential client that
 * sends several requests at once (a browser-facing gateway serving parallel calls of one session
 * from several instances) can present the same refresh token twice; strict rotation then burns the
 * family and signs the user out. With a positive {@code reuseGrace} and a {@code successorKey}, each
 * successor secret of a confidential client's family is derived from its predecessor and a random
 * per-rotation salt ({@link RefreshTokenCodec#successorSecret}), and the token the last rotation
 * superseded, presented again by that client within the grace, receives that same successor with a
 * fresh access token; the family does not change. Outside the grace it is a replay as before. This
 * is a deliberate, bounded relaxation of strict rotation, of the kind several authorization servers
 * offer as a refresh-token "reuse interval" or "grace period". It is never applied to a public
 * client, for which possession of the refresh token is the only proof and replay detection must
 * stay strict; for a confidential client the refresh token is bound to its client authentication,
 * so the residual risk is a predecessor presented within the window by a party that also holds the
 * client's credentials. Off by default. The window is measured on server clocks, which are assumed
 * synchronised (NTP). Changing the key makes only in-flight reissues fail (refused, never burned).
 *
 * <p>A replay that revokes a family is logged once, at the revocation, with the family, tenant,
 * baseline and client and no token material, so a forced sign-out can be diagnosed; presentations
 * against an already revoked family are logged at debug level only.
 */
public final class RefreshService implements RefreshUseCase {

    private static final System.Logger LOG = System.getLogger(RefreshService.class.getName());

    private final ClientRepositoryPort clients;
    private final ClientSecretVerifierPort secretVerifier;
    private final TokenSignerPort signer;
    private final OpaqueIdentifierPort identifiers;
    private final RefreshTokenStorePort refreshStore;
    private final RefreshTokenTenantResolverPort tenantResolver;
    private final Clock clock;
    private final String issuer;
    private final Duration accessTokenTtl;
    private final Duration idTokenTtl;
    private final boolean enabled;
    private final Duration reuseGrace;
    private final byte[] successorKey;

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
        this(clients, secretVerifier, signer, identifiers, refreshStore, tenantResolver, clock, issuer,
                accessTokenTtl, accessTokenTtl, enabled, Duration.ZERO, null);
    }

    /**
     * As the ten-argument constructor, with the ID token's lifetime and a reuse grace.
     *
     * @param idTokenTtl   lifetime of the ID token a refresh re-issues under {@code openid}
     * @param reuseGrace   how long after a rotation its predecessor is re-issuable ({@link
     *                     Duration#ZERO} for none; never negative)
     * @param successorKey the server-side key successor secrets are derived with; required (at least
     *                     32 bytes) when {@code reuseGrace} is positive, ignored otherwise
     */
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
            Duration idTokenTtl,
            boolean enabled,
            Duration reuseGrace,
            byte[] successorKey) {
        this.reuseGrace = requireNonNull(reuseGrace, "reuseGrace");
        if (reuseGrace.isNegative()) {
            throw new IllegalArgumentException("reuseGrace must not be negative");
        }
        if (!reuseGrace.isZero() && (successorKey == null || successorKey.length < 32)) {
            throw new IllegalArgumentException(
                    "a reuse grace needs a successor key of at least 32 bytes");
        }
        this.successorKey = reuseGrace.isZero() ? null : successorKey.clone();
        this.clients = requireNonNull(clients, "clients");
        this.secretVerifier = requireNonNull(secretVerifier, "secretVerifier");
        this.signer = requireNonNull(signer, "signer");
        this.identifiers = requireNonNull(identifiers, "identifiers");
        this.refreshStore = requireNonNull(refreshStore, "refreshStore");
        this.tenantResolver = requireNonNull(tenantResolver, "tenantResolver");
        this.clock = requireNonNull(clock, "clock");
        this.issuer = requireText(issuer, "issuer");
        this.accessTokenTtl = requirePositive(accessTokenTtl, "accessTokenTtl");
        this.idTokenTtl = requirePositive(idTokenTtl, "idTokenTtl");
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
                    // The grace, and the derived successor it needs, only ever for a confidential
                    // client: a public client's refresh token is its only proof, so its replay
                    // detection stays strict.
                    Duration grace = graceOn() && client instanceof ConfidentialClient
                            ? reuseGrace : Duration.ZERO;
                    String salt = grace.isZero() ? null : identifiers.newRefreshToken();
                    String newSecret = salt == null
                            ? identifiers.newRefreshToken()
                            : RefreshTokenCodec.successorSecret(successorKey, fid, presentedSecret, salt);
                    String newHash = RefreshTokenCodec.sha256(newSecret);
                    return refreshStore
                            .consumeAndRotate(fid, authoritativeRealm, presentedHash, newHash, now,
                                    grace, salt)
                            .flatMap(outcome -> onOutcome(
                                    command, client, authoritativeRealm, fid, newSecret, presentedSecret,
                                    outcome, now));
                });
            });
        });
    }

    private Uni<TokenResult> onOutcome(
            RefreshCommand command, Client client, RealmKey authoritativeRealm, FamilyId fid,
            String newSecret, String presentedSecret, RefreshConsumeOutcome outcome, Instant now) {
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
                yield issue(command, family, authoritativeRealm, fid, newSecret, now);
            }
            // The predecessor of the live token, again, inside the reuse grace (a concurrent request
            // of the same session): answer with the successor its first presentation received. The
            // successor is re-derived, never stored, and must hash to the family's live token; if it
            // does not (the key changed, or the rotation predates the grace), refuse without burning.
            case RefreshDecision.Reissue reissue -> {
                RefreshTokenFamily family = outcome.family();
                if (family == null || !family.clientId().equals(client.id())
                        || !command.requestRealm().equals(authoritativeRealm) || !graceOn()
                        || !(client instanceof ConfidentialClient) || family.rotationSalt() == null) {
                    yield invalidGrant("refresh token is invalid");
                }
                String successor = RefreshTokenCodec.successorSecret(
                        successorKey, fid, presentedSecret, family.rotationSalt());
                if (!RefreshTokenCodec.sha256(successor).equals(family.currentTokenHash())) {
                    yield invalidGrant("refresh token is invalid");
                }
                yield issue(command, family, authoritativeRealm, fid, successor, now);
            }
            // Replay: the store already burned the family inside the CAS; revoke again (idempotent)
            // as a belt-and-braces fail-safe, then refuse.
            case RefreshDecision.Replay replay -> {
                RefreshTokenFamily family = outcome.family();
                LOG.log(replay.burns() ? System.Logger.Level.WARNING : System.Logger.Level.DEBUG,
                        replay.burns()
                                ? "Refresh-token replay: family {0} revoked (tenant {1}, baseline {2}, client {3})"
                                : "Refresh-token replay: family {0} already revoked (tenant {1}, baseline {2}, client {3})",
                        fid.value(), authoritativeRealm.tenant().value(),
                        authoritativeRealm.baseline().value(),
                        family != null ? family.clientId().value() : command.clientId());
                yield refreshStore.revokeFamily(fid, authoritativeRealm)
                        .chain(() -> invalidGrant("refresh token is invalid"));
            }
            case RefreshDecision.Unknown unknown -> invalidGrant("refresh token is invalid");
            case RefreshDecision.Expired expired -> invalidGrant("refresh token is invalid");
        };
    }

    private Uni<TokenResult> issue(
            RefreshCommand command, RefreshTokenFamily family, RealmKey authoritativeRealm,
            FamilyId fid, String refreshSecret, Instant now) {
        // The refreshed access token carries no scope: echoing the request scope would be an
        // unbounded escalation, and carrying the family's granted scope on it is a separate change.
        // An ID token is re-issued when the original grant included openid (OIDC Core §12.2), for
        // the same subject and client and without a nonce.
        ClaimSet accessClaims = IssuedTokenClaims.accessToken(
                issuer, family.userId(), command.clientId(), Set.of(issuer), Set.of(),
                identifiers.newTokenId(), now, now.plus(accessTokenTtl));
        // NOTE (follow-up): the refreshed access token is not yet sender-constrained.
        // Binding it correctly requires continuity — the refresh proof must match the
        // confirmation bound at original issuance — which needs the confirmation persisted
        // on the refresh-token family. Until then the rotated access token is an unbound
        // Bearer.
        Uni<String> accessUni = signer.sign(authoritativeRealm, "at+jwt", accessClaims);
        Uni<String> idUni = family.grantedScopes().contains("openid")
                ? signer.sign(authoritativeRealm, "JWT", IssuedTokenClaims.idToken(
                        issuer, family.userId(), command.clientId(), null, now, now.plus(idTokenTtl),
                        family.grantedScopes(), authoritativeRealm))
                : Uni.createFrom().nullItem();
        return Uni.combine().all().unis(accessUni, idUni).asTuple()
                .map(tuple -> new TokenResult.Issued(
                        tuple.getItem1(), "Bearer", tuple.getItem2(), accessTokenTtl.toSeconds(), "",
                        RefreshTokenCodec.assemble(fid, refreshSecret)));
    }

    private boolean graceOn() {
        return successorKey != null;
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
