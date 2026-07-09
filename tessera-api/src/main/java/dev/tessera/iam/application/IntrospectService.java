package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.IntrospectUseCase;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort.VerifiedAccessToken;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.refresh.RefreshTokenCodec;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;

/**
 * Application service for token introspection ({@code POST /introspect}, RFC 7662).
 *
 * <p>Framework-free; the reactive fold is the only control flow. The caller is authenticated first
 * (its failure is the only surfaced error); then the token is classified and evaluated strictly
 * within the caller's own realm:
 * <ul>
 *   <li><strong>Opaque refresh token</strong> (parses via {@link RefreshTokenCodec}) — active iff its
 *       family is visible in the caller's realm, not revoked, not expired, and the presented secret
 *       is the family's <em>current</em> (live) token hash. A superseded token is inactive.</li>
 *   <li><strong>JWT access token</strong> — verified via {@link AccessTokenIntrospectorPort} against
 *       the realm's published keys; active iff it verifies and has not expired.</li>
 * </ul>
 * Every negative outcome (unknown, malformed, expired, superseded, foreign-tenant) collapses to
 * {@link IntrospectionResult.Inactive} — the non-oracle guarantee. Realm-binding is header-bound like
 * revocation, never resolved from server state: introspection must not leak across tenants.
 *
 * <p><strong>Access-token active-state is signature + expiry, not a revocation list.</strong> A
 * self-contained JWT access token reports {@code active} until its {@code exp} regardless of any later
 * revocation of the session or refresh-token family it was minted from — this is inherent to stateless
 * bearer JWTs (their short TTL bounds the exposure). Refresh-token introspection, by contrast, does
 * reflect revocation and single-use rotation. A relying party that needs immediate revocation of
 * access must use short access-token lifetimes rather than assume introspection catches it.
 */
public final class IntrospectService implements IntrospectUseCase {

    private final ClientRepositoryPort clients;
    private final ClientSecretVerifierPort secretVerifier;
    private final RefreshTokenStorePort refreshStore;
    private final AccessTokenIntrospectorPort accessTokens;
    private final Clock clock;

    public IntrospectService(
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            RefreshTokenStorePort refreshStore,
            AccessTokenIntrospectorPort accessTokens,
            Clock clock) {
        this.clients = requireNonNull(clients, "clients");
        this.secretVerifier = requireNonNull(secretVerifier, "secretVerifier");
        this.refreshStore = requireNonNull(refreshStore, "refreshStore");
        this.accessTokens = requireNonNull(accessTokens, "accessTokens");
        this.clock = requireNonNull(clock, "clock");
    }

    @Override
    public Uni<IntrospectionResult> introspect(IntrospectCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        // Authenticate the caller within its own realm; unknown client or failed secret both
        // collapse to invalid_client — the endpoint's only surfaced failure.
        return clients.findByClientId(command.realm(), command.clientId()).flatMap(client -> {
            if (client == null) {
                return authFailed();
            }
            return authenticate(command.realm(), client, command.clientSecret()).flatMap(ok -> ok
                    ? classify(command)
                    : authFailed());
        });
    }

    private Uni<IntrospectionResult> classify(IntrospectCommand command) {
        Instant now = clock.instant();
        // An opaque refresh token has exactly one '.' and a 16-byte family id; a JWT (two '.') never
        // parses here, so the ordering unambiguously routes each kind.
        Optional<RefreshTokenCodec.Parsed> refresh = RefreshTokenCodec.parse(command.token());
        if (refresh.isPresent()) {
            return introspectRefresh(command.realm(), refresh.get(), now);
        }
        return accessTokens.verify(command.realm(), command.token())
                .map(verified -> introspectAccess(verified, now));
    }

    private Uni<IntrospectionResult> introspectRefresh(
            RealmKey realm, RefreshTokenCodec.Parsed parsed, Instant now) {
        return refreshStore.find(parsed.id(), realm).map(family -> {
            // Realm-equality is explicit (belt-and-braces): the store scopes by tenant, but the
            // isolation unit is (tenant, baseline) — never report a same-tenant/other-baseline family.
            if (family == null || !family.realm().equals(realm)) {
                return inactive();
            }
            if (family.reused() || family.isExpired(now)) {
                return inactive();
            }
            // Only the family's current (live) token is active; a superseded token is inactive.
            String presentedHash = RefreshTokenCodec.sha256(parsed.secret());
            if (!presentedHash.equals(family.currentTokenHash())) {
                return inactive();
            }
            return active(refreshClaims(family));
        });
    }

    private IntrospectionResult introspectAccess(Optional<VerifiedAccessToken> verified, Instant now) {
        if (verified.isEmpty()) {
            return inactive();
        }
        VerifiedAccessToken v = verified.get();
        // Verified signature under the realm's keys; the active decision is expiry, evaluated here.
        if (v.expiresAt() != null && now.getEpochSecond() >= v.expiresAt()) {
            return inactive();
        }
        return active(new ActiveToken(
                v.scope(), v.clientId(), v.subject(), "Bearer", v.expiresAt(), v.issuedAt(), v.jti()));
    }

    private static ActiveToken refreshClaims(RefreshTokenFamily family) {
        Long exp = family.expiresAt() == null ? null : family.expiresAt().getEpochSecond();
        Long iat = family.createdAt() == null ? null : family.createdAt().getEpochSecond();
        // A refresh family carries no scope or jti; token_type is omitted (a refresh token is not a
        // bearer access token). Those members are simply absent from the response.
        return new ActiveToken(
                null, family.clientId().value().toString(), family.userId(), null, exp, iat, null);
    }

    private Uni<Boolean> authenticate(RealmKey realm, Client client, String presentedSecret) {
        return switch (client) {
            case PublicClient ignored ->
                    // A public client holds no secret; presenting its client_id is its identification.
                    Uni.createFrom().item(Boolean.TRUE);
            case ConfidentialClient confidential -> {
                if (presentedSecret == null || presentedSecret.isBlank()) {
                    yield Uni.createFrom().item(Boolean.FALSE);
                }
                yield secretVerifier.verifySecret(realm, confidential.id(), presentedSecret);
            }
        };
    }

    private static IntrospectionResult active(ActiveToken token) {
        return new IntrospectionResult.Active(token);
    }

    private static IntrospectionResult inactive() {
        return new IntrospectionResult.Inactive();
    }

    private static Uni<IntrospectionResult> authFailed() {
        return Uni.createFrom().item(new IntrospectionResult.ClientAuthenticationFailed());
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }
}
