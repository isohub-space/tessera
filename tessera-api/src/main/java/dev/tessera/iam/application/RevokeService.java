package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.RevokeUseCase;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.refresh.RefreshTokenCodec;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.Optional;

/**
 * Application service for token revocation ({@code POST /revoke}, RFC 7009).
 *
 * <p>Framework-free; the reactive fold is the only control flow. The endpoint is a deliberate
 * <strong>non-oracle</strong> — once the client authenticates, the result is always success with an
 * empty body, whatever became of the token. The security-relevant invariants:
 * <ul>
 *   <li><strong>Client-authenticated.</strong> The only surfaced failure is a client-authentication
 *       failure ({@code invalid_client}); an unknown client, a missing secret, or a wrong secret all
 *       collapse to it, learning the caller nothing.</li>
 *   <li><strong>Realm-scoped, header-bound.</strong> Unlike the refresh grant (which resolves a
 *       token's authoritative realm server-side so a replay is caught under any header), revocation
 *       acts <em>only</em> within the caller's own realm. A token belonging to another tenant is
 *       invisible under this realm's RLS and is therefore a silent no-op — never a cross-tenant leak
 *       or a cross-tenant revoke.</li>
 *   <li><strong>Ownership-checked.</strong> A refresh family is revoked only when it belongs to the
 *       authenticating client (RFC 7009 §2.1), so one client cannot revoke another's family even
 *       within a shared tenant. A mismatch is a no-op, not an error.</li>
 *   <li><strong>Idempotent.</strong> {@link RefreshTokenStorePort#revokeFamily} is monotonic, so
 *       revoking an already-revoked (or non-existent) token is harmless and still succeeds.</li>
 * </ul>
 * A non-refresh token (a self-contained JWT access token), a malformed token, or a blank token is
 * accepted and does nothing — a bearer access token is bounded by its short TTL rather than a
 * server-side revocation list.
 */
public final class RevokeService implements RevokeUseCase {

    private final ClientRepositoryPort clients;
    private final ClientSecretVerifierPort secretVerifier;
    private final RefreshTokenStorePort refreshStore;

    public RevokeService(
            ClientRepositoryPort clients,
            ClientSecretVerifierPort secretVerifier,
            RefreshTokenStorePort refreshStore) {
        this.clients = requireNonNull(clients, "clients");
        this.secretVerifier = requireNonNull(secretVerifier, "secretVerifier");
        this.refreshStore = requireNonNull(refreshStore, "refreshStore");
    }

    @Override
    public Uni<RevokeResult> revoke(RevokeCommand command) {
        if (command == null) {
            throw new IllegalArgumentException("command must not be null");
        }
        // Authenticate the client within the caller's own realm. Unknown client or failed secret
        // both collapse to invalid_client — the endpoint's only surfaced failure.
        return clients.findByClientId(command.realm(), command.clientId()).flatMap(client -> {
            if (client == null) {
                return authFailed();
            }
            return authenticate(command.realm(), client, command.clientSecret()).flatMap(ok -> {
                if (!ok) {
                    return authFailed();
                }
                return revokeIfOwnedRefreshToken(command.realm(), client, command.token())
                        .replaceWith(done());
            });
        });
    }

    /**
     * Revokes the token's family iff the token parses as a refresh token whose family is visible in
     * the caller's realm and owned by the authenticated client. Every other case (blank, malformed,
     * non-refresh, foreign-tenant, other client) is a silent no-op — the non-oracle guarantee.
     */
    private Uni<Void> revokeIfOwnedRefreshToken(RealmKey realm, Client client, String token) {
        Optional<RefreshTokenCodec.Parsed> parsed = RefreshTokenCodec.parse(token);
        if (parsed.isEmpty()) {
            return Uni.createFrom().voidItem();
        }
        FamilyId fid = parsed.get().id();
        // RLS-scoped read: a family outside this realm is invisible (null) — no cross-tenant action.
        return refreshStore.find(fid, realm).flatMap(family -> {
            // Realm-equality is belt-and-braces: RLS scopes the read to the tenant, but the isolation
            // unit is (tenant, baseline). Requiring the snapshot's own realm to equal the caller's makes
            // baseline isolation explicit here rather than resting on a store adapter's scoping, so a
            // same-tenant / other-baseline family is never revoked even if an adapter under-scopes.
            if (family == null || !family.realm().equals(realm) || !ownedBy(family, client)) {
                return Uni.createFrom().voidItem();
            }
            return refreshStore.revokeFamily(fid, realm);
        });
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

    private static boolean ownedBy(RefreshTokenFamily family, Client client) {
        return family.clientId().equals(client.id());
    }

    private static Uni<RevokeResult> done() {
        return Uni.createFrom().item(new RevokeResult.Done());
    }

    private static Uni<RevokeResult> authFailed() {
        return Uni.createFrom().item(new RevokeResult.ClientAuthenticationFailed());
    }

    private static <T> T requireNonNull(T value, String name) {
        if (value == null) {
            throw new IllegalArgumentException(name + " must not be null");
        }
        return value;
    }
}
