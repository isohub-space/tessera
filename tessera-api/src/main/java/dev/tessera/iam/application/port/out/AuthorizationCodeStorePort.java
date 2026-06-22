package dev.tessera.iam.application.port.out;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.tenancy.RealmKey;

/**
 * Outbound port for the short-lived, single-use authorization-code store.
 *
 * <p>An authorization code is an opaque handle issued at {@code /authorize} and redeemed
 * once at {@code /token}. This port abstracts the store (an Infinispan cache in the
 * shipped adapter, with a per-entry TTL); the application depends only on the contract:
 *
 * <ul>
 *   <li><strong>Tenant-scoped, fail-closed.</strong> Every entry is keyed by
 *       {@link RealmKey} as well as code, and a lookup outside the storing tenant must
 *       miss — a code stored for one realm can never be consumed from another.</li>
 *   <li><strong>Consume-exactly-once.</strong> {@link #consume(RealmKey, String)} must
 *       atomically remove-and-return: a second redemption of the same code (a replay, or
 *       two concurrent redemptions) returns empty for all but one caller. This is the
 *       sole replay defence for authorization codes (RFC 6749 §4.1.2 / §10.5).</li>
 * </ul>
 */
public interface AuthorizationCodeStorePort {

    /**
     * Stores a grant under a freshly minted, opaque authorization code, scoped to the
     * grant's realm, with the store's configured single-use TTL.
     *
     * @param code  the opaque authorization code (never {@code null} or blank)
     * @param grant the grant the code stands for (never {@code null})
     * @return a {@link Uni} that completes when the code is durably stored
     */
    Uni<Void> store(String code, AuthorizationGrant grant);

    /**
     * Atomically consumes (removes and returns) the grant for a code within a realm. A
     * code can be consumed at most once; a second call for the same code returns
     * {@code null}. A code stored for a different realm is not visible here (fail-closed).
     *
     * @param realm the realm redeeming the code (RLS/tenant-scoped)
     * @param code  the opaque authorization code presented at the token endpoint
     * @return a {@link Uni} emitting the consumed {@link AuthorizationGrant}, or
     *         {@code null} if the code is unknown, already consumed, or from another realm
     */
    Uni<AuthorizationGrant> consume(RealmKey realm, String code);
}
