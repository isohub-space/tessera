// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.authcode.PendingAuthorization;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Outbound port for the short-lived store of authorization requests waiting for the end user
 * to sign in.
 *
 * <p>The same contract as {@link AuthorizationCodeStorePort}, and the same two adapters (a
 * shared cache for several nodes, a process-local map otherwise):
 *
 * <ul>
 *   <li><strong>Tenant-scoped, fail-closed.</strong> An entry is keyed by its realm as well as
 *       its transaction id, and a lookup from another realm misses.</li>
 *   <li><strong>Expiry on read.</strong> An entry past its {@code expiresAt} is a miss whether
 *       or not the store has evicted it yet.</li>
 *   <li><strong>Consume-exactly-once.</strong> {@link #consume} removes and returns atomically,
 *       so one sign-in yields at most one authorization code however often the form is
 *       posted.</li>
 * </ul>
 */
public interface PendingAuthorizationStorePort {

    /**
     * Stores a pending request under its transaction id until its {@code expiresAt}.
     *
     * @param pending the pending request (never {@code null}; not yet expired)
     * @return a {@link Uni} that completes once the entry is stored
     */
    Uni<Void> store(PendingAuthorization pending);

    /**
     * Reads a pending request without removing it.
     *
     * @param realm         the realm of the lookup
     * @param transactionId the transaction id from the sign-in URL
     * @return a {@link Uni} emitting the entry, or {@code null} if it is unknown, expired or
     *         belongs to another realm
     */
    Uni<PendingAuthorization> find(RealmKey realm, String transactionId);

    /**
     * Atomically removes and returns a pending request. Of any number of concurrent calls for
     * one transaction id, at most one receives the entry.
     *
     * @param realm         the realm of the lookup
     * @param transactionId the transaction id from the sign-in URL
     * @return a {@link Uni} emitting the entry, or {@code null} if it is unknown, already
     *         consumed, expired or belongs to another realm
     */
    Uni<PendingAuthorization> consume(RealmKey realm, String transactionId);
}
