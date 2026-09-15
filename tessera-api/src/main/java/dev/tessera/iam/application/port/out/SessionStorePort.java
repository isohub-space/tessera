package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.session.Session;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.time.Duration;
import java.util.Optional;

/**
 * Outbound port for durable, tenant-scoped session storage.
 *
 * <p>Backs {@code auth_session} — a table already shaped for exactly this (append-heavy,
 * time-ordered PK, RLS by tenant) before this port existed to write to it. {@link #find}
 * fails closed: an id from another realm, an unknown id, or an expired session are all
 * indistinguishable misses to the caller, which is what makes tenant-scoped sessions provable
 * (a lookup can never accidentally cross a tenant boundary — it simply finds nothing).
 */
public interface SessionStorePort {

    /**
     * Creates and persists a new session.
     *
     * @param realm     the realm the session belongs to (never {@code null})
     * @param subjectId the authenticated end-user {@code sub} (never {@code null} or blank)
     * @param ttl       how long the session remains valid from now (never {@code null},
     *                  positive)
     * @return a {@link Uni} emitting the persisted {@link Session}
     */
    Uni<Session> create(RealmKey realm, String subjectId, Duration ttl);

    /**
     * Looks a session up by id, scoped to {@code realm}.
     *
     * @param realm the realm the caller claims to be in (never {@code null})
     * @param id    the session id (never {@code null})
     * @return a {@link Uni} emitting the session if it exists, belongs to {@code realm}, and
     *         has not expired; {@link Optional#empty()} otherwise
     */
    Uni<Optional<Session>> find(RealmKey realm, SessionId id);

    /**
     * Invalidates a session so it no longer resolves. Idempotent.
     *
     * @param realm the realm the session belongs to (never {@code null})
     * @param id    the session id to invalidate (never {@code null})
     * @return a {@link Uni} completing once the invalidation is durable
     */
    Uni<Void> invalidate(RealmKey realm, SessionId id);
}
