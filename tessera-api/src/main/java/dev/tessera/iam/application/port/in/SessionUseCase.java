package dev.tessera.iam.application.port.in;

import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.Optional;

/**
 * Inbound port for resolving and ending an established {@link dev.tessera.iam.domain.session.Session}.
 *
 * <p>{@link #resolveSubject} is what a cookie-to-header filter calls on every tenant-scoped
 * request to fill the {@code X-Subject-Id} seam from a session cookie: it looks the session
 * up within the caller's realm, rejects it fail-closed (unknown id, wrong realm, or expired
 * all resolve to {@link Optional#empty()} — never an exception a filter would have to
 * distinguish), and returns the subject only for a live session in the caller's own realm.
 * This is the enforcement point for tenant-scoped sessions: a session id from realm A
 * presented under realm B never resolves, because the lookup itself is realm-scoped.
 */
public interface SessionUseCase {

    /**
     * Resolves the authenticated subject for a session, if it is still valid within
     * {@code realm}.
     *
     * @param realm the realm the caller claims to be in (never {@code null})
     * @param id    the session id presented (e.g. via cookie) (never {@code null})
     * @return a {@link Uni} emitting the subject, or {@link Optional#empty()} if the session
     *         is unknown, belongs to another realm, or has expired
     */
    Uni<Optional<String>> resolveSubject(RealmKey realm, SessionId id);

    /**
     * Ends a session (logout). Idempotent: ending an already-ended or unknown session within
     * the realm is not an error.
     *
     * @param realm the realm the session belongs to (never {@code null})
     * @param id    the session id to end (never {@code null})
     * @return a {@link Uni} completing once the session is invalidated
     */
    Uni<Void> logout(RealmKey realm, SessionId id);
}
