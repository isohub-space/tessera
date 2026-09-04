package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.SessionUseCase;
import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.Optional;

/**
 * Application service that resolves a session to its authenticated subject, and ends
 * sessions. Framework-free, mirroring {@link AuthorizationService}'s shape.
 */
public final class SessionService implements SessionUseCase {

    private final SessionStorePort sessions;

    public SessionService(SessionStorePort sessions) {
        if (sessions == null) {
            throw new IllegalArgumentException("sessions must not be null");
        }
        this.sessions = sessions;
    }

    @Override
    public Uni<Optional<String>> resolveSubject(RealmKey realm, SessionId id) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        if (id == null) {
            throw new IllegalArgumentException("id must not be null");
        }
        return sessions.find(realm, id).map(found -> found.map(dev.tessera.iam.domain.session.Session::subjectId));
    }

    @Override
    public Uni<Void> logout(RealmKey realm, SessionId id) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        if (id == null) {
            throw new IllegalArgumentException("id must not be null");
        }
        return sessions.invalidate(realm, id);
    }
}
