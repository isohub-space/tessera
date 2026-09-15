package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.domain.session.Session;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Test double for {@link SessionStorePort} (the persistence-backed store is owned by
 * {@code tessera-persistence}, which is not on this module's test classpath). An in-memory
 * map keyed by {@code (realm, id)}, mirroring the tenant-scoping the real store enforces via
 * row-level security plus its own baseline check.
 */
@Mock
@ApplicationScoped
public class FakeSessionStore implements SessionStorePort {

    private final ConcurrentMap<Key, Session> sessions = new ConcurrentHashMap<>();

    @Override
    public Uni<Session> create(RealmKey realm, String subjectId, Duration ttl) {
        Instant now = Instant.now();
        Session session = new Session(realm, SessionId.generate(), subjectId, now, now.plus(ttl));
        sessions.put(new Key(realm, session.id()), session);
        return Uni.createFrom().item(session);
    }

    @Override
    public Uni<Optional<Session>> find(RealmKey realm, SessionId id) {
        Session session = sessions.get(new Key(realm, id));
        boolean valid = session != null && !session.isExpired(Instant.now());
        return Uni.createFrom().item(valid ? Optional.of(session) : Optional.empty());
    }

    @Override
    public Uni<Void> invalidate(RealmKey realm, SessionId id) {
        sessions.remove(new Key(realm, id));
        return Uni.createFrom().voidItem();
    }

    private record Key(RealmKey realm, SessionId id) {
    }
}
