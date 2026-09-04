package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.out.SessionStorePort;
import dev.tessera.iam.domain.session.Session;
import dev.tessera.iam.domain.session.SessionId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("SessionService — resolves a session's subject and ends sessions, fail-closed across realms")
class SessionServiceTest {

    private static final RealmKey REALM_A = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final RealmKey REALM_B = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** An in-memory store keyed by (realm, id) — a real store would apply RLS instead. */
    private static final class InMemorySessions implements SessionStorePort {
        private final ConcurrentMap<Object, Session> byKey = new ConcurrentHashMap<>();

        @Override
        public Uni<Session> create(RealmKey realm, String subjectId, Duration ttl) {
            Session session = new Session(realm, SessionId.generate(), subjectId, NOW, NOW.plus(ttl));
            byKey.put(key(realm, session.id()), session);
            return Uni.createFrom().item(session);
        }

        @Override
        public Uni<Optional<Session>> find(RealmKey realm, SessionId id) {
            Session found = byKey.get(key(realm, id));
            return Uni.createFrom().item(Optional.ofNullable(found));
        }

        @Override
        public Uni<Void> invalidate(RealmKey realm, SessionId id) {
            byKey.remove(key(realm, id));
            return Uni.createFrom().voidItem();
        }

        private static Object key(RealmKey realm, SessionId id) {
            return realm + "|" + id;
        }
    }

    @Test
    @DisplayName("a session created in realm A resolves its subject when looked up in realm A")
    void resolvesWithinOwningRealm() {
        InMemorySessions store = new InMemorySessions();
        SessionService service = new SessionService(store);
        Session created = store.create(REALM_A, "sub-1", Duration.ofMinutes(10)).await().indefinitely();

        Optional<String> resolved = service.resolveSubject(REALM_A, created.id()).await().indefinitely();

        assertThat(resolved).contains("sub-1");
    }

    @Test
    @DisplayName("the SAME session id presented under a different realm never resolves (tenant scoping)")
    void neverResolvesUnderAnotherRealm() {
        InMemorySessions store = new InMemorySessions();
        SessionService service = new SessionService(store);
        Session created = store.create(REALM_A, "sub-1", Duration.ofMinutes(10)).await().indefinitely();

        Optional<String> resolved = service.resolveSubject(REALM_B, created.id()).await().indefinitely();

        assertThat(resolved).isEmpty();
    }

    @Test
    @DisplayName("an unknown session id resolves to empty, not an error")
    void unknownSessionResolvesEmpty() {
        SessionService service = new SessionService(new InMemorySessions());

        Optional<String> resolved =
                service.resolveSubject(REALM_A, SessionId.generate()).await().indefinitely();

        assertThat(resolved).isEmpty();
    }

    @Test
    @DisplayName("logout invalidates the session so it no longer resolves")
    void logoutInvalidatesSession() {
        InMemorySessions store = new InMemorySessions();
        SessionService service = new SessionService(store);
        Session created = store.create(REALM_A, "sub-1", Duration.ofMinutes(10)).await().indefinitely();

        service.logout(REALM_A, created.id()).await().indefinitely();

        assertThat(service.resolveSubject(REALM_A, created.id()).await().indefinitely()).isEmpty();
    }
}
