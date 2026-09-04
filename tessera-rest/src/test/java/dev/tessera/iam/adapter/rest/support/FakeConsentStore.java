package dev.tessera.iam.adapter.rest.support;

import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Test double for {@link ConsentStorePort} (the persistence-backed store is owned by
 * {@code tessera-persistence}). An in-memory map keyed by {@code (realm, subject, client)}.
 */
@Mock
@ApplicationScoped
public class FakeConsentStore implements ConsentStorePort {

    private final ConcurrentMap<Key, Set<String>> granted = new ConcurrentHashMap<>();

    @Override
    public Uni<Boolean> hasConsent(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        Set<String> existing = granted.get(new Key(realm, subjectId, clientId));
        return Uni.createFrom().item(existing != null && existing.containsAll(scopes));
    }

    @Override
    public Uni<Void> grant(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        granted.put(new Key(realm, subjectId, clientId), Set.copyOf(scopes));
        return Uni.createFrom().voidItem();
    }

    private record Key(RealmKey realm, String subjectId, ClientId clientId) {
    }
}
