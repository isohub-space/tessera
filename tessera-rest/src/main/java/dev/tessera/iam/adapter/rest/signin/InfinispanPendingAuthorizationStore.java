// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import dev.tessera.iam.application.port.out.PendingAuthorizationStorePort;
import dev.tessera.iam.domain.authcode.PendingAuthorization;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.arc.profile.UnlessBuildProfile;
import io.quarkus.infinispan.client.Remote;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.infinispan.client.hotrod.Flag;
import org.infinispan.client.hotrod.RemoteCache;

/**
 * Shared-cache (Infinispan) store of requests waiting for sign-in, so the page served by one
 * node can be posted to another. It follows {@code InfinispanAuthorizationCodeStore} point for
 * point: a realm-prefixed key of fixed-width UUIDs, a per-entry lifespan equal to the remaining
 * lifetime, expiry and realm re-checked on read, and a consume that is one atomic
 * {@code removeAsync} with {@link Flag#FORCE_RETURN_VALUE}, without which every consume would
 * miss.
 */
@ApplicationScoped
@UnlessBuildProfile(anyOf = {"test", "singlenode"})
public class InfinispanPendingAuthorizationStore implements PendingAuthorizationStorePort {

    /** Cache name; must match the cache configured in application.properties. */
    public static final String CACHE_NAME = "tessera-pending-authorizations";

    private final RemoteCache<String, String> cache;
    private final Clock clock;

    @Inject
    public InfinispanPendingAuthorizationStore(@Remote(CACHE_NAME) RemoteCache<String, String> cache) {
        this(cache, Clock.systemUTC());
    }

    /** Visible for testing: a fixed clock makes lifespan and expiry assertions deterministic. */
    public InfinispanPendingAuthorizationStore(RemoteCache<String, String> cache, Clock clock) {
        this.cache = Objects.requireNonNull(cache, "cache").withFlags(Flag.FORCE_RETURN_VALUE);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Uni<Void> store(PendingAuthorization pending) {
        if (pending == null) {
            throw new IllegalArgumentException("pending must not be null");
        }
        long ttlMillis = Instant.now(clock).until(pending.expiresAt(), ChronoUnit.MILLIS);
        if (ttlMillis <= 0) {
            // To Infinispan a non-positive lifespan means the default or immortal, not expired.
            throw new IllegalArgumentException("pending authorization is already expired; refusing to store");
        }
        String key = key(pending.realm(), pending.transactionId());
        return Uni.createFrom()
                .completionStage(() -> cache.putAsync(
                        key, StoredPendingAuthorization.encode(pending), ttlMillis, TimeUnit.MILLISECONDS))
                .replaceWithVoid();
    }

    @Override
    public Uni<PendingAuthorization> find(RealmKey realm, String transactionId) {
        if (realm == null || transactionId == null || transactionId.isBlank()) {
            return Uni.createFrom().nullItem();
        }
        return Uni.createFrom()
                .completionStage(() -> cache.getAsync(key(realm, transactionId)))
                .map(stored -> live(realm, stored));
    }

    @Override
    public Uni<PendingAuthorization> consume(RealmKey realm, String transactionId) {
        if (realm == null || transactionId == null || transactionId.isBlank()) {
            return Uni.createFrom().nullItem();
        }
        return Uni.createFrom()
                .completionStage(() -> cache.removeAsync(key(realm, transactionId)))
                .map(stored -> live(realm, stored));
    }

    private PendingAuthorization live(RealmKey realm, String stored) {
        if (stored == null) {
            return null;
        }
        PendingAuthorization pending = StoredPendingAuthorization.decode(stored);
        if (pending == null || !realm.equals(pending.realm()) || pending.isExpired(Instant.now(clock))) {
            return null;
        }
        return pending;
    }

    private static String key(RealmKey realm, String transactionId) {
        return realm.tenant().value() + ":" + realm.baseline().value() + ":" + transactionId;
    }
}
