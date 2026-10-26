// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import dev.tessera.iam.application.port.out.PendingAuthorizationStorePort;
import dev.tessera.iam.domain.authcode.PendingAuthorization;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.arc.DefaultBean;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Process-local store of requests waiting for sign-in: the {@link DefaultBean} fallback, used
 * under the {@code test} and {@code singlenode} profiles. Everywhere else
 * {@link InfinispanPendingAuthorizationStore} replaces it, so a sign-in started on one node can
 * finish on another.
 */
@ApplicationScoped
@DefaultBean
public class InMemoryPendingAuthorizationStore implements PendingAuthorizationStorePort {

    private final ConcurrentMap<Key, PendingAuthorization> entries = new ConcurrentHashMap<>();
    private final Clock clock;

    public InMemoryPendingAuthorizationStore() {
        this(Clock.systemUTC());
    }

    /** Visible for testing: a fixed clock exercises expiry deterministically. */
    public InMemoryPendingAuthorizationStore(Clock clock) {
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Uni<Void> store(PendingAuthorization pending) {
        if (pending == null) {
            throw new IllegalArgumentException("pending must not be null");
        }
        Instant now = clock.instant();
        // Each new sign-in is the moment to drop abandoned ones; nothing else would.
        entries.values().removeIf(entry -> entry.isExpired(now));
        entries.put(new Key(pending.realm(), pending.transactionId()), pending);
        return Uni.createFrom().voidItem();
    }

    @Override
    public Uni<PendingAuthorization> find(RealmKey realm, String transactionId) {
        if (realm == null || transactionId == null || transactionId.isBlank()) {
            return Uni.createFrom().nullItem();
        }
        return Uni.createFrom().item(live(entries.get(new Key(realm, transactionId))));
    }

    @Override
    public Uni<PendingAuthorization> consume(RealmKey realm, String transactionId) {
        if (realm == null || transactionId == null || transactionId.isBlank()) {
            return Uni.createFrom().nullItem();
        }
        return Uni.createFrom().item(live(entries.remove(new Key(realm, transactionId))));
    }

    private PendingAuthorization live(PendingAuthorization entry) {
        return entry == null || entry.isExpired(clock.instant()) ? null : entry;
    }

    private record Key(RealmKey realm, String transactionId) {
    }
}
