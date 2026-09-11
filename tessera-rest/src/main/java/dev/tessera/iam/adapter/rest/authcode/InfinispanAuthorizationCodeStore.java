package dev.tessera.iam.adapter.rest.authcode;

import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.arc.profile.UnlessBuildProfile;
import io.quarkus.infinispan.client.Remote;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import org.infinispan.client.hotrod.Flag;
import org.infinispan.client.hotrod.RemoteCache;

/**
 * Shared-cache (Infinispan / JDG) single-use authorization-code store — the multi-node
 * implementation of {@link AuthorizationCodeStorePort}.
 *
 * <p>The in-memory sibling is process-local, so a code minted at {@code /authorize} on one
 * node cannot be redeemed at {@code /token} on another and the flow only works behind sticky
 * sessions. Entries here live in a cache every node shares, so any node can redeem.
 *
 * <h2>Consume-exactly-once is the cache's job, not the caller's</h2>
 *
 * <p>{@link #consume} is a single {@link RemoteCache#removeAsync(Object)} — one atomic
 * remove-and-return against the key's owner. Of any number of concurrent redemptions of one
 * code, exactly one gets the grant back and the rest get {@code null}. A read-then-remove
 * would reintroduce the lost-update race that is the sole replay defence for authorization
 * codes (RFC 6749 §4.1.2 / §10.5).
 *
 * <p><strong>{@link Flag#FORCE_RETURN_VALUE} is load-bearing, not an optimisation knob.</strong>
 * Hot Rod does not ship the previous value back by default: without this flag
 * {@code removeAsync} completes with {@code null} whether or not the code existed, so every
 * redemption would miss and the authorization-code grant would be dead (fail-closed, but
 * dead). With it, the returned value <em>is</em> the proof that this caller — and only this
 * caller — won the removal.
 *
 * <h2>Tenant scoping, fail-closed</h2>
 *
 * <p>The cache key is {@code <tenant-uuid>:<baseline-uuid>:<code>}. Both UUIDs render at a
 * fixed 36 characters, so the first 73 characters of a key are determined entirely by the
 * realm doing the lookup and no code value can shift that boundary: a code stored for realm A
 * cannot be addressed from realm B. {@link #consume} additionally re-checks the realm carried
 * inside the decoded value, so a cache that returned a foreign entry anyway is still a miss.
 *
 * <h2>Expiry</h2>
 *
 * <p>Each entry carries a per-entry TTL equal to the remaining code lifetime, so the server
 * expires it without a sweep. Expiry is re-checked on read as well: a still-visible entry past
 * its {@code expiresAt} is a miss, so correctness never depends on the server's expiration
 * timing.
 *
 * <p>All cache calls are the reactive Hot Rod variants and are adapted to {@link Uni} without
 * blocking, so nothing here parks an event-loop thread.
 */
@ApplicationScoped
@UnlessBuildProfile("test")
public class InfinispanAuthorizationCodeStore implements AuthorizationCodeStorePort {

    /** Cache name; must match the cache configured on the server / in application.properties. */
    public static final String CACHE_NAME = "tessera-authorization-codes";

    private final RemoteCache<String, String> cache;
    private final Clock clock;

    @Inject
    public InfinispanAuthorizationCodeStore(@Remote(CACHE_NAME) RemoteCache<String, String> cache) {
        this(cache, Clock.systemUTC());
    }

    /** Visible for testing: a fixed clock makes TTL and expiry assertions deterministic. */
    public InfinispanAuthorizationCodeStore(RemoteCache<String, String> cache, Clock clock) {
        // FORCE_RETURN_VALUE is applied once, here, so no call site can forget it.
        this.cache = Objects.requireNonNull(cache, "cache").withFlags(Flag.FORCE_RETURN_VALUE);
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public Uni<Void> store(String code, AuthorizationGrant grant) {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("code must not be null or blank");
        }
        if (grant == null) {
            throw new IllegalArgumentException("grant must not be null");
        }
        long ttlMillis = Instant.now(clock).until(grant.expiresAt(), java.time.temporal.ChronoUnit.MILLIS);
        if (ttlMillis <= 0) {
            // A non-positive lifespan is not "already expired" to Infinispan — it means
            // "use the configured default", and -1 means immortal. Storing an expired grant
            // would therefore leak an entry that outlives the code it stands for. The issuing
            // service always mints a future expiry, so this is a bug signal, not a flow.
            throw new IllegalArgumentException("grant is already expired; refusing to store");
        }
        String key = key(grant.realm(), code);
        return Uni.createFrom()
                .completionStage(() ->
                        cache.putAsync(key, StoredGrant.encode(grant), ttlMillis, TimeUnit.MILLISECONDS))
                .replaceWithVoid();
    }

    @Override
    public Uni<AuthorizationGrant> consume(RealmKey realm, String code) {
        if (realm == null || code == null || code.isBlank()) {
            // Fail closed: a malformed lookup never matches.
            return Uni.createFrom().nullItem();
        }
        String key = key(realm, code);
        return Uni.createFrom()
                .completionStage(() -> cache.removeAsync(key))
                .map(stored -> {
                    if (stored == null) {
                        // Unknown, already consumed, from another realm, or server-expired.
                        return null;
                    }
                    AuthorizationGrant grant = StoredGrant.decode(stored);
                    if (grant == null
                            || !realm.equals(grant.realm())
                            || grant.isExpired(Instant.now(clock))) {
                        return null;
                    }
                    return grant;
                });
    }

    /**
     * Realm-scoped cache key. The two UUIDs are fixed-width, so the realm prefix cannot be
     * spoofed by any value of {@code code}.
     */
    private static String key(RealmKey realm, String code) {
        return realm.tenant().value() + ":" + realm.baseline().value() + ":" + code;
    }
}
