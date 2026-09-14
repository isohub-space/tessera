package dev.tessera.iam.adapter.rest.authcode;

import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.quarkus.arc.profile.UnlessBuildProfile;
import io.quarkus.redis.datasource.ReactiveRedisDataSource;
import io.quarkus.redis.datasource.value.ReactiveValueCommands;
import io.quarkus.redis.datasource.value.SetArgs;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;

/**
 * Shared-store (Redis) single-use authorization-code store — the multi-node implementation of
 * {@link AuthorizationCodeStorePort}.
 *
 * <p>The in-memory sibling is process-local, so a code minted at {@code /authorize} on one node
 * cannot be redeemed at {@code /token} on another and the flow only works behind sticky sessions.
 * Entries here live in a store every node shares, so any node can redeem.
 *
 * <h2>Consume-exactly-once is the server's job, not the caller's</h2>
 *
 * <p>{@link #consume} is a single {@code GETDEL} (Redis 6.2+). Redis executes commands one at a
 * time against a single primary, so of any number of concurrent redemptions of one code exactly
 * one gets the value back and the rest get {@code null}. A {@code GET} followed by a {@code DEL}
 * would be a check-then-act race and would reintroduce the lost-update window that is the sole
 * replay defence for authorization codes (RFC 6749 §4.1.2 / §10.5).
 *
 * <p><strong>The bound of that guarantee, stated plainly.</strong> Exactly-once here is a property
 * of a single primary serialising its command stream. Redis replication is asynchronous, so a
 * failover to a replica that has not yet received the {@code GETDEL} (or the preceding
 * {@code SET}) can lose that fact. The residual risk is a redemption racing a primary failover in
 * a window bounded by the replication lag and by the code's own ~2-minute lifetime; it is not
 * removed by anything in this class, and no test in this repository demonstrates it either way.
 * Closing it fully needs a second, durable single-use check at the token endpoint — not a
 * different cache.
 *
 * <h2>Tenant scoping, fail-closed</h2>
 *
 * <p>The key is {@code tessera:authcode:<tenant-uuid>:<baseline-uuid>:<code>}. Both UUIDs render
 * at a fixed 36 characters, so everything up to the last separator is determined entirely by the
 * realm doing the lookup and no {@code code} value can shift that boundary: a code stored for
 * realm A cannot be addressed from realm B. {@link #consume} additionally re-checks the realm
 * carried inside the decoded value, so a store that returned a foreign entry anyway is still a
 * miss. The fixed prefix keeps these entries in their own slice of what is, unlike a dedicated
 * cache, a keyspace shared with whatever else the deployment puts on the same instance.
 *
 * <h2>Expiry</h2>
 *
 * <p>Each entry is written with {@code SET … PX}, a per-entry TTL equal to the remaining code
 * lifetime, so Redis expires it natively and no sweep job exists to forget to run. Expiry is
 * re-checked on read as well: a still-visible entry past its {@code expiresAt} is a miss, so
 * correctness never depends on the server's expiration timing or on the two clocks agreeing.
 * ({@code GETEX} is not used — redemption removes the entry outright, so there is no surviving
 * entry whose TTL would need extending or clearing.)
 *
 * <p>All calls are the reactive command variants and are returned as {@link Uni} without
 * blocking, so nothing here parks an event-loop thread.
 */
@ApplicationScoped
@UnlessBuildProfile("test")
public class RedisAuthorizationCodeStore implements AuthorizationCodeStorePort {

    /**
     * Fixed key prefix. Redis has one flat keyspace per database, so the adapter namespaces its
     * own entries rather than assuming it owns the instance.
     */
    static final String KEY_PREFIX = "tessera:authcode:";

    private final ReactiveValueCommands<String, String> values;
    private final Clock clock;

    @Inject
    public RedisAuthorizationCodeStore(ReactiveRedisDataSource redis) {
        // String keys and String values: the Quarkus marshaller special-cases String and writes
        // the raw UTF-8 bytes, so the stored value is exactly the JSON StoredGrant produces and
        // no codec or schema has to be registered anywhere.
        this(Objects.requireNonNull(redis, "redis").value(String.class), Clock.systemUTC());
    }

    /** Visible for testing: a fixed clock makes TTL and expiry assertions deterministic. */
    RedisAuthorizationCodeStore(ReactiveValueCommands<String, String> values, Clock clock) {
        this.values = Objects.requireNonNull(values, "values");
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
        long ttlMillis = Instant.now(clock).until(grant.expiresAt(), ChronoUnit.MILLIS);
        if (ttlMillis <= 0) {
            // Redis rejects a non-positive PX outright, but the useful thing to say is that the
            // caller minted a code that is already dead: the issuing service always sets a future
            // expiry, so this is a bug signal, not a flow. Refusing here also guarantees the
            // entry can never be written without a lifespan.
            throw new IllegalArgumentException("grant is already expired; refusing to store");
        }
        return values.set(key(grant.realm(), code), StoredGrant.encode(grant), new SetArgs().px(ttlMillis));
    }

    @Override
    public Uni<AuthorizationGrant> consume(RealmKey realm, String code) {
        if (realm == null || code == null || code.isBlank()) {
            // Fail closed: a malformed lookup never matches.
            return Uni.createFrom().nullItem();
        }
        // Atomic remove-and-return: the single replay defence.
        return values.getdel(key(realm, code)).map(stored -> {
            if (stored == null) {
                // Unknown, already consumed, from another realm, or expired by the server.
                return null;
            }
            AuthorizationGrant grant = StoredGrant.decode(stored);
            if (grant == null || !realm.equals(grant.realm()) || grant.isExpired(Instant.now(clock))) {
                // An undecodable, foreign or stale entry is a miss, never a 500 on /token. The
                // GETDEL has already taken it, so it cannot be retried either way.
                return null;
            }
            return grant;
        });
    }

    /**
     * Realm-scoped key. The two UUIDs are fixed-width, so the realm prefix cannot be spoofed by
     * any value of {@code code}.
     *
     * <p>Package-private rather than private so the integration test can plant an entry at a key
     * the adapter will actually look up, which is how the read-side expiry re-check is provable
     * independently of Redis's own TTL.
     */
    static String key(RealmKey realm, String code) {
        return KEY_PREFIX + realm.tenant().value() + ":" + realm.baseline().value() + ":" + code;
    }
}
