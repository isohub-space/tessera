package dev.tessera.iam.adapter.rest.authcode;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.out.AuthorizationCodeStorePort;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.ApplicationScoped;
import java.time.Clock;
import java.time.Instant;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory, single-use authorization-code store.
 *
 * <p>This is the development / single-node implementation of
 * {@link AuthorizationCodeStorePort}. A clustered deployment would back this port with a
 * distributed cache (e.g. Infinispan) so a code minted on one node can be redeemed on
 * another; the contract — tenant-scoped, fail-closed, consume-exactly-once, TTL — is the
 * same, so swapping the backing store is a CDI-bean change with no caller impact.
 *
 * <p>The two security properties the port mandates are both enforced here:
 * <ul>
 *   <li><strong>Consume-exactly-once.</strong> {@link #consume} uses
 *       {@link ConcurrentMap#remove(Object)}, which atomically removes-and-returns: of any
 *       number of concurrent redemptions of the same code, exactly one sees the grant and
 *       the rest see {@code null}. This is the sole replay defence (RFC 6749 §10.5).</li>
 *   <li><strong>Tenant scoping, fail-closed.</strong> The map key carries the
 *       {@link RealmKey}, so a code stored for one realm is invisible to a lookup from
 *       another — a cross-tenant redemption misses rather than leaking.</li>
 * </ul>
 *
 * <p>Expiry is enforced on read (a removed-but-expired grant is treated as a miss) so a
 * code can never be redeemed past its TTL even if a sweep has not yet run; the expiry
 * instant lives on the {@link AuthorizationGrant} itself, set by the issuing service.
 */
@ApplicationScoped
public class InMemoryAuthorizationCodeStore implements AuthorizationCodeStorePort {

    private final ConcurrentMap<CodeKey, AuthorizationGrant> entries = new ConcurrentHashMap<>();
    private final Clock clock;

    /** CDI requires a no-arg constructor; uses the system UTC clock. */
    public InMemoryAuthorizationCodeStore() {
        this(Clock.systemUTC());
    }

    /** Visible for testing: inject a fixed clock to exercise expiry deterministically. */
    public InMemoryAuthorizationCodeStore(Clock clock) {
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
        entries.put(new CodeKey(grant.realm(), code), grant);
        return Uni.createFrom().voidItem();
    }

    @Override
    public Uni<AuthorizationGrant> consume(RealmKey realm, String code) {
        if (realm == null || code == null || code.isBlank()) {
            // Fail closed: a malformed lookup never matches.
            return Uni.createFrom().nullItem();
        }
        // Atomic remove-and-return: the single replay defence.
        AuthorizationGrant grant = entries.remove(new CodeKey(realm, code));
        if (grant == null || grant.isExpired(clock.instant())) {
            // Unknown, already consumed, from another realm, or expired — all a miss.
            return Uni.createFrom().nullItem();
        }
        return Uni.createFrom().item(grant);
    }

    /**
     * Removes every entry whose grant has expired at {@code now}. Optional housekeeping —
     * correctness does not depend on it ({@link #consume} re-checks expiry), it only
     * bounds memory.
     *
     * @param now the current instant
     */
    public void evictExpired(Instant now) {
        entries.values().removeIf(grant -> grant.isExpired(now));
    }

    /** Composite key: a code is only ever visible within the realm that stored it. */
    private record CodeKey(RealmKey realm, String code) {
    }
}
