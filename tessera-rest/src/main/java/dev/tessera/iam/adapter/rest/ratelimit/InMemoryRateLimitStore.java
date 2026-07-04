package dev.tessera.iam.adapter.rest.ratelimit;

import io.quarkus.arc.DefaultBean;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * In-memory, single-node {@link RateLimitStore}: a {@link ConcurrentHashMap} of one
 * {@link TokenBucket} per {@link RateLimitKey}, refilled from a monotonic {@code nanoTime}
 * source.
 *
 * <p>This is the development / single-node implementation, mirroring
 * {@code InMemoryAuthorizationCodeStore}: buckets are per-process, so a limit is enforced
 * per node. A clustered deployment backs the port with a shared-cache backend (e.g. Infinispan)
 * so a bucket is enforced fleet-wide; swapping the backing store is a CDI-bean change with no
 * caller impact. Registered {@link DefaultBean} so that a future distributed adapter (a plain
 * {@code @ApplicationScoped} bean) supersedes it automatically.
 *
 * <p><strong>Bounded memory.</strong> An attacker rotating {@code client_id}/IP would otherwise
 * grow the map without limit. Two guards bound it: a hard {@code maxTrackedKeys} cap — once
 * reached, a request for an untracked key is refused (fail-closed) rather than allocating — and
 * a lazy sweep that drops full-and-idle buckets (a full bucket holds no useful state; it is
 * recreated full on next use). The sweep runs opportunistically every {@value #SWEEP_INTERVAL}
 * calls, so no scheduler dependency is needed.
 *
 * <p><strong>Event-loop safe.</strong> Every operation is a {@code ConcurrentHashMap} access
 * plus a {@code synchronized} bucket update with no I/O, so it is safe to call directly from the
 * reactive request filter.
 */
@ApplicationScoped
@DefaultBean
class InMemoryRateLimitStore implements RateLimitStore {

    /** Run the full-and-idle sweep once per this many acquire calls. */
    private static final int SWEEP_INTERVAL = 1024;

    private final ConcurrentMap<RateLimitKey, TokenBucket> buckets = new ConcurrentHashMap<>();
    private final AtomicLong callsSinceSweep = new AtomicLong();
    private final int maxTrackedKeys;
    private final LongSupplier nanoTime;

    @Inject
    InMemoryRateLimitStore(RateLimitConfig config) {
        this(config.maxTrackedKeys(), System::nanoTime);
    }

    /** Visible for testing: inject a deterministic clock and a small key bound. */
    InMemoryRateLimitStore(int maxTrackedKeys, LongSupplier nanoTime) {
        if (maxTrackedKeys <= 0) {
            throw new IllegalArgumentException("maxTrackedKeys must be positive");
        }
        this.maxTrackedKeys = maxTrackedKeys;
        this.nanoTime = nanoTime;
    }

    @Override
    public RateLimitDecision tryAcquire(RateLimitKey key, RateLimitPolicy policy) {
        TokenBucket bucket = buckets.get(key);
        if (bucket == null) {
            if (buckets.size() >= maxTrackedKeys) {
                sweep();
                if (buckets.size() >= maxTrackedKeys) {
                    // Fail closed: the tracking table is full, so treat an untracked key as
                    // throttled rather than growing memory without bound under a key-rotation flood.
                    return RateLimitDecision.deny((long) Math.ceil(1.0 / policy.refillPerSecond()));
                }
            }
            bucket = buckets.computeIfAbsent(key,
                    k -> new TokenBucket(policy.capacity(), policy.refillPerSecond(), nanoTime));
        }
        maybeSweep();
        return bucket.tryAcquire()
                ? RateLimitDecision.allow()
                : RateLimitDecision.deny(bucket.retryAfterSeconds());
    }

    private void maybeSweep() {
        if (callsSinceSweep.incrementAndGet() >= SWEEP_INTERVAL) {
            callsSinceSweep.set(0L);
            sweep();
        }
    }

    /**
     * Drops every full bucket. A full bucket has all its tokens and thus no state worth keeping;
     * if the key is seen again a fresh full bucket is created, which grants exactly the same
     * allowance. Weakly consistent over the concurrent map — a bucket used concurrently with the
     * sweep may be dropped and reset to full, at most re-granting its capacity, which is
     * acceptable for abuse mitigation.
     */
    private void sweep() {
        buckets.values().removeIf(TokenBucket::isFull);
    }
}
