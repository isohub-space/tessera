package dev.tessera.iam.adapter.rest.ratelimit;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * The failure budgets of a credential throttle, one per key, in a table bounded by
 * {@link RateLimitConfig#maxTrackedKeys()}.
 *
 * <p>The keys are attacker-chosen ({@code client_id}s and usernames, existing or not), so the table
 * must not grow without limit. A full budget has spent nothing and is dropped by a periodic sweep.
 * When the table is still at its cap, a new key gets no budget: {@link #budgetFor} returns
 * {@code null} and the caller verifies the credential without one. That is the same for an
 * existing and a made-up key, so it tells them apart no more than the budget does, and it fails
 * open on the throttle, not on authentication: the cost of each verification stays bounded by the
 * Argon2 admission control, and the secrets being guessed are high-entropy. The cap is soft by at
 * most the number of callers racing to insert at the same moment.
 */
final class CredentialBudgets<K> {

    /** Run the idle-eviction sweep once per this many lookups. */
    private static final int SWEEP_INTERVAL = 1024;

    /** At the cap, sweep at most this often, so a flood of new keys cannot make every lookup O(n). */
    private static final long CAP_SWEEP_INTERVAL_NANOS = TimeUnit.SECONDS.toNanos(1);

    private final ConcurrentMap<K, TokenBucket> budgets = new ConcurrentHashMap<>();
    private final AtomicLong callsSinceSweep = new AtomicLong();
    private final AtomicLong lastCapSweep = new AtomicLong(System.nanoTime() - CAP_SWEEP_INTERVAL_NANOS);

    /**
     * @return the key's budget, or {@code null} when the key is new and the table is at its cap
     */
    TokenBucket budgetFor(K key, RateLimitConfig config) {
        maybeSweep();
        TokenBucket existing = budgets.get(key);
        if (existing != null) {
            return existing;
        }
        if (budgets.size() >= config.maxTrackedKeys() && !sweepAtCap(config)) {
            return null;
        }
        return budgets.computeIfAbsent(key, k -> new TokenBucket(
                config.credentialFailureBurst(),
                config.credentialRefillPerMinute() / 60.0,
                System::nanoTime));
    }

    /** Drops full budgets if not done in the last second; {@code true} when there is room after. */
    private boolean sweepAtCap(RateLimitConfig config) {
        long now = System.nanoTime();
        long last = lastCapSweep.get();
        if (now - last >= CAP_SWEEP_INTERVAL_NANOS && lastCapSweep.compareAndSet(last, now)) {
            budgets.values().removeIf(TokenBucket::isFull);
        }
        return budgets.size() < config.maxTrackedKeys();
    }

    private void maybeSweep() {
        if (callsSinceSweep.incrementAndGet() >= SWEEP_INTERVAL) {
            callsSinceSweep.set(0L);
            // Drop full budgets — a full bucket has spent nothing and is recreated full on next use.
            budgets.values().removeIf(TokenBucket::isFull);
        }
    }
}
