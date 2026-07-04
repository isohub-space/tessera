package dev.tessera.iam.adapter.rest.ratelimit;

import java.util.function.LongSupplier;

/**
 * Per-key brute-force failure lockout. After {@code maxFailures} consecutive failures the key is
 * locked out for {@code lockoutSeconds}; a success ({@link #reset()}) or the window expiring clears
 * it. Framework-free with an injected nano-time source for deterministic tests. Thread-safe via
 * instance synchronization (per key).
 */
final class BruteForceLockout {

    private final int maxFailures;
    private final long lockoutNanos;
    private final LongSupplier nanoTime;
    private int failures;
    private long lockedUntilNanos;   // 0 = not locked

    BruteForceLockout(int maxFailures, long lockoutSeconds, LongSupplier nanoTime) {
        if (maxFailures <= 0) {
            throw new IllegalArgumentException("maxFailures must be positive");
        }
        if (lockoutSeconds <= 0) {
            throw new IllegalArgumentException("lockoutSeconds must be positive");
        }
        this.maxFailures = maxFailures;
        this.lockoutNanos = lockoutSeconds * 1_000_000_000L;
        this.nanoTime = nanoTime;
    }

    synchronized boolean isLockedOut() {
        return remainingLockoutNanos() > 0L;
    }

    synchronized void recordFailure() {
        if (remainingLockoutNanos() > 0L) {
            return;   // already locked; keep the existing window
        }
        failures++;
        if (failures >= maxFailures) {
            lockedUntilNanos = nanoTime.getAsLong() + lockoutNanos;
        }
    }

    synchronized void reset() {
        failures = 0;
        lockedUntilNanos = 0L;
    }

    synchronized long retryAfterSeconds() {
        long remaining = remainingLockoutNanos();
        return remaining <= 0L ? 0L : (long) Math.ceil(remaining / 1_000_000_000.0);
    }

    /** True when no failures are counted and no lockout is active — a safe eviction candidate. */
    synchronized boolean isIdle() {
        return failures == 0 && remainingLockoutNanos() <= 0L;
    }

    private long remainingLockoutNanos() {
        if (lockedUntilNanos == 0L) {
            return 0L;
        }
        long remaining = lockedUntilNanos - nanoTime.getAsLong();
        if (remaining <= 0L) {
            // Window elapsed — clear so counting restarts fresh on the next failure.
            lockedUntilNanos = 0L;
            failures = 0;
            return 0L;
        }
        return remaining;
    }
}
