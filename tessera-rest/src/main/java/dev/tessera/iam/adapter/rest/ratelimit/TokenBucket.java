package dev.tessera.iam.adapter.rest.ratelimit;

import java.util.function.LongSupplier;

/**
 * A single-key token bucket with lazy, monotonic refill. Framework-free so it can be unit-tested
 * with a deterministic clock (the nano-time source is injected). Thread-safe via coarse
 * synchronization on the instance; each rate-limit key owns its own bucket, so contention stays
 * per-key.
 */
final class TokenBucket {

    private final double capacity;
    private final double refillPerSecond;
    private final LongSupplier nanoTime;
    private double tokens;
    private long lastRefillNanos;

    TokenBucket(int capacity, double refillPerSecond, LongSupplier nanoTime) {
        if (capacity <= 0) {
            throw new IllegalArgumentException("capacity must be positive");
        }
        if (refillPerSecond <= 0) {
            throw new IllegalArgumentException("refillPerSecond must be positive");
        }
        this.capacity = capacity;
        this.refillPerSecond = refillPerSecond;
        this.nanoTime = nanoTime;
        this.tokens = capacity;
        this.lastRefillNanos = nanoTime.getAsLong();
    }

    /** Consumes one token if available. */
    synchronized boolean tryAcquire() {
        refill();
        if (tokens >= 1.0) {
            tokens -= 1.0;
            return true;
        }
        return false;
    }

    /** Whole seconds until at least one token is available (0 if one is available now). */
    synchronized long retryAfterSeconds() {
        refill();
        if (tokens >= 1.0) {
            return 0L;
        }
        return (long) Math.ceil((1.0 - tokens) / refillPerSecond);
    }

    /** True when the bucket is full — it holds no useful state and is a safe eviction candidate. */
    synchronized boolean isFull() {
        refill();
        return tokens >= capacity;
    }

    private void refill() {
        long now = nanoTime.getAsLong();
        long elapsedNanos = now - lastRefillNanos;
        if (elapsedNanos > 0L) {
            tokens = Math.min(capacity, tokens + (elapsedNanos / 1_000_000_000.0) * refillPerSecond);
            lastRefillNanos = now;
        }
    }
}
