package dev.tessera.iam.adapter.rest.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The fail-closed {@code max-tracked-keys} path reports a {@code trackingTableFull} event to the
 * metrics sink, so operators can see the limiter shed load under a key-rotation flood. Deterministic
 * unit test over the in-memory store with a counting {@link RateLimitMetrics} and a frozen clock.
 */
@DisplayName("InMemoryRateLimitStore — fail-closed table-full records a metric")
class InMemoryRateLimitStoreMetricsTest {

    @Test
    @DisplayName("overflowing the tracking table denies the request and records trackingTableFull")
    void tableFullRecordsMetric() {
        CountingMetrics metrics = new CountingMetrics();
        // A one-key table with a frozen clock (no refill), so a full bucket never sweeps away.
        InMemoryRateLimitStore store = new InMemoryRateLimitStore(1, () -> 0L, metrics);
        RateLimitPolicy policy = new RateLimitPolicy(1, 0.001);

        RateLimitKey first = new RateLimitKey(RateLimitKey.Surface.TOKEN, UUID.randomUUID(), "ip:a");
        RateLimitKey second = new RateLimitKey(RateLimitKey.Surface.TOKEN, UUID.randomUUID(), "ip:b");

        // The first key is tracked and consumes its only token — the table now holds one key.
        assertThat(store.tryAcquire(first, policy).allowed()).isTrue();
        assertThat(metrics.tableFull.get()).isZero();

        // A second, distinct key cannot be tracked (cap reached, nothing sweepable) → fail-closed
        // deny plus exactly one table-full event.
        var decision = store.tryAcquire(second, policy);
        assertThat(decision.allowed()).isFalse();
        assertThat(metrics.tableFull.get()).isEqualTo(1);
    }

    /** Counts each event so the test can assert the store reported the table-full exactly once. */
    private static final class CountingMetrics implements RateLimitMetrics {
        final AtomicInteger ingress = new AtomicInteger();
        final AtomicInteger tableFull = new AtomicInteger();
        final AtomicInteger credential = new AtomicInteger();

        @Override
        public void ingressThrottled(String surface, UUID tenant) {
            ingress.incrementAndGet();
        }

        @Override
        public void trackingTableFull() {
            tableFull.incrementAndGet();
        }

        @Override
        public void credentialThrottled(UUID tenant) {
            credential.incrementAndGet();
        }
    }
}
