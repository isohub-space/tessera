package dev.tessera.iam.adapter.rest.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("TokenBucket — capacity, refill, retry-after (deterministic clock)")
class TokenBucketTest {

    private final AtomicLong now = new AtomicLong(0);

    private TokenBucket bucket(int capacity, double refillPerSecond) {
        return new TokenBucket(capacity, refillPerSecond, now::get);
    }

    private void advanceSeconds(double seconds) {
        now.addAndGet((long) (seconds * 1_000_000_000.0));
    }

    @Test
    @DisplayName("drains after capacity acquisitions, then refuses")
    void drains() {
        TokenBucket b = bucket(3, 1.0);
        assertThat(b.tryAcquire()).isTrue();
        assertThat(b.tryAcquire()).isTrue();
        assertThat(b.tryAcquire()).isTrue();
        assertThat(b.tryAcquire()).isFalse();
    }

    @Test
    @DisplayName("refills over time, capped at capacity")
    void refills() {
        TokenBucket b = bucket(2, 1.0);   // 1 token / second
        assertThat(b.tryAcquire()).isTrue();
        assertThat(b.tryAcquire()).isTrue();
        assertThat(b.tryAcquire()).isFalse();
        advanceSeconds(1.0);              // +1 token
        assertThat(b.tryAcquire()).isTrue();
        assertThat(b.tryAcquire()).isFalse();
        advanceSeconds(100.0);            // caps at capacity=2, not 100
        assertThat(b.isFull()).isTrue();
        assertThat(b.tryAcquire()).isTrue();
        assertThat(b.tryAcquire()).isTrue();
        assertThat(b.tryAcquire()).isFalse();
    }

    @Test
    @DisplayName("retryAfterSeconds is 0 when a token is available, else the refill wait")
    void retryAfter() {
        TokenBucket b = bucket(1, 0.5);   // 1 token / 2 seconds
        assertThat(b.retryAfterSeconds()).isZero();
        assertThat(b.tryAcquire()).isTrue();
        assertThat(b.retryAfterSeconds()).isEqualTo(2L);
    }

    @Test
    @DisplayName("hasToken peeks availability without consuming")
    void hasTokenDoesNotConsume() {
        TokenBucket b = bucket(1, 0.5);   // 1 token / 2 seconds
        assertThat(b.hasToken()).isTrue();
        assertThat(b.hasToken()).isTrue();   // repeated peeks never drain
        assertThat(b.tryAcquire()).isTrue(); // the single token is still there to take
        assertThat(b.hasToken()).isFalse();  // now empty
        assertThat(b.tryAcquire()).isFalse();
    }

    @Test
    @DisplayName("rejects non-positive parameters")
    void rejectsBadParams() {
        assertThatThrownBy(() -> bucket(0, 1.0)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> bucket(1, 0.0)).isInstanceOf(IllegalArgumentException.class);
    }
}
