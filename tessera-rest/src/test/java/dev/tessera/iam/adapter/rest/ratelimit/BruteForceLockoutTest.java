package dev.tessera.iam.adapter.rest.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("BruteForceLockout — failure counting, lockout window, reset")
class BruteForceLockoutTest {

    private final AtomicLong now = new AtomicLong(0);

    private BruteForceLockout lockout(int maxFailures, long lockoutSeconds) {
        return new BruteForceLockout(maxFailures, lockoutSeconds, now::get);
    }

    private void advanceSeconds(long seconds) {
        now.addAndGet(seconds * 1_000_000_000L);
    }

    @Test
    @DisplayName("locks out after max consecutive failures")
    void locksOut() {
        BruteForceLockout l = lockout(3, 300);
        l.recordFailure();
        l.recordFailure();
        assertThat(l.isLockedOut()).isFalse();
        l.recordFailure();
        assertThat(l.isLockedOut()).isTrue();
        assertThat(l.retryAfterSeconds()).isEqualTo(300L);
    }

    @Test
    @DisplayName("a reset (success) clears the counter before lockout")
    void resetClears() {
        BruteForceLockout l = lockout(3, 300);
        l.recordFailure();
        l.recordFailure();
        l.reset();
        l.recordFailure();
        l.recordFailure();
        assertThat(l.isLockedOut()).isFalse();   // only 2 failures since reset
    }

    @Test
    @DisplayName("lockout expires after the window and counting restarts")
    void windowExpires() {
        BruteForceLockout l = lockout(2, 60);
        l.recordFailure();
        l.recordFailure();
        assertThat(l.isLockedOut()).isTrue();
        advanceSeconds(61);
        assertThat(l.isLockedOut()).isFalse();
        assertThat(l.retryAfterSeconds()).isZero();
        assertThat(l.isIdle()).isTrue();
    }

    @Test
    @DisplayName("rejects non-positive parameters")
    void rejectsBadParams() {
        assertThatThrownBy(() -> lockout(0, 60)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> lockout(2, 0)).isInstanceOf(IllegalArgumentException.class);
    }
}
