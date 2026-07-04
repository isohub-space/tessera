package dev.tessera.iam.domain.refresh;

import java.time.Instant;

/**
 * The pure refresh-token reuse-detection rule — the security heart of rotating refresh tokens.
 *
 * <p>Given an immutable {@link RefreshTokenFamily} snapshot and the hash of a presented token, it
 * classifies the redemption into a {@link RefreshDecision} with no I/O, no clock read (the instant
 * is passed in), and no crypto (hashing is an adapter concern). The rule is deliberately framework-
 * free and exhaustively unit-tested; the persistence adapter enforces the same decision
 * <em>atomically</em> under concurrency, and a test asserts the two agree.
 *
 * <p>Order of checks matters and is fail-safe:
 * <ol>
 *   <li>an already-{@link RefreshTokenFamily#reused() reused} family → {@link RefreshDecision.Replay}
 *       (it is burned; every further presentation is a replay);</li>
 *   <li>an expired family → {@link RefreshDecision.Expired};</li>
 *   <li>the current-token hash → {@link RefreshDecision.Rotate};</li>
 *   <li>the previous-token hash → {@link RefreshDecision.Replay} (a superseded token was presented —
 *       the canonical stolen-token replay);</li>
 *   <li>anything else → {@link RefreshDecision.Unknown}.</li>
 * </ol>
 */
public final class RefreshReuseDetection {

    private RefreshReuseDetection() {
    }

    /**
     * Classifies a presented refresh token against its family.
     *
     * @param family        the family snapshot (never {@code null})
     * @param presentedHash the hash of the presented token (never {@code null} or blank)
     * @param now           the current instant (never {@code null})
     * @return the decision (never {@code null})
     */
    public static RefreshDecision classify(
            RefreshTokenFamily family, String presentedHash, Instant now) {
        if (family == null) {
            throw new IllegalArgumentException("family must not be null");
        }
        if (presentedHash == null || presentedHash.isBlank()) {
            throw new IllegalArgumentException("presentedHash must not be null or blank");
        }
        if (now == null) {
            throw new IllegalArgumentException("now must not be null");
        }
        if (family.reused()) {
            return new RefreshDecision.Replay(family.id());
        }
        if (family.isExpired(now)) {
            return new RefreshDecision.Expired();
        }
        if (presentedHash.equals(family.currentTokenHash())) {
            return new RefreshDecision.Rotate(family.id(), family.generation());
        }
        if (presentedHash.equals(family.previousTokenHash())) {
            return new RefreshDecision.Replay(family.id());
        }
        return new RefreshDecision.Unknown();
    }
}
