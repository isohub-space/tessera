package dev.tessera.iam.domain.refresh;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;

/**
 * The pure refresh-token reuse-detection rule — the security heart of rotating refresh tokens.
 *
 * <p>Given an immutable {@link RefreshTokenFamily} snapshot and the hash of a presented token, it
 * classifies the redemption into a {@link RefreshDecision} with no I/O, no clock read (the instant
 * is passed in), and no crypto (hashing is an adapter concern). The rule is deliberately framework-
 * free and exhaustively unit-tested; each store adapter enforces the same decision — the in-memory
 * one under a per-key atomic remap, the persistence one under a row-locking compare-and-swap — and
 * the store tests exercise the same rotate/replay/unknown scenarios against both.
 *
 * <p>Order of checks matters and is fail-safe:
 * <ol>
 *   <li>an already-{@link RefreshTokenFamily#reused() reused} family → {@link RefreshDecision.Replay}
 *       (it is burned; every further presentation is a replay);</li>
 *   <li>an expired family → {@link RefreshDecision.Expired};</li>
 *   <li>the current-token hash → {@link RefreshDecision.Rotate};</li>
 *   <li>the previous-token hash, presented within the reuse grace of the family's last rotation →
 *       {@link RefreshDecision.Reissue} (two concurrent requests of one session presented the same
 *       token; the loser receives the winner's successor). Off unless a grace is passed; the caller
 *       passes one only for confidential clients;</li>
 *   <li>the previous-token hash otherwise → {@link RefreshDecision.Replay} (a superseded token was
 *       presented — the canonical stolen-token replay);</li>
 *   <li>anything else → {@link RefreshDecision.Unknown} (rejected, no side effect).</li>
 * </ol>
 *
 * <p><strong>Detection depth is the immediate predecessor, by design.</strong> Only the current and
 * one previous hash are tracked, so a token more than one generation stale hashes to neither and is
 * {@code Unknown} (rejected) rather than {@code Replay} (burn). This is deliberate: burning a family
 * on <em>any</em> non-current hash would let a caller who guesses a family id (the id is embedded in
 * the token and is time-ordered) revoke that family with an arbitrary secret — a revocation
 * denial-of-service. Requiring the presented token to match a genuinely recent hash means only a
 * party that actually held a real recent token can trigger the burn. A deeply stale token is already
 * useless (it will not rotate), so the residual is a lost defence-in-depth signal, not access.
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
        return classify(family, presentedHash, now, Duration.ZERO);
    }

    /**
     * Classifies a presented refresh token against its family, allowing the token superseded by
     * the family's last rotation to be presented again within {@code reuseGrace}.
     *
     * <p>The grace trades a few seconds of replay detection for concurrency: a stolen predecessor
     * presented inside it obtains the same successor the legitimate holder did, never a new branch,
     * and outside it is a replay as before. A zero or negative grace is no grace.
     *
     * @param family        the family snapshot (never {@code null})
     * @param presentedHash the hash of the presented token (never {@code null} or blank)
     * @param now           the current instant (never {@code null})
     * @param reuseGrace    how long after a rotation its predecessor stays re-issuable
     *                      (never {@code null})
     * @return the decision (never {@code null})
     */
    public static RefreshDecision classify(
            RefreshTokenFamily family, String presentedHash, Instant now, Duration reuseGrace) {
        if (reuseGrace == null) {
            throw new IllegalArgumentException("reuseGrace must not be null");
        }
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
            return new RefreshDecision.Replay(family.id(), false);
        }
        if (family.isExpired(now)) {
            return new RefreshDecision.Expired();
        }
        if (sameHash(presentedHash, family.currentTokenHash())) {
            return new RefreshDecision.Rotate(family.id());
        }
        if (sameHash(presentedHash, family.previousTokenHash())) {
            if (family.rotatedWithin(reuseGrace, now)) {
                return new RefreshDecision.Reissue(family.id());
            }
            return new RefreshDecision.Replay(family.id());
        }
        return new RefreshDecision.Unknown();
    }

    /**
     * Constant-time equality of two token hashes, so a mismatch does not reveal how long a prefix of
     * the stored hash it shares; a {@code null} stored hash (no previous token yet) never matches.
     */
    private static boolean sameHash(String presented, String stored) {
        return stored != null && MessageDigest.isEqual(
                presented.getBytes(StandardCharsets.US_ASCII), stored.getBytes(StandardCharsets.US_ASCII));
    }
}
