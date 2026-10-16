package dev.tessera.iam.domain.refresh;

/**
 * The outcome of classifying a presented refresh token against its family — the pure decision
 * {@link RefreshReuseDetection} produces and the application service acts on.
 *
 * <p>Exhaustive by construction (a sealed hierarchy), so a handler must address every case with
 * no {@code default}:
 * <ul>
 *   <li>{@link Rotate} — the presented token is the family's current token: mint a new token and
 *       advance the family;</li>
 *   <li>{@link Reissue} — the token the family's last rotation superseded was presented again
 *       by a confidential client within the configured reuse grace: answer with the same successor
 *       the rotation issued, and change nothing. A deliberate, bounded relaxation of strict
 *       rotation for concurrent requests, never applied to public clients;</li>
 *   <li>{@link Replay} — a superseded (or already-revoked) token was presented: revoke the
 *       <strong>entire</strong> family (OAuth 2.0 Security BCP / RFC 9700 §4.14);</li>
 *   <li>{@link Unknown} — the hash matches no known token in the family: reject, no side effect;</li>
 *   <li>{@link Expired} — the family has expired: reject, no side effect.</li>
 * </ul>
 */
public sealed interface RefreshDecision
        permits RefreshDecision.Rotate,
                RefreshDecision.Reissue,
                RefreshDecision.Replay,
                RefreshDecision.Unknown,
                RefreshDecision.Expired {

    /**
     * The presented token is current; rotate the family forward. The post-rotation family state
     * (new generation, hashes) travels on the store outcome's family snapshot, not here, so the two
     * adapters cannot disagree on a generation number.
     */
    record Rotate(FamilyId id) implements RefreshDecision {
        public Rotate {
            if (id == null) {
                throw new IllegalArgumentException("Rotate id must not be null");
            }
        }
    }

    /**
     * The immediately superseded token was presented again within the reuse grace, as two
     * concurrent requests of one session do. Re-issue the successor of that token; the family
     * itself does not change.
     */
    record Reissue(FamilyId id) implements RefreshDecision {
        public Reissue {
            if (id == null) {
                throw new IllegalArgumentException("Reissue id must not be null");
            }
        }
    }

    /**
     * A superseded or already-revoked token was replayed; revoke the whole family.
     *
     * @param id    the family
     * @param burns {@code true} when this presentation is what revokes the family, {@code false} when
     *              the family was already revoked (so a caller can report each revocation once)
     */
    record Replay(FamilyId id, boolean burns) implements RefreshDecision {
        public Replay {
            if (id == null) {
                throw new IllegalArgumentException("Replay id must not be null");
            }
        }

        /** A replay that revokes the family. */
        public Replay(FamilyId id) {
            this(id, true);
        }
    }

    /** The presented hash belongs to no known generation of the family. */
    record Unknown() implements RefreshDecision {
    }

    /** The family has expired. */
    record Expired() implements RefreshDecision {
    }
}
