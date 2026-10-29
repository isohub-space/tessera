package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshDecision;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.time.Duration;
import java.time.Instant;

/**
 * Outbound port for the rotating refresh-token family store — the analogue of
 * {@link AuthorizationCodeStorePort} for refresh tokens.
 *
 * <p>A refresh token belongs to a lineage (a "family"); each redemption issues a fresh token,
 * invalidates the presented one, and advances the family. Presenting a superseded (or an
 * already-revoked) token is a replay that revokes the whole family (OAuth 2.0 Security BCP /
 * RFC 9700 §4.14). The security-critical contract:
 *
 * <ul>
 *   <li><strong>Atomic single-use rotation.</strong> {@link #consumeAndRotate} must compare-and-swap
 *       the current-token hash exactly once: of any number of concurrent redemptions of the same
 *       token, at most one is a {@link RefreshDecision.Rotate}; the rest observe the superseded hash
 *       and become {@link RefreshDecision.Replay}, or {@link RefreshDecision.Reissue} within a
 *       configured reuse grace (which changes nothing). This atomicity is the store's job, not the
 *       caller's — an in-JVM lock would neither be event-loop-safe nor hold across nodes.</li>
 *   <li><strong>Tenant-scoped, fail-closed.</strong> Reads and rotation are scoped to the family's
 *       authoritative realm; a lookup outside it misses rather than leaking.</li>
 *   <li><strong>Idempotent, monotonic revocation.</strong> {@link #revokeFamily} may be called any
 *       number of times with the same effect.</li>
 * </ul>
 *
 * <p>The shipped adapter is single-node (in-memory for tests; a single Postgres node for the
 * server, whose row lock provides the CAS). A clustered deployment backs this port with a
 * shared-cache backend providing the same atomic compare-and-swap + monotonic revoke; the swap is a
 * CDI-bean change with no caller impact, so implementations must not leak store-specific assumptions
 * into this contract.
 */
public interface RefreshTokenStorePort {

    /**
     * Persists a freshly issued family at generation 0. The family carries its own authoritative
     * realm, so no separate tenant argument is needed.
     *
     * @param family the family to store (never {@code null})
     * @return a {@link Uni} completing when stored
     */
    Uni<Void> createFamily(RefreshTokenFamily family);

    /**
     * Atomically consumes the presented token and, if it is current, rotates the family forward:
     * sets {@code previous := current}, {@code current := newTokenHash}, and increments the
     * generation — all in one atomic step scoped to {@code authoritativeRealm}. Returns the decision
     * the store actually enforced.
     *
     * @param id                 the family id parsed from the presented token (never {@code null})
     * @param authoritativeRealm the family's own realm — the source of truth for scoping, resolved
     *                           server-side, not from any request header (never {@code null})
     * @param presentedHash      hash of the presented token (never {@code null} or blank)
     * @param newTokenHash       hash of the freshly minted replacement token (never {@code null} or blank)
     * @param now                the current instant, for expiry evaluation (never {@code null})
     * @return a {@link Uni} emitting the outcome (never {@code null}); a {@code Rotate} outcome
     *         carries the updated family snapshot needed to mint the new tokens
     */
    default Uni<RefreshConsumeOutcome> consumeAndRotate(
            FamilyId id,
            RealmKey authoritativeRealm,
            String presentedHash,
            String newTokenHash,
            Instant now) {
        return consumeAndRotate(
                id, authoritativeRealm, presentedHash, newTokenHash, now, Duration.ZERO, null);
    }

    /**
     * As {@link #consumeAndRotate(FamilyId, RealmKey, String, String, Instant)}, and records the
     * rotation instant and {@code rotationSalt} on a rotation; the token the family's last rotation
     * superseded, presented again within {@code reuseGrace} of that rotation, is a {@link
     * RefreshDecision.Reissue} that leaves the family unchanged instead of a {@link
     * RefreshDecision.Replay} that burns it.
     *
     * @param reuseGrace   the reuse grace ({@link Duration#ZERO} for none; never {@code null})
     * @param rotationSalt the salt the new token's secret was derived with, stored on a rotation
     *                     ({@code null} when the secret is random)
     */
    Uni<RefreshConsumeOutcome> consumeAndRotate(
            FamilyId id,
            RealmKey authoritativeRealm,
            String presentedHash,
            String newTokenHash,
            Instant now,
            Duration reuseGrace,
            String rotationSalt);

    /**
     * Revokes the entire family (idempotent). Used both by replay handling and by explicit token
     * revocation.
     *
     * @param id                 the family id (never {@code null})
     * @param authoritativeRealm the family's own realm (never {@code null})
     * @return a {@link Uni} completing when the family is revoked (or was already)
     */
    Uni<Void> revokeFamily(FamilyId id, RealmKey authoritativeRealm);

    /**
     * Revokes every family that {@code clientId} holds for {@code userId} within {@code realm} and
     * that was created before {@code createdBefore} (idempotent). Used when the user ends their
     * session with that client (RP-initiated logout): a refresh token is not linked to the session
     * it was issued under, so ending the session revokes the client's families for the user, but
     * never one created after the ID token the logout presented, so an old hint cannot end a later
     * sign-in. A user id that cannot own a family (one that is not a UUID) revokes nothing.
     * @param realm         the realm to revoke within (never {@code null})
     * @param userId        the subject the families were issued for (never {@code null})
     * @param clientId      the client the families were issued to (never {@code null})
     * @param createdBefore only families created strictly before this instant are revoked
     *                      (never {@code null})
     * @return a {@link Uni} completing when every matching family is revoked
     */
    Uni<Void> revokeFamiliesOf(RealmKey realm, String userId, ClientId clientId, Instant createdBefore);

    /**
     * Reads a family snapshot within {@code realm} (RLS-scoped), or {@code null} if none matches.
     * Used by introspection and by tests; not the rotation path.
     *
     * @param id    the family id (never {@code null})
     * @param realm the realm to scope the read to (never {@code null})
     * @return a {@link Uni} emitting the snapshot, or {@code null}
     */
    Uni<RefreshTokenFamily> find(FamilyId id, RealmKey realm);

    /**
     * The outcome of {@link #consumeAndRotate}: the enforced decision and, when present, the family
     * snapshot it acted on. For a {@link RefreshDecision.Rotate} the snapshot is the post-rotation
     * state (new generation and current hash) the caller mints tokens from. {@code family} is
     * {@code null} only when the id matched no family at all.
     *
     * @param decision the decision the store enforced (never {@code null})
     * @param family   the affected family snapshot, or {@code null} if the id was unknown
     */
    record RefreshConsumeOutcome(RefreshDecision decision, RefreshTokenFamily family) {

        public RefreshConsumeOutcome {
            if (decision == null) {
                throw new IllegalArgumentException("decision must not be null");
            }
        }
    }
}
