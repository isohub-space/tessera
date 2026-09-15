package dev.tessera.iam.domain.session;

import dev.tessera.iam.domain.tenancy.RealmKey;
import java.time.Instant;

/**
 * An established end-user login session: proof, for the lifetime of {@code expiresAt},
 * that {@code subjectId} has authenticated within {@code realm}.
 *
 * <p>Tenant-scoped by construction: {@link #realm()} travels with the session everywhere
 * it is looked up, so a session minted for one {@code (tenant, baseline)} is a structurally
 * different value from a session minted for another, even if a colliding {@link SessionId}
 * were ever presented — the store is expected to additionally enforce this at the
 * persistence boundary (row-level security), this type only carries the invariant.
 *
 * @param realm     the realm the session was established in (never {@code null})
 * @param id        the session identity — also the cookie value (never {@code null})
 * @param subjectId the authenticated end-user {@code sub} (never {@code null} or blank)
 * @param createdAt when the session was established (never {@code null})
 * @param expiresAt when the session stops being valid (never {@code null})
 */
public record Session(RealmKey realm, SessionId id, String subjectId, Instant createdAt, Instant expiresAt) {

    public Session {
        if (realm == null) {
            throw new IllegalArgumentException("Session realm must not be null");
        }
        if (id == null) {
            throw new IllegalArgumentException("Session id must not be null");
        }
        if (subjectId == null || subjectId.isBlank()) {
            throw new IllegalArgumentException("Session subjectId must not be blank");
        }
        if (createdAt == null) {
            throw new IllegalArgumentException("Session createdAt must not be null");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("Session expiresAt must not be null");
        }
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("Session expiresAt must be after createdAt");
        }
    }

    /** True when this session is no longer valid at {@code now}. */
    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
