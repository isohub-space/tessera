package dev.tessera.iam.domain.refresh;

import java.util.UUID;

/**
 * Stable identity of a {@link RefreshTokenFamily} — the lineage a rotating refresh token
 * belongs to.
 *
 * <p>A time-ordered UUID (version 7) in practice, because families are created on a hot,
 * append-heavy path; the domain reasons only over the identity, not its textual shape. The
 * id is embedded (non-secret) in the opaque refresh-token string so a presented token can be
 * routed to its family without trusting any request header.
 *
 * @param value the family UUID (never {@code null})
 */
public record FamilyId(UUID value) {

    public FamilyId {
        if (value == null) {
            throw new IllegalArgumentException("FamilyId value must not be null");
        }
    }

    /** Parses a {@link FamilyId} from its canonical UUID string form. */
    public static FamilyId fromString(String value) {
        return new FamilyId(UUID.fromString(value));
    }
}
