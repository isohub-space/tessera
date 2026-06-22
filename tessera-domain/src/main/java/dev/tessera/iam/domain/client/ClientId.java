package dev.tessera.iam.domain.client;

import java.util.UUID;

/**
 * Stable internal identity of a {@link Client}.
 *
 * <p><strong>Type choice: UUID, not the wire {@code client_id} string.</strong>
 * OAuth2's {@code client_id} is an opaque, registration-time string, but inside
 * the domain we want one uniform, collision-free, framework-free identity model —
 * matching every other id in this codebase ({@code ItemId}, an external tenant registry
 * {@code TenantId}). The human/wire {@code client_id} (which may be a UUID's
 * canonical form, or a chosen handle) is a registration mapping handled in the
 * adapter shell; the domain never reasons over its textual shape.
 *
 * @param value the client UUID (never {@code null})
 */
public record ClientId(UUID value) {

    public ClientId {
        if (value == null) {
            throw new IllegalArgumentException("ClientId value must not be null");
        }
    }

    /** Parses a {@link ClientId} from its canonical UUID string form. */
    public static ClientId fromString(String value) {
        return new ClientId(UUID.fromString(value));
    }

    /** Generates a fresh random {@link ClientId}. */
    public static ClientId generate() {
        return new ClientId(UUID.randomUUID());
    }
}
