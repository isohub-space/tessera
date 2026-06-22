package dev.tessera.iam.domain.tenancy;

import java.util.UUID;

/**
 * Identity of a tenant, as seen by Tessera.
 *
 * <p>A deliberately self-contained, framework-free value object. iam-domain does
 * <strong>not</strong> import an external tenant registry's {@code TenantId}: keeping a local copy
 * keeps the domain a closed, dependency-free functional core (the design's
 * "iam-domain is pure {@code java..}" rule). Correlation with an external tenant registry happens
 * in the adapter shell, not here.
 *
 * @param value the tenant UUID (never {@code null})
 */
public record TenantId(UUID value) {

    public TenantId {
        if (value == null) {
            throw new IllegalArgumentException("TenantId value must not be null");
        }
    }

    /** Parses a {@link TenantId} from its canonical UUID string form. */
    public static TenantId fromString(String value) {
        return new TenantId(UUID.fromString(value));
    }

    /** Generates a fresh random {@link TenantId}. */
    public static TenantId generate() {
        return new TenantId(UUID.randomUUID());
    }
}
