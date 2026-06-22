package dev.tessera.iam.domain.tenancy;

import java.util.UUID;

/**
 * Baseline (configuration-version) identity scoping a tenant's IAM state
 *.
 *
 * <p>Framework-free value object. Together with {@link TenantId} it forms the
 * {@link RealmKey} that scopes every piece of IAM data; the platform isolation
 * rule is that domain keys carry {@code TenantId} + {@code BaselineId}.
 *
 * @param value the baseline UUID (never {@code null})
 */
public record BaselineId(UUID value) {

    public BaselineId {
        if (value == null) {
            throw new IllegalArgumentException("BaselineId value must not be null");
        }
    }

    /** Parses a {@link BaselineId} from its canonical UUID string form. */
    public static BaselineId fromString(String value) {
        return new BaselineId(UUID.fromString(value));
    }

    /** Generates a fresh random {@link BaselineId}. */
    public static BaselineId generate() {
        return new BaselineId(UUID.randomUUID());
    }
}
