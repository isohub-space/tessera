package dev.tessera.iam.adapter.persistence;

import java.util.UUID;

/**
 * The fixed, well-known development tenant.
 *
 * <p>In {@code %dev} the Flyway dev-seed ({@code db/dev-seed/V900__dev_seed.sql})
 * inserts this tenant's single {@code ACTIVE} signing key so {@code /q/health/ready}
 * comes up green under {@code quarkus dev}. The signing-key readiness gate scopes
 * its query to this same tenant. The literal here MUST match the UUID hard-coded in
 * that seed migration.</p>
 *
 * <p>This is a dev-only convenience; production tenants are provisioned by an external tenant registry
 * and bound per request, never from this constant.</p>
 */
public final class DevTenant {

    /** Fixed well-known dev tenant id — keep in sync with V900__dev_seed.sql. */
    public static final UUID ID = UUID.fromString("0de00000-0000-4000-a000-00000000d3f0");

    private DevTenant() {
    }
}
