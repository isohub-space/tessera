package dev.tessera.iam.adapter.rest.tenancy;

import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.util.UUID;

/**
 * The trusted ingress header contract for tenant resolution, and the fail-closed parser
 * that turns it into a {@link RealmKey}.
 *
 * <p><strong>Trust boundary.</strong> {@link #TENANT} ({@value #TENANT}) is a
 * <em>gateway-asserted</em> header: the deployment's edge gateway authenticates the
 * caller, sets this header, and strips any client-supplied value before the request
 * reaches this server. The server therefore trusts the header as the caller's tenant and
 * never infers the tenant from the request body. Reaching this server with a
 * client-controlled tenant header is a deployment misconfiguration (the gateway must
 * overwrite/strip it), not a supported mode. On the public, unauthenticated metadata
 * endpoints (OIDC discovery, JWKS) a forged header could at most expose another tenant's
 * <em>public</em> metadata — an accepted low-severity bound — never any private material.
 *
 * <p>{@link #BASELINE} ({@value #BASELINE}) is optional; when absent the realm uses the
 * zero baseline, which is the convention for the single configuration tier.
 *
 * <p>This type is framework-free so the resolution rule can be unit-tested without a
 * container; the {@link TenantResolutionFilter} adapts it to the JAX-RS request pipeline.
 */
public final class TenantHeaders {

    /** Gateway-asserted tenant header (a canonical UUID string). */
    public static final String TENANT = "X-Tenant-Id";

    /** Optional baseline (configuration-version) header (a canonical UUID string). */
    public static final String BASELINE = "X-Baseline-Id";

    private static final BaselineId ZERO_BASELINE = new BaselineId(new UUID(0L, 0L));

    private TenantHeaders() {
    }

    /**
     * Resolves the realm from the ingress headers, fail-closed.
     *
     * @param tenantHeader   the {@value #TENANT} value (required, a UUID string)
     * @param baselineHeader the {@value #BASELINE} value (optional, a UUID string)
     * @return the resolved {@link RealmKey}
     * @throws MissingTenantException if the tenant header is absent or blank
     * @throws MalformedTenantException if a header is present but not a valid UUID
     */
    public static RealmKey resolve(String tenantHeader, String baselineHeader) {
        if (tenantHeader == null || tenantHeader.isBlank()) {
            throw new MissingTenantException();
        }
        TenantId tenant = new TenantId(parse(tenantHeader.trim(), TENANT));
        BaselineId baseline = (baselineHeader == null || baselineHeader.isBlank())
                ? ZERO_BASELINE
                : new BaselineId(parse(baselineHeader.trim(), BASELINE));
        return new RealmKey(tenant, baseline);
    }

    private static UUID parse(String value, String header) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new MalformedTenantException(header);
        }
    }

    /** The required tenant header was absent or blank. */
    public static final class MissingTenantException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        MissingTenantException() {
            super("Missing " + TENANT + " header");
        }
    }

    /** A tenant/baseline header was present but not a valid UUID. */
    public static final class MalformedTenantException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        MalformedTenantException(String header) {
            super("Malformed " + header + " header (expected a UUID)");
        }
    }
}
