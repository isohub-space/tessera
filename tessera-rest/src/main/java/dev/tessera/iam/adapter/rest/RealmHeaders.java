package dev.tessera.iam.adapter.rest;

import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import jakarta.ws.rs.BadRequestException;
import java.util.UUID;

/**
 * Resolves the {@link RealmKey} a request runs within from the tenant headers
 * ({@code X-Tenant-Id}, optional {@code X-Baseline-Id}).
 *
 * <p>Full request-scoped tenant propagation (gateway → {@code TenantContext}) is a
 * cross-cutting concern handled elsewhere; at the endpoint edge the realm is taken
 * directly from the headers, with a zero baseline when none is supplied. Centralised here
 * so every endpoint resolves the realm identically (and fails the same way on a missing or
 * malformed tenant).
 *
 * <p><strong>TODO (provisional — tenant from a trusted header):</strong> the realm is
 * derived from the {@code X-Tenant-Id} request header, which is only safe behind a gateway
 * that authenticates the caller and sets the header itself (a raw header is otherwise
 * client-controlled). This is acceptable today because the authorization endpoint precedes
 * any authenticated session — there is no token claim to derive the tenant from yet — and it
 * keeps parity with the other edge resources. Once the session/auth layer exists, the realm
 * must be derived from an <em>authenticated</em> claim (the established session / token),
 * not a raw header.
 */
final class RealmHeaders {

    private static final BaselineId ZERO_BASELINE = new BaselineId(new UUID(0L, 0L));

    private RealmHeaders() {
    }

    /**
     * @param tenantHeader   the {@code X-Tenant-Id} header (a tenant UUID; required)
     * @param baselineHeader the {@code X-Baseline-Id} header (a baseline UUID; optional)
     * @return the resolved realm key
     * @throws BadRequestException if the tenant header is missing or not a UUID
     */
    static RealmKey resolve(String tenantHeader, String baselineHeader) {
        if (tenantHeader == null || tenantHeader.isBlank()) {
            throw new BadRequestException("Missing X-Tenant-Id header");
        }
        TenantId tenant = new TenantId(parseUuid(tenantHeader, "X-Tenant-Id"));
        BaselineId baseline = (baselineHeader == null || baselineHeader.isBlank())
                ? ZERO_BASELINE
                : new BaselineId(parseUuid(baselineHeader, "X-Baseline-Id"));
        return new RealmKey(tenant, baseline);
    }

    private static UUID parseUuid(String value, String header) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException ex) {
            throw new BadRequestException("Malformed " + header + " header (expected a UUID)");
        }
    }
}
