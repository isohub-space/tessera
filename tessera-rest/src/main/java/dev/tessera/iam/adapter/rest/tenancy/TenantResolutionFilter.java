package dev.tessera.iam.adapter.rest.tenancy;

import dev.tessera.iam.adapter.rest.tenancy.TenantHeaders.MalformedTenantException;
import dev.tessera.iam.adapter.rest.tenancy.TenantHeaders.MissingTenantException;
import dev.tessera.iam.adapter.rest.problem.ProblemResponse;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

/**
 * Resolves the caller's realm ({@code tenant} + {@code baseline}) from the trusted
 * ingress headers once, at the start of every request, and binds it into the
 * request-scoped {@link TenantContext}. Downstream resources read the realm from that
 * context instead of re-parsing headers, so tenant resolution happens in exactly one
 * place and is impossible to skip.
 *
 * <p>Registered at {@link Priorities#AUTHENTICATION} so it runs before any resource
 * method and before authorization: a request that does not carry a resolvable tenant is
 * rejected here, fail-closed, and never reaches a handler that could touch tenant data.
 *
 * <p>The tenant comes <strong>only</strong> from the gateway-asserted
 * {@link TenantHeaders#TENANT} header — never from the request body — per the trust
 * boundary documented on {@link TenantHeaders}. A missing or malformed header is a
 * {@code 400}.
 *
 * <p>Bound via {@link TenantScoped}, so it runs only on tenant-scoped endpoints and never
 * on unscoped surfaces (health/metrics probes, utility endpoints).
 */
@Provider
@TenantScoped
@Priority(Priorities.AUTHENTICATION)
public class TenantResolutionFilter implements ContainerRequestFilter {

    @Inject
    TenantContext tenantContext;

    @Override
    public void filter(ContainerRequestContext request) {
        String tenantHeader = request.getHeaderString(TenantHeaders.TENANT);
        String baselineHeader = request.getHeaderString(TenantHeaders.BASELINE);
        try {
            RealmKey realm = TenantHeaders.resolve(tenantHeader, baselineHeader);
            tenantContext.bind(realm);
        } catch (MissingTenantException | MalformedTenantException e) {
            // Fail closed: a request with no resolvable tenant is rejected before it
            // reaches any resource that could touch tenant-scoped data.
            request.abortWith(ProblemResponse.badRequest(e.getMessage()));
        }
    }
}
