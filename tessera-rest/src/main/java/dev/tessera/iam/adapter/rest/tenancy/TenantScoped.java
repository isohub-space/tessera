package dev.tessera.iam.adapter.rest.tenancy;

import jakarta.ws.rs.NameBinding;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a JAX-RS resource (or method) as tenant-scoped: a request to it must carry a
 * resolvable tenant, and the {@link TenantResolutionFilter} runs to resolve it into the
 * request-scoped {@link TenantContext} before the resource method executes.
 *
 * <p>This is a JAX-RS {@link NameBinding}, so the filter applies <em>only</em> to
 * annotated endpoints — not to unscoped surfaces such as health/metrics probes or
 * non-tenant utility endpoints. Annotate every endpoint that reads or writes
 * tenant-scoped data with this so the tenant requirement is explicit and fail-closed.
 */
@NameBinding
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface TenantScoped {
}
