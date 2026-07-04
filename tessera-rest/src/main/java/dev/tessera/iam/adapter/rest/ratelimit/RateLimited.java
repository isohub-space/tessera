package dev.tessera.iam.adapter.rest.ratelimit;

import jakarta.ws.rs.NameBinding;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a JAX-RS resource (or method) as rate-limited: the {@link RateLimitFilter} runs before
 * the resource method and throttles abusive callers per {@code (surface, tenant, principal)}.
 *
 * <p>A JAX-RS {@link NameBinding}, so the limiter applies <em>only</em> to annotated endpoints
 * — the credential-stuffing / token-guessing surfaces ({@code /authorize}, {@code /token}) — and
 * never to unscoped surfaces such as health/metrics probes. A dedicated binding (rather than
 * reusing {@code @TenantScoped}) keeps the concern explicit and independently toggleable.
 */
@NameBinding
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimited {
}
