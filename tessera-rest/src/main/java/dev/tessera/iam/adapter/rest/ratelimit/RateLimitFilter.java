package dev.tessera.iam.adapter.rest.ratelimit;

import dev.tessera.iam.adapter.rest.problem.ProblemResponse;
import dev.tessera.iam.adapter.rest.ratelimit.RateLimitKey.Surface;
import dev.tessera.iam.adapter.rest.ratelimit.RateLimitStore.RateLimitDecision;
import dev.tessera.iam.adapter.rest.tenancy.TenantContext;
import jakarta.annotation.Priority;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Ingress rate limiter for the credential-stuffing / token-guessing surfaces. Runs as a classic
 * name-bound {@link ContainerRequestFilter} at {@link Priorities#AUTHENTICATION} {@code + 100} —
 * a higher number than {@code TenantResolutionFilter} ({@link Priorities#AUTHENTICATION}), so it
 * runs <em>after</em> tenant resolution and reads the already-bound tenant from
 * {@link TenantContext}. A request with no resolvable tenant is already {@code 400}'d upstream and
 * never reaches here.
 *
 * <p><strong>Keying.</strong> The tenant (gateway-asserted, validated upstream) is the trustworthy
 * axis and is always in the key. The {@code /token} bucket keys on the HTTP-Basic {@code client_id}
 * when present (RFC 6749 §2.3.1's preferred path) — the body {@code client_id} is deliberately not
 * read, because consuming the entity stream in a filter breaks form parsing; that case is covered
 * by the credential-lockout tier instead. {@code /authorize} keys on the query {@code client_id}
 * plus a coarse per-IP backstop.
 *
 * <p><strong>Source IP is best-effort.</strong> {@code quarkus.http.proxy.trusted-proxies} is not
 * enabled, so {@code X-Forwarded-For} is spoofable by anything reaching the HTTP port. IP is
 * therefore only a secondary axis, never the sole basis of a decision; when it is absent the
 * bucket degrades to a per-tenant one rather than being skipped (fail-closed).
 *
 * <p>Every store operation is in-memory and non-blocking, so calling it on the reactive I/O
 * thread here is safe.
 */
@Provider
@RateLimited
@Priority(Priorities.AUTHENTICATION + 100)
public class RateLimitFilter implements ContainerRequestFilter {

    @Inject
    TenantContext tenantContext;

    @Inject
    RateLimitStore store;

    // Resolved lazily (at request time): this filter is a JAX-RS interceptor that RESTEasy
    // instantiates eagerly at deployment — before the @ConfigMapping is registered with the
    // runtime config — so injecting the mapping directly would fail to resolve. By request time
    // it is available.
    @Inject
    Instance<RateLimitConfig> configInstance;

    @Override
    public void filter(ContainerRequestContext request) {
        RateLimitConfig config = configInstance.get();
        if (!config.enabled()) {
            return;
        }

        UUID tenant = tenantContext.realmIfPresent()
                .map(realm -> realm.tenant().value())
                .orElse(null);
        String ip = sourceIp(request);

        List<Bucket> buckets = new ArrayList<>(2);
        if (isToken(request)) {
            String basicClientId = basicClientId(request.getHeaderString("Authorization"));
            String principal = basicClientId != null ? "cid:" + basicClientId : "ip:" + ip;
            buckets.add(new Bucket(
                    new RateLimitKey(Surface.TOKEN, tenant, principal), tokenPolicy(config)));
        } else {
            String clientId = request.getUriInfo().getQueryParameters().getFirst("client_id");
            RateLimitPolicy authorizePolicy = authorizePolicy(config);
            if (clientId != null && !clientId.isBlank()) {
                buckets.add(new Bucket(
                        new RateLimitKey(Surface.AUTHORIZE, tenant, "cid:" + clientId), authorizePolicy));
            }
            buckets.add(new Bucket(
                    new RateLimitKey(Surface.AUTHORIZE_IP, tenant, "ip:" + ip), authorizePolicy));
        }

        for (Bucket bucket : buckets) {
            RateLimitDecision decision = store.tryAcquire(bucket.key(), bucket.policy());
            if (!decision.allowed()) {
                // A single generic 429 — it must not reveal which key/limit tripped.
                request.abortWith(ProblemResponse.tooManyRequests(decision.retryAfterSeconds()));
                return;
            }
        }
    }

    private boolean isToken(ContainerRequestContext request) {
        return request.getUriInfo().getPath().contains("token");
    }

    private static RateLimitPolicy tokenPolicy(RateLimitConfig config) {
        return new RateLimitPolicy(config.tokenCapacity(), config.tokenRefillPerMinute() / 60.0);
    }

    private static RateLimitPolicy authorizePolicy(RateLimitConfig config) {
        return new RateLimitPolicy(
                config.authorizeCapacity(), config.authorizeRefillPerMinute() / 60.0);
    }

    /** First {@code X-Forwarded-For} hop, else a fixed sentinel (fail-closed to a per-tenant bucket). */
    private static String sourceIp(ContainerRequestContext request) {
        String forwarded = request.getHeaderString("X-Forwarded-For");
        if (forwarded == null || forwarded.isBlank()) {
            return "unknown";
        }
        int comma = forwarded.indexOf(',');
        String first = (comma >= 0 ? forwarded.substring(0, comma) : forwarded).trim();
        return first.isEmpty() ? "unknown" : first;
    }

    /**
     * The {@code client_id} from an HTTP-Basic {@code Authorization} header, or {@code null} if the
     * header is absent or not Basic. Parsing here never consumes the request body.
     */
    private static String basicClientId(String authorization) {
        if (authorization == null) {
            return null;
        }
        String prefix = "Basic ";
        if (!authorization.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return null;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(authorization.substring(prefix.length()).trim());
            String pair = new String(decoded, StandardCharsets.UTF_8);
            int colon = pair.indexOf(':');
            if (colon < 0) {
                return null;
            }
            String id = pair.substring(0, colon);
            return id.isBlank() ? null : id;
        } catch (IllegalArgumentException notBase64) {
            return null;
        }
    }

    /** A key paired with the policy that governs it. */
    private record Bucket(RateLimitKey key, RateLimitPolicy policy) {
    }
}
