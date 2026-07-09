package dev.tessera.iam.launcher.observability;

import dev.tessera.iam.adapter.rest.ratelimit.RateLimitMetrics;
import dev.tessera.observability.metrics.IamMetrics;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.UUID;

/**
 * Micrometer-backed {@link RateLimitMetrics}: emits {@code iam.*} counters for the rate-limit and
 * credential-throttle security controls through {@link IamMetrics}.
 *
 * <p>A plain {@code @ApplicationScoped} bean in the composition root, so it supersedes the REST
 * adapter's no-op {@code @DefaultBean} in the assembled server — the same mechanism that swaps the
 * Argon2 verifier in for the fail-closed default — keeping {@code tessera-rest} free of any metrics
 * dependency. Counters (Prometheus renders {@code iam.ratelimit.throttled} as
 * {@code iam_ratelimit_throttled_total}):
 * <ul>
 *   <li>{@code iam.ratelimit.throttled} {@code {surface, tenant}} — an ingress 429;</li>
 *   <li>{@code iam.ratelimit.table_full} — the tracking table hit its cap (fail-closed);</li>
 *   <li>{@code iam.credential.throttled} {@code {tenant}} — a credential failure-budget short-circuit.</li>
 * </ul>
 * Tags are bounded to {@code surface} and {@code tenant} (never {@code client_id} or source IP). A
 * fail-closed table-full denial is counted as <em>both</em> {@code table_full} (the reason) and
 * {@code throttled} (the outcome — the request was throttled), so {@code table_full} is a strict
 * subset of {@code throttled}, not a disjoint total.
 */
@ApplicationScoped
public class MicrometerRateLimitMetrics implements RateLimitMetrics {

    private static final String SUBSYSTEM_RATELIMIT = "ratelimit";
    private static final String SUBSYSTEM_CREDENTIAL = "credential";
    private static final String TAG_NONE = "none";

    private final IamMetrics metrics;

    @Inject
    public MicrometerRateLimitMetrics(IamMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public void ingressThrottled(String surface, UUID tenant) {
        metrics.increment(SUBSYSTEM_RATELIMIT, "throttled", "surface", text(surface), "tenant", text(tenant));
    }

    @Override
    public void trackingTableFull() {
        metrics.increment(SUBSYSTEM_RATELIMIT, "table_full");
    }

    @Override
    public void credentialThrottled(UUID tenant) {
        metrics.increment(SUBSYSTEM_CREDENTIAL, "throttled", "tenant", text(tenant));
    }

    private static String text(String value) {
        return value == null || value.isBlank() ? TAG_NONE : value;
    }

    private static String text(UUID value) {
        return value == null ? TAG_NONE : value.toString();
    }
}
