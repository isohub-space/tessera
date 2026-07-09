package dev.tessera.iam.adapter.rest.ratelimit;

import io.quarkus.arc.DefaultBean;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.UUID;

/**
 * Fail-safe no-op {@link RateLimitMetrics}: the adapter's default when no observability stack is on
 * the classpath (its own {@code @QuarkusTest}s). Registered {@link DefaultBean} so the composition
 * root's Micrometer-backed implementation supersedes it automatically in the assembled server —
 * mirroring the {@code @DefaultBean} fallbacks used for the client-secret verifier and the stores.
 */
@ApplicationScoped
@DefaultBean
class NoOpRateLimitMetrics implements RateLimitMetrics {

    @Override
    public void ingressThrottled(String surface, UUID tenant) {
        // Intentionally empty — metrics are emitted only when the observability adapter is present.
    }

    @Override
    public void trackingTableFull() {
        // Intentionally empty.
    }

    @Override
    public void credentialThrottled(UUID tenant) {
        // Intentionally empty.
    }
}
