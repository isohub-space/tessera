package dev.tessera.iam.adapter.rest.ratelimit;

import java.util.UUID;

/**
 * Observability seam for the rate-limit and credential-throttle security controls.
 *
 * <p>The controls live in this adapter but must stay free of any metrics framework —
 * {@code tessera-rest} has no Micrometer dependency — so they report events through this small
 * interface rather than touching a {@code MeterRegistry} directly. The adapter ships a fail-safe
 * {@link NoOpRateLimitMetrics} {@code @DefaultBean} (so its own {@code @QuarkusTest}s boot without an
 * observability stack), and the composition root supplies a Micrometer-backed implementation that
 * emits {@code iam.*} counters — the same {@code @DefaultBean}-superseded-by-the-real-adapter
 * mechanism used for the client-secret verifier and the stores.
 *
 * <p>Tag cardinality is deliberately bounded: events carry only the low-cardinality {@code surface}
 * and the {@code tenant}, never {@code client_id} or a source IP (both unbounded, and the latter
 * spoofable).
 */
public interface RateLimitMetrics {

    /**
     * An ingress request was throttled (HTTP 429) on the given surface.
     *
     * @param surface the rate-limit surface (e.g. {@code TOKEN}, {@code AUTHORIZE},
     *                {@code AUTHORIZE_IP}) — a bounded enum name
     * @param tenant  the resolved tenant, or {@code null} if unbound
     */
    void ingressThrottled(String surface, UUID tenant);

    /**
     * The rate-limit tracking table hit its {@code max-tracked-keys} cap and refused an untracked key
     * (fail-closed) — a signal that the limiter is under key-rotation pressure.
     */
    void trackingTableFull();

    /**
     * A credential-verification attempt was short-circuited because the per-{@code (tenant, client)}
     * failure budget was spent (the Argon2 pass was skipped).
     *
     * @param tenant the tenant whose credential budget was exhausted, or {@code null}
     */
    void credentialThrottled(UUID tenant);
}
