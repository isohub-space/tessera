package dev.tessera.observability.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.Objects;

/**
 * Central factory and naming authority for the authorization server's
 * application metrics.
 *
 * <p>Every meter the server publishes follows a single convention:
 * {@code iam.<subsystem>.<metric>}, where {@code subsystem} names a coherent area
 * of the server (e.g. {@code token}, {@code authorize}, {@code key}, {@code audit},
 * {@code server}) and {@code metric} is a short, dimensionless event or quantity
 * name (e.g. {@code issued}, {@code requests}, {@code rotations}). Micrometer maps
 * the dotted name onto each registry's native form (Prometheus renders
 * {@code iam.token.issued} as {@code iam_token_issued_total}); callers always use
 * the dotted, registry-neutral name through this helper so the convention is
 * applied in exactly one place.</p>
 *
 * <p>Application-scoped and backed by the injected {@link MeterRegistry}. Meter
 * creation is idempotent — Micrometer returns the existing meter for a repeated
 * name+tag set — so callers may fetch a counter or timer on every event without
 * caching it themselves.</p>
 */
@ApplicationScoped
public class IamMetrics {

    /** Common prefix for every application meter. */
    public static final String PREFIX = "iam";

    private final MeterRegistry registry;

    @Inject
    public IamMetrics(MeterRegistry registry) {
        this.registry = Objects.requireNonNull(registry, "registry must not be null");
    }

    /**
     * Composes a metric name from a subsystem and a metric, enforcing the
     * {@code iam.<subsystem>.<metric>} convention.
     *
     * @param subsystem the subsystem segment (e.g. {@code "token"}); not null/blank
     * @param metric    the metric segment (e.g. {@code "issued"}); not null/blank
     * @return the fully-qualified dotted meter name
     */
    public static String name(String subsystem, String metric) {
        requireSegment(subsystem, "subsystem");
        requireSegment(metric, "metric");
        return PREFIX + "." + subsystem + "." + metric;
    }

    /**
     * Returns (creating on first use) the counter {@code iam.<subsystem>.<metric>}
     * carrying the supplied tags.
     *
     * @param subsystem the subsystem segment
     * @param metric    the metric segment
     * @param tags      alternating key/value tag pairs; must be of even length
     * @return the counter
     */
    public Counter counter(String subsystem, String metric, String... tags) {
        return Counter.builder(name(subsystem, metric)).tags(tags).register(registry);
    }

    /**
     * Increments the counter {@code iam.<subsystem>.<metric>} by one — the common
     * "an event happened" case.
     *
     * @param subsystem the subsystem segment
     * @param metric    the metric segment
     * @param tags      alternating key/value tag pairs; must be of even length
     */
    public void increment(String subsystem, String metric, String... tags) {
        counter(subsystem, metric, tags).increment();
    }

    /**
     * Returns (creating on first use) the timer {@code iam.<subsystem>.<metric>}
     * carrying the supplied tags, for recording operation latencies.
     *
     * @param subsystem the subsystem segment
     * @param metric    the metric segment
     * @param tags      alternating key/value tag pairs; must be of even length
     * @return the timer
     */
    public Timer timer(String subsystem, String metric, String... tags) {
        return Timer.builder(name(subsystem, metric)).tags(tags).register(registry);
    }

    /**
     * Registers a gauge {@code iam.<subsystem>.<metric>} that samples {@code state}
     * via {@code accessor} whenever the registry is scraped.
     *
     * @param subsystem the subsystem segment
     * @param metric    the metric segment
     * @param state     the object to sample (held by a weak reference by Micrometer)
     * @param accessor  reads the current value from {@code state}
     * @param <T>       the sampled state type
     * @return {@code state}, as Micrometer's gauge registration returns its subject
     */
    public <T> T gauge(String subsystem, String metric, T state,
            java.util.function.ToDoubleFunction<T> accessor) {
        return registry.gauge(name(subsystem, metric), state, accessor);
    }

    private static void requireSegment(String segment, String label) {
        if (segment == null || segment.isBlank()) {
            throw new IllegalArgumentException(label + " must not be null or blank");
        }
        if (segment.indexOf('.') >= 0) {
            throw new IllegalArgumentException(label + " must not contain '.': " + segment);
        }
    }
}
