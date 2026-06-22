package dev.tessera.observability.health;

import java.util.List;
import java.util.Objects;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;

/**
 * Shared base for a service's {@code @Readiness} probe that projects a
 * {@link DegradedSubsystemRegistry} into {@code GET /q/health/ready} and rolls
 * the subsystem statuses up into an overall verdict according to a pluggable
 * {@link ReadinessPolicy}.
 *
 * <p>A concrete subclass is annotated {@code @Readiness @ApplicationScoped},
 * injects the registry, and supplies:</p>
 * <ul>
 *   <li>{@link #serviceName()} — the {@code named(...)} of the response;</li>
 *   <li>{@link #subsystems()} — the ordered catalogue of subsystems to render,
 *       each flagged required or optional;</li>
 *   <li>{@link #policy()} — how those statuses determine the overall verdict.</li>
 * </ul>
 *
 * <p>The response lists each subsystem as a data entry ({@code name -> status});
 * subclasses may add their own entries by overriding {@link #decorate}. Health
 * lives in the launcher/rest layer only — this class is framework-light (no CDI
 * annotations of its own) so the concrete subclass owns the bean scope and never
 * leaks into {@code domain}/{@code api}.</p>
 */
public abstract class AbstractReadinessCheck implements HealthCheck {

    /**
     * A subsystem to render in the readiness response.
     *
     * @param name     the data-key / subsystem name as registered in the
     *                 {@link DegradedSubsystemRegistry}
     * @param required whether {@link ReadinessPolicy#MINIMUM_VIABLE} must see
     *                 this subsystem {@link SubsystemStatus#UP} for overall UP;
     *                 ignored under {@link ReadinessPolicy#UP_WHILE_DEGRADED}
     */
    public record Subsystem(String name, boolean required) {
        public Subsystem {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("subsystem name must not be null or blank");
            }
        }

        /** A required subsystem (must be UP under {@link ReadinessPolicy#MINIMUM_VIABLE}). */
        public static Subsystem required(String name) {
            return new Subsystem(name, true);
        }

        /** An optional subsystem (degraded/down never fails readiness). */
        public static Subsystem optional(String name) {
            return new Subsystem(name, false);
        }
    }

    /** @return the {@code named(...)} value of the readiness response (the service name). */
    protected abstract String serviceName();

    /** @return the ordered catalogue of subsystems to render and evaluate. */
    protected abstract List<Subsystem> subsystems();

    /** @return how subsystem statuses roll up into the overall verdict. */
    protected abstract ReadinessPolicy policy();

    /** @return the registry this check projects; supplied by the subclass (typically injected). */
    protected abstract DegradedSubsystemRegistry registry();

    /**
     * Hook called at the very start of {@link #call()}, before the registry is
     * read. A subsystem whose status is computed on demand (rather than pushed
     * by a separate probe) reports it here so the snapshot the response renders
     * is current. Default: no-op.
     */
    protected void refresh() {
        // no-op by default
    }

    /**
     * Hook for a subclass to add extra response data (e.g. an aggregate
     * {@code mode} entry). Called after each subsystem has been rendered and
     * before the overall verdict is applied. Default: no-op.
     *
     * @param builder the in-flight response builder
     */
    protected void decorate(HealthCheckResponseBuilder builder) {
        // no-op by default
    }

    @Override
    public final HealthCheckResponse call() {
        refresh();
        DegradedSubsystemRegistry registry = Objects.requireNonNull(registry(), "registry() must not be null");
        HealthCheckResponseBuilder builder = HealthCheckResponse.named(serviceName());

        boolean overallUp = true;
        for (Subsystem subsystem : subsystems()) {
            SubsystemStatus status = registry.statusOf(subsystem.name());
            builder.withData(subsystem.name(), status.name());
            if (policy() == ReadinessPolicy.MINIMUM_VIABLE
                    && subsystem.required()
                    && status != SubsystemStatus.UP) {
                overallUp = false;
            }
        }

        decorate(builder);
        return builder.status(overallUp).build();
    }
}
