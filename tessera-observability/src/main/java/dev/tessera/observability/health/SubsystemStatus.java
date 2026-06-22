package dev.tessera.observability.health;

/**
 * Availability of an optional backend subsystem tracked by the
 * {@link DegradedSubsystemRegistry}.
 *
 * <p>Three levels let a service distinguish "running without an optional
 * capability" ({@link #DEGRADED}) from "a capability the service cannot operate
 * without is gone" ({@link #DOWN}). How those levels roll up into the overall
 * readiness verdict is the job of the {@link ReadinessPolicy}.</p>
 */
public enum SubsystemStatus {

    /** Subsystem is reachable and operating normally. */
    UP,

    /**
     * Subsystem is unavailable but the service deliberately runs without it
     * (fail-soft). On its own this never fails readiness.
     */
    DEGRADED,

    /**
     * Subsystem is unavailable and considered required. Whether this fails
     * overall readiness depends on the {@link ReadinessPolicy} in force.
     */
    DOWN
}
