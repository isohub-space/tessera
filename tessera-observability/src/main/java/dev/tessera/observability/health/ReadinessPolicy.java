package dev.tessera.observability.health;

/**
 * How a set of {@link SubsystemStatus} values rolls up into the overall verdict
 * of a readiness probe.
 *
 * <p>The two policies capture the two patterns that existed independently across
 * the platform before this was extracted:</p>
 * <ul>
 *   <li>{@link #UP_WHILE_DEGRADED} — the core HTTP/REST surface is the readiness
 *       contract; optional subsystems only annotate the response and never block
 *       it. This is the TTC posture (SPIKE-S0 §8: "starts degraded — never
 *       crashes").</li>
 *   <li>{@link #MINIMUM_VIABLE} — a declared set of <em>required</em> subsystems
 *       must be {@link SubsystemStatus#UP}; if any required one is
 *       {@link SubsystemStatus#DOWN} the service is not ready. This is the SFD
 *       posture (UP iff Orekit data is loaded).</li>
 * </ul>
 */
public enum ReadinessPolicy {

    /**
     * Overall status is always {@code UP}: degraded or down subsystems are
     * reported in the response data but never fail the probe.
     */
    UP_WHILE_DEGRADED,

    /**
     * Overall status is {@code UP} only while every <em>required</em> subsystem
     * is {@link SubsystemStatus#UP}; a required subsystem reported
     * {@link SubsystemStatus#DOWN} makes the overall status {@code DOWN}.
     * Optional (non-required) subsystems never fail the probe.
     */
    MINIMUM_VIABLE
}
