package dev.tessera.observability.health;

import jakarta.enterprise.context.ApplicationScoped;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import org.jboss.logging.Logger;

/**
 * Shared, thread-safe registry of a service's <em>optional</em> backend
 * subsystems so the service can start <strong>degraded</strong> rather than
 * crash when one is missing.
 *
 * <p>A subsystem is identified by a free-form name (e.g. {@code "kafka"},
 * {@code "database"}); the owning service declares its catalogue by
 * {@linkplain #register(String, SubsystemStatus) registering} each name once at
 * startup, then flips statuses as its probes observe the world. An
 * {@link AbstractReadinessCheck} projects the registry into
 * {@code GET /q/health/ready}.</p>
 *
 * <p>Application-scoped. A transition
 * <em>into</em> {@link SubsystemStatus#DEGRADED} or {@link SubsystemStatus#DOWN}
 * is logged at WARN via JBoss logging so the degraded start is visible in the
 * operator log without failing the boot.</p>
 */
@ApplicationScoped
public class DegradedSubsystemRegistry {

    private static final Logger LOG = Logger.getLogger(DegradedSubsystemRegistry.class);

    private final Map<String, SubsystemStatus> statuses = new ConcurrentHashMap<>();

    /**
     * Declares an optional subsystem with an initial status. Typically called
     * once per subsystem at startup; the conventional fail-soft default is
     * {@link SubsystemStatus#DEGRADED} until a probe proves it
     * {@link SubsystemStatus#UP}. Re-registering an existing name simply updates
     * it (equivalent to {@link #report(String, SubsystemStatus)}).
     *
     * @param subsystem the subsystem name; must not be {@code null} or blank
     * @param initial   its initial status; must not be {@code null}
     */
    public void register(String subsystem, SubsystemStatus initial) {
        report(subsystem, initial);
    }

    /**
     * Records the current status of a subsystem. A transition into
     * {@link SubsystemStatus#DEGRADED} or {@link SubsystemStatus#DOWN} is logged
     * at WARN so the change is visible to operators; an unchanged status is not
     * re-logged.
     *
     * @param subsystem the subsystem name; must not be {@code null} or blank
     * @param status    its observed status; must not be {@code null}
     */
    public void report(String subsystem, SubsystemStatus status) {
        if (subsystem == null || subsystem.isBlank()) {
            throw new IllegalArgumentException("subsystem name must not be null or blank");
        }
        Objects.requireNonNull(status, "status must not be null");
        SubsystemStatus previous = statuses.put(subsystem, status);
        if (status != SubsystemStatus.UP && status != previous) {
            LOG.warnf("Subsystem %s is %s — service continues; readiness reflects this", subsystem, status);
        }
    }

    /**
     * @param subsystem the subsystem to query
     * @return its last reported status, or {@link SubsystemStatus#DEGRADED} if it
     *         was never registered (fail-soft default)
     */
    public SubsystemStatus statusOf(String subsystem) {
        return statuses.getOrDefault(subsystem, SubsystemStatus.DEGRADED);
    }

    /** @return {@code true} if every registered subsystem is {@link SubsystemStatus#UP}. */
    public boolean allUp() {
        return statuses.values().stream().allMatch(s -> s == SubsystemStatus.UP);
    }

    /** @return an immutable snapshot of every registered subsystem's status. */
    public Map<String, SubsystemStatus> snapshot() {
        return Map.copyOf(statuses);
    }
}
