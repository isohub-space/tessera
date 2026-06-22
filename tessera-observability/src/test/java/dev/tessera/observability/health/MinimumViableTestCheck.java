package dev.tessera.observability.health;

import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import org.eclipse.microprofile.health.Readiness;

/**
 * Test subclass exercising {@link ReadinessPolicy#MINIMUM_VIABLE}: a single
 * required subsystem ({@code orekit}, mirroring SFD) plus an optional one. The
 * required subsystem's status is recomputed each call from the
 * {@code test.minviable.orekit-up} system property (default {@code true}) so a
 * single bean can be driven to both verdicts from the Quarkus test.
 */
@Readiness
@ApplicationScoped
class MinimumViableTestCheck extends AbstractReadinessCheck {

    static final String OREKIT_UP_PROPERTY = "test.minviable.orekit-up";

    private final DegradedSubsystemRegistry registry = new DegradedSubsystemRegistry();

    MinimumViableTestCheck() {
        registry.register("orekit", SubsystemStatus.UP);
        registry.register("gpu", SubsystemStatus.DEGRADED);
    }

    @Override
    protected void refresh() {
        boolean orekitUp = Boolean.parseBoolean(System.getProperty(OREKIT_UP_PROPERTY, "true"));
        registry.report("orekit", orekitUp ? SubsystemStatus.UP : SubsystemStatus.DOWN);
    }

    @Override
    protected String serviceName() {
        return "test-minimum-viable";
    }

    @Override
    protected List<Subsystem> subsystems() {
        return List.of(Subsystem.required("orekit"), Subsystem.optional("gpu"));
    }

    @Override
    protected ReadinessPolicy policy() {
        return ReadinessPolicy.MINIMUM_VIABLE;
    }

    @Override
    protected DegradedSubsystemRegistry registry() {
        return registry;
    }
}
