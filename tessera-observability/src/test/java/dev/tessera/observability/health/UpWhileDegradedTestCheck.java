package dev.tessera.observability.health;

import jakarta.enterprise.context.ApplicationScoped;
import java.util.List;
import org.eclipse.microprofile.health.HealthCheckResponseBuilder;
import org.eclipse.microprofile.health.Readiness;

/**
 * Test subclass exercising {@link ReadinessPolicy#UP_WHILE_DEGRADED}: it owns its
 * own registry (so the two policy test checks do not share state) seeded with one
 * degraded subsystem, and adds an aggregate {@code mode} data entry the way TTC
 * does. Overall must stay UP despite the degraded subsystem.
 */
@Readiness
@ApplicationScoped
class UpWhileDegradedTestCheck extends AbstractReadinessCheck {

    private final DegradedSubsystemRegistry registry = new DegradedSubsystemRegistry();

    UpWhileDegradedTestCheck() {
        registry.register("kafka", SubsystemStatus.DEGRADED);
        registry.register("object_store", SubsystemStatus.UP);
    }

    @Override
    protected String serviceName() {
        return "test-up-while-degraded";
    }

    @Override
    protected List<Subsystem> subsystems() {
        return List.of(Subsystem.optional("kafka"), Subsystem.optional("object_store"));
    }

    @Override
    protected ReadinessPolicy policy() {
        return ReadinessPolicy.UP_WHILE_DEGRADED;
    }

    @Override
    protected DegradedSubsystemRegistry registry() {
        return registry;
    }

    @Override
    protected void decorate(HealthCheckResponseBuilder builder) {
        builder.withData("mode", registry.allUp() ? "FULL" : "DEGRADED");
    }
}
