package dev.tessera.iam.launcher.observability;

import static org.junit.jupiter.api.Assertions.assertEquals;

import dev.tessera.observability.metrics.IamMetrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Verifies the composition-root {@link MicrometerRateLimitMetrics} emits the expected {@code iam.*}
 * counters, names, and bounded tags against a real {@link IamMetrics}/{@link SimpleMeterRegistry} —
 * no server boot required.
 */
@DisplayName("MicrometerRateLimitMetrics — bounded-cardinality iam.* counters")
class MicrometerRateLimitMetricsTest {

    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final MicrometerRateLimitMetrics metrics =
            new MicrometerRateLimitMetrics(new IamMetrics(registry));

    @Test
    @DisplayName("ingressThrottled increments iam.ratelimit.throttled tagged by surface + tenant")
    void ingressThrottled() {
        UUID tenant = UUID.fromString("00000000-0000-0000-0000-000000000001");
        metrics.ingressThrottled("TOKEN", tenant);
        metrics.ingressThrottled("TOKEN", tenant);

        double count = registry.get("iam.ratelimit.throttled")
                .tag("surface", "TOKEN").tag("tenant", tenant.toString())
                .counter().count();
        assertEquals(2.0, count);
    }

    @Test
    @DisplayName("a null tenant is rendered as the 'none' tag, never absent")
    void nullTenantIsTagged() {
        metrics.ingressThrottled("AUTHORIZE_IP", null);

        double count = registry.get("iam.ratelimit.throttled")
                .tag("surface", "AUTHORIZE_IP").tag("tenant", "none")
                .counter().count();
        assertEquals(1.0, count);
    }

    @Test
    @DisplayName("trackingTableFull increments iam.ratelimit.table_full (untagged)")
    void trackingTableFull() {
        metrics.trackingTableFull();

        assertEquals(1.0, registry.get("iam.ratelimit.table_full").counter().count());
    }

    @Test
    @DisplayName("credentialThrottled increments iam.credential.throttled tagged by tenant")
    void credentialThrottled() {
        UUID tenant = UUID.fromString("00000000-0000-0000-0000-000000000002");
        metrics.credentialThrottled(tenant);

        double count = registry.get("iam.credential.throttled")
                .tag("tenant", tenant.toString())
                .counter().count();
        assertEquals(1.0, count);
    }
}
