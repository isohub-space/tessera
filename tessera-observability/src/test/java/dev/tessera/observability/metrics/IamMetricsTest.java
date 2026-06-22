package dev.tessera.observability.metrics;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the {@code iam.<subsystem>.<metric>} naming convention and that meter
 * creation is idempotent.
 */
@DisplayName("IamMetrics — naming convention & meter factory")
class IamMetricsTest {

    @Test
    @DisplayName("name() composes iam.<subsystem>.<metric>")
    void nameComposes() {
        assertThat(IamMetrics.name("token", "issued")).isEqualTo("iam.token.issued");
        assertThat(IamMetrics.name("authorize", "requests")).isEqualTo("iam.authorize.requests");
    }

    @Test
    @DisplayName("a segment containing a dot is rejected so the convention stays two-level")
    void dottedSegmentRejected() {
        assertThatThrownBy(() -> IamMetrics.name("token.sub", "issued"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> IamMetrics.name("token", ""))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("increment registers and bumps the named counter; repeated calls reuse it")
    void incrementIsIdempotentlyRegistered() {
        SimpleMeterRegistry registry = new SimpleMeterRegistry();
        IamMetrics metrics = new IamMetrics(registry);

        metrics.increment("token", "issued", "grant", "authorization_code");
        metrics.increment("token", "issued", "grant", "authorization_code");

        assertThat(registry.get("iam.token.issued").tags("grant", "authorization_code")
                .counter().count()).isEqualTo(2.0);
        // No duplicate meter was created for the same name+tags.
        assertThat(registry.getMeters().stream()
                .filter(m -> m.getId().getName().equals("iam.token.issued")).count()).isEqualTo(1L);
    }
}
