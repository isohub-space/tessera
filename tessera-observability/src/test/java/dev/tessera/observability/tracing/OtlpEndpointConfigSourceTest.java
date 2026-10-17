package dev.tessera.observability.tracing;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OtlpEndpointConfigSource — tracing is on only when an OTLP endpoint is configured")
class OtlpEndpointConfigSourceTest {

    @Test
    @DisplayName("no endpoint anywhere disables the SDK")
    void noEndpointDisables() {
        OtlpEndpointConfigSource source = new OtlpEndpointConfigSource(Map.of(), Map.of());
        assertThat(source.getValue(OtlpEndpointConfigSource.SDK_DISABLED)).isEqualTo("true");
    }

    @Test
    @DisplayName("a blank endpoint counts as none")
    void blankEndpointDisables() {
        OtlpEndpointConfigSource source = new OtlpEndpointConfigSource(
                Map.of("OTEL_EXPORTER_OTLP_ENDPOINT", " "), Map.of());
        assertThat(source.getValue(OtlpEndpointConfigSource.SDK_DISABLED)).isEqualTo("true");
    }

    @Test
    @DisplayName("an endpoint in the environment or a system property leaves the SDK alone")
    void endpointLeavesItOn() {
        assertThat(new OtlpEndpointConfigSource(
                Map.of("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317"), Map.of())
                .getPropertyNames()).isEmpty();
        assertThat(new OtlpEndpointConfigSource(
                Map.of(), Map.of("quarkus.otel.exporter.otlp.traces.endpoint", "http://collector:4317"))
                .getPropertyNames()).isEmpty();
    }

    @Test
    @DisplayName("it ranks below application.properties and the environment")
    void ranksBelowUserSources() {
        assertThat(new OtlpEndpointConfigSource(Map.of(), Map.of()).getOrdinal())
                .isLessThan(250).isGreaterThan(100);
    }
}
