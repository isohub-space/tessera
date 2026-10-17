package dev.tessera.observability.tracing;

import static org.assertj.core.api.Assertions.assertThat;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;
import java.util.Map;
import java.util.Optional;
import org.eclipse.microprofile.config.spi.ConfigSource;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OtlpEndpointConfigSourceFactory — tracing is on only when an OTLP endpoint is configured")
class OtlpEndpointConfigSourceFactoryTest {

    // What this module's microprofile-config.properties ships, at its ordinal.
    private static final ConfigSource LIBRARY_DEFAULTS = new PropertiesConfigSource(Map.of(
            "quarkus.otel.exporter.otlp.traces.endpoint", "${OTEL_EXPORTER_OTLP_ENDPOINT:http://localhost:4317}"),
            "microprofile-config.properties", 100);

    private static Optional<Boolean> sdkDisabled(String profile, ConfigSource... userSources) {
        SmallRyeConfigBuilder builder = new SmallRyeConfigBuilder()
                .withSources(LIBRARY_DEFAULTS)
                .withSources(userSources)
                .withSources(new OtlpEndpointConfigSourceFactory());
        if (profile != null) {
            builder.withProfile(profile);
        }
        SmallRyeConfig config = builder.build();
        return config.getOptionalValue(OtlpEndpointConfigSourceFactory.SDK_DISABLED, Boolean.class);
    }

    private static ConfigSource source(String name, int ordinal, String key, String value) {
        return new PropertiesConfigSource(Map.of(key, value), name, ordinal);
    }

    @Test
    @DisplayName("no endpoint anywhere, only the library's localhost fallback, disables the SDK")
    void noEndpointDisables() {
        assertThat(sdkDisabled(null)).contains(true);
    }

    @Test
    @DisplayName("a blank endpoint counts as none")
    void blankEndpointDisables() {
        assertThat(sdkDisabled(null, source("env", 300, "OTEL_EXPORTER_OTLP_ENDPOINT", " "))).contains(true);
    }

    @Test
    @DisplayName("an endpoint in the environment leaves the SDK on")
    void environmentEndpoint() {
        assertThat(sdkDisabled(null, source("env", 300, "OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")))
                .isEmpty();
    }

    @Test
    @DisplayName("an endpoint only in application.properties leaves the SDK on")
    void applicationPropertiesEndpoint() {
        assertThat(sdkDisabled(null, source("application.properties", 250,
                "quarkus.otel.exporter.otlp.traces.endpoint", "http://collector:4317"))).isEmpty();
    }

    @Test
    @DisplayName("an endpoint set for the active profile leaves the SDK on; one for another profile does not")
    void profileEndpoint() {
        ConfigSource prodOnly = source("application.properties", 250,
                "%prod.quarkus.otel.exporter.otlp.endpoint", "http://collector:4317");
        assertThat(sdkDisabled("prod", prodOnly)).isEmpty();
        assertThat(sdkDisabled("dev", prodOnly)).contains(true);
    }

    @Test
    @DisplayName("an explicit setting in a user source wins over the factory's default")
    void explicitSettingWins() {
        assertThat(sdkDisabled(null, source("application.properties", 250,
                OtlpEndpointConfigSourceFactory.SDK_DISABLED, "false"))).contains(false);
    }
}
