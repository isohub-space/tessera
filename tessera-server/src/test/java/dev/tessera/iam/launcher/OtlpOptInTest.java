package dev.tessera.iam.launcher;

import static org.assertj.core.api.Assertions.assertThat;

import io.quarkus.test.junit.QuarkusTest;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.ConfigValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The OTLP opt-in is wired into the running application: with no OTLP endpoint configured, the
 * OpenTelemetry SDK is disabled by the observability module's config source factory, not only by the
 * test profile's own default.
 */
@QuarkusTest
@DisplayName("IAM service — tracing is off when no OTLP endpoint is configured")
class OtlpOptInTest {

    @Test
    @DisplayName("quarkus.otel.sdk.disabled comes from the OTLP opt-in source at runtime")
    void sdkDisabledByTheOptInSource() {
        ConfigValue disabled = ConfigProvider.getConfig().getConfigValue("quarkus.otel.sdk.disabled");
        assertThat(disabled.getValue()).isEqualTo("true");
        assertThat(disabled.getSourceName()).contains("tessera-otlp-endpoint");
    }
}
