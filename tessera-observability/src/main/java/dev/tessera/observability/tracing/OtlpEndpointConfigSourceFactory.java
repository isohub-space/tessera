package dev.tessera.observability.tracing;

import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigSourceFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.PropertiesConfigSource;
import java.util.List;
import java.util.Map;
import org.eclipse.microprofile.config.spi.ConfigSource;

/**
 * Turns the OpenTelemetry SDK off when no OTLP endpoint is configured.
 *
 * <p>The OTLP exporter otherwise falls back to {@code localhost:4317}; where no collector listens
 * there, every export attempt fails and logs a connection-refused warning. Tracing is therefore on
 * only when the deployment names an endpoint: {@code OTEL_EXPORTER_OTLP_ENDPOINT},
 * {@code OTEL_EXPORTER_OTLP_TRACES_ENDPOINT}, or {@code quarkus.otel.exporter.otlp[.traces].endpoint}
 * in any user configuration (environment, system properties, {@code application.properties}, a
 * {@code .env} file, a profile, or another configured location).
 *
 * <p>As a factory it reads the configuration the other sources hold, not just the environment.
 * Values at or below ordinal {@value #DEFAULTS_ORDINAL} are library defaults, such as this
 * module's own {@code microprofile-config.properties}, which maps the traces endpoint to
 * {@code OTEL_EXPORTER_OTLP_ENDPOINT} with a {@code localhost} fallback; they do not count as a
 * configured endpoint.
 *
 * <p>The source it adds sits below every user-supplied source (ordinal {@value #ORDINAL}, under
 * {@code application.properties} at 250 and environment variables at 300), so an explicit
 * {@code quarkus.otel.sdk.disabled} anywhere else still wins.
 */
public final class OtlpEndpointConfigSourceFactory implements ConfigSourceFactory {

    static final int ORDINAL = 150;
    static final int DEFAULTS_ORDINAL = 100;
    static final String SDK_DISABLED = "quarkus.otel.sdk.disabled";
    static final String NAME = "tessera-otlp-endpoint";

    private static final List<String> ENDPOINT_KEYS = List.of(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "quarkus.otel.exporter.otlp.endpoint",
            "quarkus.otel.exporter.otlp.traces.endpoint");

    @Override
    public Iterable<ConfigSource> getConfigSources(ConfigSourceContext context) {
        boolean endpointConfigured = ENDPOINT_KEYS.stream().anyMatch(key -> userConfigured(context.getValue(key)));
        return endpointConfigured
                ? List.of()
                : List.of(new PropertiesConfigSource(Map.of(SDK_DISABLED, "true"), NAME, ORDINAL));
    }

    private static boolean userConfigured(ConfigValue value) {
        return value != null
                && value.getValue() != null
                && !value.getValue().isBlank()
                && value.getConfigSourceOrdinal() > DEFAULTS_ORDINAL;
    }
}
