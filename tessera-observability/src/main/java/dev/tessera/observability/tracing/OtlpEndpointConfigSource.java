package dev.tessera.observability.tracing;

import java.util.Map;
import java.util.Set;
import org.eclipse.microprofile.config.spi.ConfigSource;

/**
 * Turns the OpenTelemetry SDK off when no OTLP endpoint is configured.
 *
 * <p>The OTLP exporter otherwise falls back to {@code localhost:4317}; where no collector listens
 * there, every export attempt fails and logs a connection-refused warning. Tracing is therefore
 * on only when the deployment names an endpoint ({@code OTEL_EXPORTER_OTLP_ENDPOINT}, or the
 * {@code quarkus.otel.exporter.otlp[.traces].endpoint} properties).
 *
 * <p>This source sits below every user-supplied source (ordinal {@value #ORDINAL}, under
 * {@code application.properties} at 250 and environment variables at 300), so an explicit
 * {@code quarkus.otel.sdk.disabled} anywhere else still wins.
 */
public final class OtlpEndpointConfigSource implements ConfigSource {

    static final int ORDINAL = 150;
    static final String SDK_DISABLED = "quarkus.otel.sdk.disabled";

    private static final Set<String> ENDPOINT_KEYS = Set.of(
            "OTEL_EXPORTER_OTLP_ENDPOINT",
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "QUARKUS_OTEL_EXPORTER_OTLP_ENDPOINT",
            "QUARKUS_OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
            "quarkus.otel.exporter.otlp.endpoint",
            "quarkus.otel.exporter.otlp.traces.endpoint");

    private final Map<String, String> properties;

    /** The source the configuration loads, reading the process environment and system properties. */
    public OtlpEndpointConfigSource() {
        this(System.getenv(), System.getProperties());
    }

    OtlpEndpointConfigSource(Map<String, String> env, Map<Object, Object> systemProperties) {
        boolean endpointConfigured = ENDPOINT_KEYS.stream().anyMatch(key ->
                notBlank(env.get(key)) || notBlank(systemProperties.get(key)));
        this.properties = endpointConfigured ? Map.of() : Map.of(SDK_DISABLED, "true");
    }

    private static boolean notBlank(Object value) {
        return value != null && !value.toString().isBlank();
    }

    @Override
    public Map<String, String> getProperties() {
        return properties;
    }

    @Override
    public Set<String> getPropertyNames() {
        return properties.keySet();
    }

    @Override
    public String getValue(String propertyName) {
        return properties.get(propertyName);
    }

    @Override
    public String getName() {
        return "tessera-otlp-endpoint";
    }

    @Override
    public int getOrdinal() {
        return ORDINAL;
    }
}
