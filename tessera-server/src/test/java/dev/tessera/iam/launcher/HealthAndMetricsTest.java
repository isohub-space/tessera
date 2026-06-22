package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * End-to-end {@code @QuarkusTest}: the assembled service boots and exposes the
 * health probes and Prometheus metrics.
 */
@QuarkusTest
@DisplayName("IAM service — startup, health & metrics")
class HealthAndMetricsTest {

    @Test
    @DisplayName("the service boots and the aggregate health is UP")
    void aggregateHealthIsUp() {
        given().when().get("/q/health").then().statusCode(200).body("status", equalTo("UP"));
    }

    @Test
    @DisplayName("liveness probe is UP")
    void livenessIsUp() {
        given().when().get("/q/health/live").then().statusCode(200).body("status", equalTo("UP"));
    }

    @Test
    @DisplayName("Prometheus metrics are exposed at /q/metrics")
    void metricsExposed() {
        given().when().get("/q/metrics").then()
                .statusCode(200)
                .body(is(notNullValue()))
                // JVM binder is enabled, so a baseline JVM metric is present.
                .body(containsString("jvm_"));
    }

    @Test
    @DisplayName("the application iam.server.* metrics are wired through the assembly")
    void applicationServerMetricsExposed() {
        // ServerStartupMetrics records iam.server.started on boot; Prometheus renders
        // the dotted name with underscores.
        given().when().get("/q/metrics").then()
                .statusCode(200)
                .body(containsString("iam_server_started"));
    }

    @Test
    @DisplayName("the iam.key.active gauge is registered through the assembly")
    void keyActiveGaugeExposed() {
        // SigningKeyReadinessCheck registers iam.key.active at @PostConstruct, so the
        // gauge is present even under %test where the readiness probe is config-disabled.
        given().when().get("/q/metrics").then()
                .statusCode(200)
                .body(containsString("iam_key_active"));
    }
}
