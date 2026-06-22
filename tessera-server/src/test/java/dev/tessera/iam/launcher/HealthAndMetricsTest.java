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
}
