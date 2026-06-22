package dev.tessera.observability.health;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code @QuarkusTest} exercising {@link AbstractReadinessCheck} end-to-end at
 * {@code GET /q/health/ready} under BOTH policies:
 * {@link UpWhileDegradedTestCheck} (UP_WHILE_DEGRADED) and
 * {@link MinimumViableTestCheck} (MINIMUM_VIABLE). Per-check statuses are read
 * from the SmallRye Health JSON so each policy is asserted independently of the
 * AND-ed overall verdict.
 */
@QuarkusTest
@DisplayName("AbstractReadinessCheck — both readiness policies over /q/health/ready")
class AbstractReadinessCheckQuarkusTest {

    @AfterEach
    void clearOverride() {
        System.clearProperty(MinimumViableTestCheck.OREKIT_UP_PROPERTY);
    }

    @Test
    @DisplayName("UP_WHILE_DEGRADED: overall UP even with a degraded subsystem; mode=DEGRADED")
    void upWhileDegradedStaysUp() {
        given().when().get("/q/health/ready").then()
                .statusCode(200)
                .body("checks.find { it.name == 'test-up-while-degraded' }.status", equalTo("UP"))
                .body("checks.find { it.name == 'test-up-while-degraded' }.data.kafka", equalTo("DEGRADED"))
                .body("checks.find { it.name == 'test-up-while-degraded' }.data.object_store", equalTo("UP"))
                .body("checks.find { it.name == 'test-up-while-degraded' }.data.mode", equalTo("DEGRADED"));
    }

    @Test
    @DisplayName("MINIMUM_VIABLE: required subsystem UP → check UP")
    void minimumViableUpWhenRequiredUp() {
        System.setProperty(MinimumViableTestCheck.OREKIT_UP_PROPERTY, "true");
        given().when().get("/q/health/ready").then()
                // required orekit UP → the whole endpoint can be 200 (both checks UP)
                .statusCode(200)
                .body("checks.find { it.name == 'test-minimum-viable' }.status", equalTo("UP"))
                .body("checks.find { it.name == 'test-minimum-viable' }.data.orekit", equalTo("UP"))
                .body("checks.find { it.name == 'test-minimum-viable' }.data.gpu", equalTo("DEGRADED"));
    }

    @Test
    @DisplayName("MINIMUM_VIABLE: required subsystem DOWN → check DOWN (overall 503)")
    void minimumViableDownWhenRequiredDown() {
        System.setProperty(MinimumViableTestCheck.OREKIT_UP_PROPERTY, "false");
        given().when().get("/q/health/ready").then()
                // a DOWN readiness check makes the aggregate endpoint 503
                .statusCode(503)
                .body("checks.find { it.name == 'test-minimum-viable' }.status", equalTo("DOWN"))
                .body("checks.find { it.name == 'test-minimum-viable' }.data.orekit", equalTo("DOWN"))
                // optional degraded subsystem alone never fails the check
                .body("checks.find { it.name == 'test-up-while-degraded' }.status", equalTo("UP"));
    }
}
