package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Positive counterpart to the deny-by-default checks in {@link EdgeSecurityBaselineTest}: with a
 * configured allow-list, a request from a listed origin is allowed and the origin is echoed in
 * {@code Access-Control-Allow-Origin}. This guards the {@code TESSERA_CORS_ORIGINS} wiring against a
 * silent regression where a typo (or a broken property binding) would deny every cross-origin call.
 */
@QuarkusTest
@TestProfile(CorsAllowedOriginTest.AllowedOriginProfile.class)
@DisplayName("Edge security baseline — CORS allows a configured origin")
class CorsAllowedOriginTest {

    private static final String ENDPOINT = "/api/v1/items";
    private static final String ALLOWED_ORIGIN = "https://app.example";

    public static class AllowedOriginProfile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("quarkus.http.cors.origins", ALLOWED_ORIGIN);
        }
    }

    @Test
    @DisplayName("a listed origin is echoed in Access-Control-Allow-Origin")
    void corsAllowsListedOrigin() {
        given()
                .header("Origin", ALLOWED_ORIGIN)
                .when()
                .get(ENDPOINT)
                .then()
                .statusCode(200)
                .header("Access-Control-Allow-Origin", equalTo(ALLOWED_ORIGIN));
    }
}
