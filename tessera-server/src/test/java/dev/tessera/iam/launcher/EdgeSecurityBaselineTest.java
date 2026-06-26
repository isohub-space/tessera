package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * End-to-end edge security baseline (RFC 9700 §2): every response carries the strict
 * security-header set, and CORS denies by default. Asserted against the always-on sample
 * resource so the checks are independent of any one protocol endpoint. HSTS is verified
 * absent here because it is emitted only when served over TLS (production profile).
 */
@QuarkusTest
@DisplayName("Edge security baseline — headers + CORS deny-by-default")
class EdgeSecurityBaselineTest {

    private static final String ENDPOINT = "/api/v1/items";

    @Test
    @DisplayName("every response carries the strict security-header baseline")
    void securityHeadersPresent() {
        given()
                .when()
                .get(ENDPOINT)
                .then()
                .statusCode(200)
                .header("X-Content-Type-Options", equalTo("nosniff"))
                .header("X-Frame-Options", equalTo("DENY"))
                .header("Referrer-Policy", equalTo("no-referrer"))
                .header("Content-Security-Policy", containsString("default-src 'none'"));
    }

    @Test
    @DisplayName("HSTS is not emitted over plain HTTP (enabled only in prod)")
    void noHstsOutsideProd() {
        given()
                .when()
                .get(ENDPOINT)
                .then()
                .statusCode(200)
                .header("Strict-Transport-Security", nullValue());
    }

    @Test
    @DisplayName("CORS denies an unlisted origin (deny-by-default → 403)")
    void corsDeniesUnlistedOrigin() {
        given()
                .header("Origin", "https://evil.example")
                .when()
                .get(ENDPOINT)
                .then()
                .statusCode(403);
    }
}
