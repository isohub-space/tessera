package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * End-to-end edge security baseline (RFC 9700 §2): every response carries the strict
 * security-header set, and CORS denies by default. Asserted against the health probe — an
 * always-on, tenant-unscoped route — so the checks are independent of any one protocol
 * endpoint's own {@code X-Tenant-Id} requirement. HSTS is verified absent here because it is
 * emitted only when served over TLS (production profile). The hosted sign-in page is the one
 * path whose Content-Security-Policy is its own.
 */
@QuarkusTest
@DisplayName("Edge security baseline — headers + CORS deny-by-default")
class EdgeSecurityBaselineTest {

    private static final String ENDPOINT = "/q/health";

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
                .header("Content-Security-Policy", containsString("default-src 'none'"))
                .header("Content-Security-Policy", containsString("form-action 'none'"));
    }

    @Test
    @DisplayName("the hosted sign-in page carries its own policy only, never the server-wide one as well")
    void signInPageHasItsOwnPolicyOnly() {
        // Browsers enforce every policy a response carries, so a second, server-wide
        // form-action 'none' would block the page's form.
        var response = given()
                .header("X-Tenant-Id", java.util.UUID.randomUUID().toString())
                .when()
                .get("/signin");
        assertThat(response.getHeaders().getValues("Content-Security-Policy"))
                .singleElement()
                .asString()
                .contains("style-src 'self'");
        response.then()
                .header("X-Frame-Options", equalTo("DENY"))
                .header("X-Content-Type-Options", equalTo("nosniff"));
    }

    @Test
    @DisplayName("the sign-in form's own same-origin post passes CORS (deny-by-default stays for others)")
    void sameOriginSignInPostPassesCors() {
        // A browser sends Origin on a same-origin form post; the deny-by-default CORS policy must
        // not turn the page's own form away. With no binding cookie the page answers 400.
        String self = "http://localhost:" + io.restassured.RestAssured.port;
        given()
                .header("X-Tenant-Id", java.util.UUID.randomUUID().toString())
                .header("Origin", self)
                .header("Sec-Fetch-Site", "same-origin")
                .contentType("application/x-www-form-urlencoded")
                .formParam("txn", "t")
                .formParam("csrf", "c")
                .when()
                .post("/signin")
                .then()
                .statusCode(400);
        given()
                .header("X-Tenant-Id", java.util.UUID.randomUUID().toString())
                .header("Origin", "https://evil.example")
                .contentType("application/x-www-form-urlencoded")
                .formParam("txn", "t")
                .when()
                .post("/signin")
                .then()
                .statusCode(403);
    }

    @Test
    @DisplayName("a path that merely starts with /signin keeps the server-wide policy")
    void signInPrefixKeepsServerPolicy() {
        given()
                .when()
                .get("/signin-elsewhere")
                .then()
                .header("Content-Security-Policy", containsString("form-action 'none'"));
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

    @Test
    @DisplayName("CORS rejects an unlisted-origin preflight and echoes no allow-origin")
    void corsPreflightRejectsUnlistedOrigin() {
        given()
                .header("Origin", "https://evil.example")
                .header("Access-Control-Request-Method", "GET")
                .when()
                .options(ENDPOINT)
                .then()
                .statusCode(403)
                .header("Access-Control-Allow-Origin", nullValue());
    }
}
