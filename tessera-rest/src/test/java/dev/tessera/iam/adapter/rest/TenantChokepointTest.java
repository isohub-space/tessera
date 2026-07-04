package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code /authorize} and {@code /token} resolve their realm from the request-scoped
 * {@link dev.tessera.iam.adapter.rest.tenancy.TenantContext} bound by the single
 * {@code TenantResolutionFilter} (they no longer parse tenant headers themselves). This
 * proves the chokepoint applies to both endpoints and stays fail-closed: a request with no
 * resolvable tenant is rejected 400 before the handler runs, so no code is issued and no
 * token endpoint logic executes tenant-less.
 */
@QuarkusTest
@DisplayName("Tenant chokepoint — /authorize and /token are fail-closed behind the resolution filter")
class TenantChokepointTest {

    @Test
    @DisplayName("/authorize with no X-Tenant-Id is rejected 400 before issuing a code")
    void authorizeMissingTenantIsRejected() {
        given()
                .config(noFollow())
                .queryParam("response_type", "code")
                .queryParam("client_id", "any")
                .queryParam("redirect_uri", "https://client.example/callback")
                .queryParam("state", "s")
                .queryParam("nonce", "n")
                .header("X-Subject-Id", "user-sub-1")
                .when()
                .get("/authorize")
                .then()
                .statusCode(400)
                .contentType(containsString("problem+json"))
                .body("detail", containsString("X-Tenant-Id"));
    }

    @Test
    @DisplayName("/authorize with a malformed X-Tenant-Id is rejected 400")
    void authorizeMalformedTenantIsRejected() {
        given()
                .config(noFollow())
                .header("X-Tenant-Id", "not-a-uuid")
                .queryParam("response_type", "code")
                .queryParam("client_id", "any")
                .queryParam("redirect_uri", "https://client.example/callback")
                .queryParam("state", "s")
                .queryParam("nonce", "n")
                .header("X-Subject-Id", "user-sub-1")
                .when()
                .get("/authorize")
                .then()
                .statusCode(400)
                .contentType(containsString("problem+json"));
    }

    @Test
    @DisplayName("/token with no X-Tenant-Id is rejected 400 before any grant processing")
    void tokenMissingTenantIsRejected() {
        given()
                .config(noFollow())
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", "x")
                .formParam("redirect_uri", "https://client.example/callback")
                .formParam("client_id", "any")
                .formParam("code_verifier", UUID.randomUUID().toString())
                .when()
                .post("/token")
                .then()
                .statusCode(400)
                .contentType(containsString("problem+json"));
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }
}
