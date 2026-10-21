package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Positive counterpart to the deny-by-default checks in {@link EdgeSecurityBaselineTest}: with a
 * configured allow-list, a request from a listed origin is allowed and the origin is echoed in
 * {@code Access-Control-Allow-Origin}. This guards the {@code TESSERA_CORS_ORIGINS} wiring against a
 * silent regression where a typo (or a broken property binding) would deny every cross-origin call.
 *
 * <p>The same allow-list must never open the authorization endpoint (RFC 9700 §2.6): with the
 * origin configured, {@code /authorize} answers no preflight or request with an allow-origin, while
 * the endpoints a browser client legitimately calls cross-origin keep the configured policy.
 */
@QuarkusTest
@TestProfile(CorsAllowedOriginTest.AllowedOriginProfile.class)
@DisplayName("Edge security baseline — CORS allows a configured origin")
class CorsAllowedOriginTest {

    // /q/health: an always-on, tenant-unscoped route, so CORS/edge behaviour is isolated
    // from any protocol endpoint's own X-Tenant-Id requirement. Health/metrics routes still
    // go through the same global Vert.x HTTP CORS/security-header policy as every other route.
    private static final String ENDPOINT = "/q/health";
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

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
        "/token", "/introspect", "/revoke", "/.well-known/openid-configuration", "/jwks",
        "/.well-known/jwks.json"
    })
    @DisplayName("a listed-origin preflight to a cross-origin endpoint keeps the configured policy")
    void corsPreflightAllowsListedOriginOnProtocolEndpoints(String path) {
        given()
                .header("Origin", ALLOWED_ORIGIN)
                .header("Access-Control-Request-Method", "POST")
                .when()
                .options(path)
                .then()
                .statusCode(200)
                .header("Access-Control-Allow-Origin", equalTo(ALLOWED_ORIGIN));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"/authorize", "/authorize/", "/authorize;x=1", "/authorize;x=1/"})
    @DisplayName("a listed-origin preflight to /authorize gets no allow-origin (RFC 9700 §2.6)")
    void corsPreflightNeverOpensAuthorize(String path) {
        given()
                .urlEncodingEnabled(false)
                .header("Origin", ALLOWED_ORIGIN)
                .header("Access-Control-Request-Method", "GET")
                .when()
                .options(path)
                .then()
                .header("Access-Control-Allow-Origin", nullValue())
                .header("Access-Control-Allow-Credentials", nullValue())
                .header("Access-Control-Allow-Methods", nullValue());
    }

    // A matrix parameter is stripped before routing, so /authorize;x=1 reaches the endpoint
    // itself: the request is routed (not a 404) and still gets no allow-origin.
    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"/authorize", "/authorize/", "/authorize;x=1", "/authorize;x=1/"})
    @DisplayName("a listed-origin request to /authorize gets no allow-origin (RFC 9700 §2.6)")
    void corsRequestNeverOpensAuthorize(String path) {
        given()
                .urlEncodingEnabled(false)
                .header("Origin", ALLOWED_ORIGIN)
                .when()
                .get(path)
                .then()
                .statusCode(not(404))
                .header("Access-Control-Allow-Origin", nullValue())
                .header("Access-Control-Allow-Credentials", nullValue());
    }
}
