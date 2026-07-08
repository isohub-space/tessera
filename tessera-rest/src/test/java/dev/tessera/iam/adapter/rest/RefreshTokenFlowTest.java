package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * End-to-end {@code grant_type=refresh_token} flow over HTTP (Docker-free, in-memory store): an
 * {@code offline_access} authorization-code exchange issues a refresh token, which rotates on
 * redemption; replaying a superseded token is {@code invalid_grant} and burns the family; and a
 * cross-tenant presentation is refused.
 */
@QuarkusTest
@DisplayName("grant_type=refresh_token — rotation, replay detection, cross-tenant")
class RefreshTokenFlowTest {

    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final String CLIENT = FakeClientRepository.REFRESH_CLIENT_ID;
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Test
    @DisplayName("authorize -> token issues a refresh token that rotates on each redemption")
    void fullRoundTrip() {
        String tenant = UUID.randomUUID().toString();
        String refresh1 = initialRefreshToken(tenant);

        Response r1 = refresh(tenant, refresh1);
        r1.then().statusCode(200).header("Cache-Control", "no-store");
        String access2 = r1.jsonPath().getString("access_token");
        String refresh2 = r1.jsonPath().getString("refresh_token");
        assertThat(access2).isNotBlank();
        assertThat(refresh2).isNotBlank().isNotEqualTo(refresh1);

        // The newest token rotates again; the just-superseded refresh1 is covered by replayBurnsFamily.
        Response r2 = refresh(tenant, refresh2);
        r2.then().statusCode(200);
        assertThat(r2.jsonPath().getString("refresh_token")).isNotEqualTo(refresh2);
    }

    @Test
    @DisplayName("replaying a superseded refresh token is invalid_grant and burns the whole family")
    void replayBurnsFamily() {
        String tenant = UUID.randomUUID().toString();
        String refresh1 = initialRefreshToken(tenant);

        String refresh2 = refresh(tenant, refresh1).then().statusCode(200)
                .extract().jsonPath().getString("refresh_token");

        // Replay the now-superseded refresh1.
        refresh(tenant, refresh1).then().statusCode(400)
                .body("error", Matchers.equalTo("invalid_grant"));

        // The family is burned: the previously-current refresh2 no longer works either.
        refresh(tenant, refresh2).then().statusCode(400)
                .body("error", Matchers.equalTo("invalid_grant"));
    }

    @Test
    @DisplayName("presenting a refresh token under a different tenant is refused (invalid_grant)")
    void crossTenantIsRejected() {
        String tenantA = UUID.randomUUID().toString();
        String refresh1 = initialRefreshToken(tenantA);

        // Header-independent resolution finds tenant A, but the fail-closed issuance check refuses
        // to mint under tenant B.
        String tenantB = UUID.randomUUID().toString();
        refresh(tenantB, refresh1).then().statusCode(400)
                .body("error", Matchers.equalTo("invalid_grant"));
    }

    // --------------------------------------------------------------------- helpers

    /** Runs authorize -> token with {@code offline_access} and returns the issued refresh token. */
    private String initialRefreshToken(String tenant) {
        String verifier = newVerifier();
        String code = authorizeCode(tenant, verifier);
        Response token = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", CLIENT)
                .formParam("code_verifier", verifier)
                .when().post("/token");
        token.then().statusCode(200);
        String refresh = token.jsonPath().getString("refresh_token");
        assertThat(refresh).as("initial refresh token").isNotBlank();
        return refresh;
    }

    private String authorizeCode(String tenant, String verifier) {
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                // The refresh family anchors on a UUID subject (see TokenService), as a real
                // deployment's OIDC subject is a user UUID.
                .header("X-Subject-Id", UUID.randomUUID().toString())
                .queryParam("response_type", "code")
                .queryParam("client_id", CLIENT)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid offline_access")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("nonce", "no-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        authorize.then().statusCode(302);
        String query = URI.create(authorize.getHeader("Location")).getQuery();
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if ("code".equals(pair.substring(0, eq))) {
                return java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        throw new IllegalStateException("no code in redirect: " + query);
    }

    private Response refresh(String tenant, String refreshToken) {
        return given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("client_id", CLIENT)
                .when().post("/token");
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }

    private static String newVerifier() {
        byte[] bytes = new byte[48];
        new java.security.SecureRandom().nextBytes(bytes);
        return B64URL.encodeToString(bytes);
    }

    private static String s256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return B64URL.encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
