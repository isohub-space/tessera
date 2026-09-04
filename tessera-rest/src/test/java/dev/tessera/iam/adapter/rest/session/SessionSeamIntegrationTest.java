package dev.tessera.iam.adapter.rest.session;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakePasswordCredentialVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the login/authorize seam integration end to end: a session established at
 * {@code POST /login} is what {@link SessionCookieFilter} translates into the
 * {@code X-Subject-Id} header {@code /authorize} has always read — with NO change to
 * {@code AuthorizeResource} or {@code AuthorizeUseCase} — so a caller who never sets
 * {@code X-Subject-Id} directly, only the session cookie the login response set, still
 * completes the Authorization Code + PKCE flow.
 */
@QuarkusTest
@DisplayName("Login → session cookie → /authorize (the X-Subject-Id seam, filled rather than redesigned)")
class SessionSeamIntegrationTest {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Test
    @DisplayName("a session cookie from /login lets /authorize issue a code with NO X-Subject-Id header")
    void sessionCookieFillsSubjectSeam() throws Exception {
        String tenant = UUID.randomUUID().toString();

        Response login = given().header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("username", FakePasswordCredentialVerifier.USERNAME)
                .formParam("password", FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .when().post("/login");
        login.then().statusCode(204);
        String sessionCookie = login.getCookie(SessionCookies.NAME);
        assertThat(sessionCookie).isNotBlank();

        String verifier = newVerifier();
        String challenge = s256(verifier);

        // Deliberately NO X-Subject-Id header — only the cookie the login response set.
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .cookie(SessionCookies.NAME, sessionCookie)
                .queryParam("response_type", "code")
                .queryParam("client_id", FakeClientRepository.PUBLIC_CLIENT_ID)
                .queryParam("redirect_uri", FakeClientRepository.REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "state-seam")
                .queryParam("nonce", "nonce-seam")
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");

        authorize.then().statusCode(302);
        assertThat(authorize.getHeader("Location")).contains("code=");
    }

    @Test
    @DisplayName("a stale/unknown session cookie does NOT fill the seam — authorize still refuses")
    void unknownSessionCookieDoesNotAuthenticate() {
        String tenant = UUID.randomUUID().toString();

        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .cookie(SessionCookies.NAME, UUID.randomUUID().toString())
                .queryParam("response_type", "code")
                .queryParam("client_id", FakeClientRepository.PUBLIC_CLIENT_ID)
                .queryParam("redirect_uri", FakeClientRepository.REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "state-seam-2")
                .queryParam("nonce", "nonce-seam-2")
                .queryParam("code_challenge", s256(newVerifier()))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");

        authorize.then().statusCode(400).body("error", org.hamcrest.Matchers.equalTo("access_denied"));
    }

    private static String newVerifier() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
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

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }
}
