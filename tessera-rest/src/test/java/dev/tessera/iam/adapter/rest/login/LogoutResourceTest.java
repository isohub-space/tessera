package dev.tessera.iam.adapter.rest.login;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.session.SessionCookies;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakePasswordCredentialVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** {@code POST /logout} — ends the session; a logged-out cookie no longer fills the subject seam. */
@QuarkusTest
@DisplayName("POST /logout — ends the session and clears the cookie")
class LogoutResourceTest {

    @Test
    @DisplayName("after logout, the same session cookie no longer authenticates /authorize")
    void logoutInvalidatesTheSessionForAuthorize() {
        String tenant = UUID.randomUUID().toString();

        Response login = given().header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("username", FakePasswordCredentialVerifier.USERNAME)
                .formParam("password", FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .when().post("/login");
        String sessionCookie = login.getCookie(SessionCookies.NAME);

        Response logout = given().header("X-Tenant-Id", tenant)
                .cookie(SessionCookies.NAME, sessionCookie)
                .when().post("/logout");
        logout.then().statusCode(204);
        assertThat(logout.getDetailedCookie(SessionCookies.NAME).getMaxAge()).isEqualTo(0);

        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .cookie(SessionCookies.NAME, sessionCookie)
                .queryParam("response_type", "code")
                .queryParam("client_id", FakeClientRepository.PUBLIC_CLIENT_ID)
                .queryParam("redirect_uri", FakeClientRepository.REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "s")
                .queryParam("nonce", "n")
                .queryParam("code_challenge", "a".repeat(43))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");

        authorize.then().statusCode(400).body("error", org.hamcrest.Matchers.equalTo("access_denied"));
    }

    @Test
    @DisplayName("logout with no session cookie at all still succeeds (idempotent)")
    void logoutWithNoCookieSucceeds() {
        given().header("X-Tenant-Id", UUID.randomUUID().toString())
                .when().post("/logout")
                .then().statusCode(204);
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }
}
