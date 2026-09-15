package dev.tessera.iam.adapter.rest.login;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;

import dev.tessera.iam.adapter.rest.session.SessionCookies;
import dev.tessera.iam.adapter.rest.support.FakePasswordCredentialVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code POST /login} — verifies a credential and establishes a session, with the security
 * flags on the resulting cookie pinned down explicitly, not defaulted.
 */
@QuarkusTest
@DisplayName("POST /login — credential verification and session cookie")
class LoginResourceTest {

    private static final String TENANT = UUID.randomUUID().toString();

    @Test
    @DisplayName("a correct credential returns 204 with a session cookie: HttpOnly, Secure, SameSite=Strict")
    void correctCredentialIssuesCookie() {
        Response response = login(FakePasswordCredentialVerifier.USERNAME, FakePasswordCredentialVerifier.CORRECT_PASSWORD);

        response.then().statusCode(204);
        var cookie = response.getDetailedCookie(SessionCookies.NAME);
        assertThat(cookie).isNotNull();
        assertThat(cookie.getValue()).isNotBlank();
        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecured()).isTrue();
        // RestAssured's DetailedCookie does not expose SameSite directly; check the raw header.
        String setCookieHeader = response.getHeader("Set-Cookie");
        assertThat(setCookieHeader).containsIgnoringCase("SameSite=Strict");
    }

    @Test
    @DisplayName("a wrong password is 401 invalid_credentials and sets no cookie")
    void wrongPasswordDenied() {
        Response response = login(FakePasswordCredentialVerifier.USERNAME, "not-the-password");

        response.then().statusCode(401).body("error", equalTo("invalid_credentials"));
        assertThat(response.getDetailedCookie(SessionCookies.NAME)).isNull();
    }

    @Test
    @DisplayName("an unknown username is 401 with the SAME body as a wrong password (no oracle)")
    void unknownUsernameDeniedIdentically() {
        Response unknown = login("nobody", "whatever");
        Response wrongPassword = login(FakePasswordCredentialVerifier.USERNAME, "whatever");

        assertThat(unknown.statusCode()).isEqualTo(wrongPassword.statusCode());
        assertThat(unknown.jsonPath().getString("error"))
                .isEqualTo(wrongPassword.jsonPath().getString("error"));
    }

    @Test
    @DisplayName("a missing password is a 400 invalid_request")
    void missingPasswordIsBadRequest() {
        given().header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("username", "alice")
                .when().post("/login")
                .then().statusCode(400).body("error", equalTo("invalid_request"));
    }

    private static Response login(String username, String password) {
        return given().header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("username", username)
                .formParam("password", password)
                .when().post("/login");
    }
}
