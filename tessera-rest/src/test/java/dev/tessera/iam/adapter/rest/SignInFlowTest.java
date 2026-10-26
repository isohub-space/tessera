// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;

import dev.tessera.iam.adapter.rest.session.SessionCookies;
import dev.tessera.iam.adapter.rest.signin.SignInCookies;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakePasswordCredentialVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import java.net.URI;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The hosted sign-in page end to end: {@code /authorize} with no signed-in user → {@code 303}
 * to {@code /signin} with the binding cookie → the form → a same-origin post → {@code 303} to
 * the client's redirect URI with a code → a DPoP-bound token for the PKCE verifier.
 */
@QuarkusTest
@DisplayName("Hosted sign-in — /authorize → /signin → code → DPoP-bound token")
class SignInFlowTest extends AuthorizationCodeFlowSupport {

    private static final Pattern CSRF = Pattern.compile("name=\"csrf\" value=\"([^\"]+)\"");

    /** What a browser holds after {@code /authorize} sent it to sign in. */
    private record Started(String transactionId, String binding, String verifier, String state) {
    }

    private Started start(String state) {
        String verifier = newVerifier();
        Response authorize = authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid",
                state, null, s256(verifier), "S256", null);
        authorize.then().statusCode(303).header("Cache-Control", "no-store");
        URI location = URI.create(authorize.getHeader("Location"));
        assertThat(location.getPath()).isEqualTo("/signin");
        String txn = queryOf(location.toString()).get("txn");
        String binding = authorize.getCookie(SignInCookies.NAME);
        assertThat(txn).isNotBlank();
        assertThat(binding).isNotBlank();
        return new Started(txn, binding, verifier, state);
    }

    private Response page(Started started) {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .cookie(SignInCookies.NAME, started.binding())
                .queryParam("txn", started.transactionId())
                .when().get("/signin");
    }

    private static String csrfOf(Response page) {
        Matcher m = CSRF.matcher(page.asString());
        assertThat(m.find()).as("the form carries a synchronizer token").isTrue();
        return m.group(1);
    }

    private Response post(Started started, String binding, String csrf, String fetchSite,
            String username, String password) {
        var req = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("txn", started.transactionId())
                .formParam("username", username)
                .formParam("password", password);
        if (binding != null) {
            req.cookie(SignInCookies.NAME, binding);
        }
        if (csrf != null) {
            req.formParam("csrf", csrf);
        }
        if (fetchSite != null) {
            req.header("Sec-Fetch-Site", fetchSite);
        }
        return req.when().post("/signin");
    }

    private Response signIn(Started started, String csrf) {
        return post(started, started.binding(), csrf, "same-origin",
                FakePasswordCredentialVerifier.USERNAME, FakePasswordCredentialVerifier.CORRECT_PASSWORD);
    }

    @Test
    @DisplayName("the whole flow: sign in on tessera's page, return with a code, redeem it with PKCE + DPoP")
    void signInThenRedeem() {
        Started started = start("state-flow");
        Response page = page(started);
        page.then().statusCode(200)
                .contentType(containsString("text/html"))
                .header("Cache-Control", "no-store")
                .body(containsString("name=\"txn\" value=\"" + started.transactionId() + "\""));

        Response signedIn = signIn(started, csrfOf(page));

        signedIn.then().statusCode(303);
        Map<String, String> query = queryOf(signedIn.getHeader("Location"));
        assertThat(signedIn.getHeader("Location")).startsWith(REDIRECT_URI + "?");
        assertThat(query).containsEntry("state", "state-flow").containsEntry("iss", ISSUER);
        assertThat(signedIn.getCookie(SessionCookies.NAME)).isNotBlank();
        assertThat(signedIn.getDetailedCookie(SignInCookies.NAME).getMaxAge()).isZero();

        tokenWithDpop(FakeClientRepository.PUBLIC_CLIENT_ID, query.get("code"), REDIRECT_URI,
                started.verifier(), dpop.proof(TOKEN_ENDPOINT))
                .then().statusCode(200)
                .body("token_type", equalTo("DPoP"));
    }

    @Test
    @DisplayName("the binding cookie is HttpOnly, Secure, SameSite=Lax and scoped to the sign-in page")
    void bindingCookieFlags() {
        Response authorize = authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid",
                "state-cookie", null, s256(newVerifier()), "S256", null);
        var cookie = authorize.getDetailedCookie(SignInCookies.NAME);

        assertThat(cookie.isHttpOnly()).isTrue();
        assertThat(cookie.isSecured()).isTrue();
        assertThat(cookie.getPath()).isEqualTo("/signin");
        assertThat(cookie.getMaxAge()).isPositive();
        assertThat(authorize.getHeader("Set-Cookie")).containsIgnoringCase("SameSite=Lax");
    }

    @Test
    @DisplayName("an unknown client or unregistered redirect URI is refused at /authorize, never sent to sign in")
    void validatesBeforeSignIn() {
        authorize("no-such-client", REDIRECT_URI, "openid", "s", null, s256(newVerifier()), "S256", null)
                .then().statusCode(400).body("error", equalTo("invalid_request"))
                .header("Location", org.hamcrest.Matchers.nullValue());
        authorize(FakeClientRepository.PUBLIC_CLIENT_ID, "https://evil.example/cb", "openid", "s", null,
                s256(newVerifier()), "S256", null)
                .then().statusCode(400).body("error", equalTo("invalid_request"))
                .header("Location", org.hamcrest.Matchers.nullValue());
    }

    @Test
    @DisplayName("the form page's policy lets the form post to tessera and end at the client's origin only")
    void formPagePolicy() {
        page(start("state-csp")).then().statusCode(200)
                .header("Content-Security-Policy", containsString("default-src 'none'"))
                .header("Content-Security-Policy", org.hamcrest.Matchers.endsWith("form-action 'self' https://client.example"))
                .header("Content-Security-Policy", containsString("frame-ancestors 'none'"))
                .header("Content-Security-Policy", not(containsString("script-src")));
    }

    @Test
    @DisplayName("the page is not shown without the binding cookie, or with another browser's")
    void pageRequiresBinding() {
        Started started = start("state-binding");

        given().config(noFollow()).header("X-Tenant-Id", TENANT)
                .queryParam("txn", started.transactionId())
                .when().get("/signin")
                .then().statusCode(400)
                .header("Content-Security-Policy", containsString("form-action 'none'"))
                .body(not(containsString("name=\"csrf\"")));
        page(new Started(started.transactionId(), "another-browser", started.verifier(), started.state()))
                .then().statusCode(400);
    }

    @Test
    @DisplayName("a wrong password shows the form again with an error, and the same transaction then succeeds")
    void wrongPasswordThenRetry() {
        Started started = start("state-retry");
        String csrf = csrfOf(page(started));

        Response denied = post(started, started.binding(), csrf, "same-origin",
                FakePasswordCredentialVerifier.USERNAME, "not-the-password");
        denied.then().statusCode(401)
                .contentType(containsString("text/html"))
                .body(containsString("role=\"alert\""))
                .body(not(containsString("not-the-password")));
        assertThat(denied.getCookie(SessionCookies.NAME)).isNull();

        signIn(started, csrfOf(denied)).then().statusCode(303);
    }

    @Test
    @DisplayName("a post without the synchronizer token, with a forged one, or without the binding is refused")
    void csrfAndBindingEnforced() {
        Started started = start("state-csrf");
        String csrf = csrfOf(page(started));
        String user = FakePasswordCredentialVerifier.USERNAME;
        String password = FakePasswordCredentialVerifier.CORRECT_PASSWORD;

        post(started, started.binding(), null, "same-origin", user, password).then().statusCode(400);
        post(started, started.binding(), "forged", "same-origin", user, password).then().statusCode(400);
        post(started, null, csrf, "same-origin", user, password).then().statusCode(400);
        post(started, "another-browser", csrf, "same-origin", user, password).then().statusCode(400);

        // None of those used the transaction up.
        signIn(started, csrf).then().statusCode(303);
    }

    @Test
    @DisplayName("a cross-site post is refused before anything is checked")
    void crossSitePostRefused() {
        Started started = start("state-site");
        String csrf = csrfOf(page(started));

        post(started, started.binding(), csrf, "cross-site", FakePasswordCredentialVerifier.USERNAME,
                FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .then().statusCode(403);
        post(started, started.binding(), csrf, "same-site", FakePasswordCredentialVerifier.USERNAME,
                FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .then().statusCode(403);
        // A browser that sends no Fetch Metadata still gets through on the token.
        post(started, started.binding(), csrf, null, FakePasswordCredentialVerifier.USERNAME,
                FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .then().statusCode(303);
    }

    @Test
    @DisplayName("one sign-in answers the request once: posting the form again is refused")
    void replayRefused() {
        Started started = start("state-replay");
        String csrf = csrfOf(page(started));

        signIn(started, csrf).then().statusCode(303);
        signIn(started, csrf).then().statusCode(400);
        page(started).then().statusCode(400);
    }

    @Test
    @DisplayName("the redirect is the one validated at /authorize, whatever the post adds")
    void injectedRedirectIgnored() {
        Started started = start("state-inject");
        String csrf = csrfOf(page(started));

        Response signedIn = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .header("Sec-Fetch-Site", "same-origin")
                .cookie(SignInCookies.NAME, started.binding())
                .contentType("application/x-www-form-urlencoded")
                .formParam("txn", started.transactionId())
                .formParam("csrf", csrf)
                .formParam("username", FakePasswordCredentialVerifier.USERNAME)
                .formParam("password", FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .formParam("redirect_uri", "https://evil.example/cb")
                .formParam("return_to", "https://evil.example/cb")
                .queryParam("redirect_uri", "https://evil.example/cb")
                .when().post("/signin");

        signedIn.then().statusCode(303);
        assertThat(signedIn.getHeader("Location")).startsWith(REDIRECT_URI + "?");
    }

    @Test
    @DisplayName("a transaction from another tenant is not visible")
    void tenantScoped() {
        Started started = start("state-tenant");

        given().config(noFollow())
                .header("X-Tenant-Id", java.util.UUID.randomUUID().toString())
                .cookie(SignInCookies.NAME, started.binding())
                .queryParam("txn", started.transactionId())
                .when().get("/signin")
                .then().statusCode(400);
    }

    @Test
    @DisplayName("the stylesheet the page links is served")
    void stylesheetServed() {
        given().when().get("/assets/signin.css")
                .then().statusCode(200).contentType(containsString("text/css"));
    }
}
