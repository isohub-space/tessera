// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;

import dev.tessera.iam.adapter.rest.session.SessionCookies;
import dev.tessera.iam.adapter.rest.signin.SignInCookies;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakePasswordCredentialVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * RP-initiated logout over HTTP ({@code /end_session}, OpenID Connect RP-Initiated Logout 1.0).
 *
 * <p>The refusals come first: each one must answer {@code 400} with no {@code Location}, and must
 * leave the user's session alive, which every refusal test checks by signing in at
 * {@code /authorize} with the same cookie afterwards and getting a code without a password. The
 * end-to-end test then signs a user in on tessera's page, signs them out through the relying
 * party's link, and shows that signing in again asks for the password and that the refresh token
 * no longer refreshes.
 */
@QuarkusTest
@DisplayName("RP-initiated logout — /end_session ends the session, refuses without redirect")
class EndSessionFlowTest extends AuthorizationCodeFlowSupport {

    private static final String CLIENT = FakeClientRepository.REFRESH_CLIENT_ID;
    private static final String POST_LOGOUT = FakeClientRepository.POST_LOGOUT_REDIRECT_URI;
    private static final Pattern CSRF = Pattern.compile("name=\"csrf\" value=\"([^\"]+)\"");

    /** What the relying party and the browser hold after a password sign-in. */
    private record SignedIn(String session, String idToken, String accessToken, String refreshToken) {
    }

    // ------------------------------------------------------------------ refusals

    @Test
    @DisplayName("without id_token_hint: refused, not redirected, session alive")
    void missingHintIsRefused() {
        SignedIn user = signInWithPassword();

        endSession(user.session(), null, null, POST_LOGOUT, "s1")
                .then().statusCode(400)
                .header("Location", nullValue())
                .header("Cache-Control", "no-store")
                .body("error", equalTo("invalid_request"));

        assertSessionAlive(user);
    }

    @Test
    @DisplayName("an unregistered post_logout_redirect_uri, or a near miss, is refused without redirect")
    void unregisteredRedirectIsRefused() {
        SignedIn user = signInWithPassword();

        for (String uri : new String[] {
                "https://evil.example/signed-out",
                POST_LOGOUT + "/",
                POST_LOGOUT + "?next=https://evil.example",
                POST_LOGOUT.toUpperCase(),
                "https://client.example/signed-out#frag",
                "https://client.example.evil.example/signed-out",
                // Registered as the client's login redirect, not as a post-logout one.
                REDIRECT_URI}) {
            endSession(user.session(), user.idToken(), null, uri, "s2")
                    .then().statusCode(400)
                    .header("Location", nullValue())
                    .body("error", equalTo("invalid_request"));
        }

        assertSessionAlive(user);
    }

    @Test
    @DisplayName("a hint for another user than the signed-in one is refused, and ends nothing")
    void hintForAnotherUserIsRefused() {
        SignedIn user = signInWithPassword();
        String otherUsersHint = issueTokens(UUID.randomUUID().toString(), null).idToken();

        endSession(user.session(), otherUsersHint, null, POST_LOGOUT, "s3")
                .then().statusCode(400)
                .header("Location", nullValue());

        assertSessionAlive(user);
        refresh(user.refreshToken()).then().statusCode(200);
    }

    @Test
    @DisplayName("a tampered hint, an access token as hint, or another tenant's hint is refused")
    void invalidHintsAreRefused() {
        SignedIn user = signInWithPassword();
        String[] parts = user.idToken().split("\\.");
        String tampered = parts[0] + "."
                + B64URL.encodeToString(new String(B64URL_DEC.decode(parts[1]), StandardCharsets.UTF_8)
                        .replace(FakePasswordCredentialVerifier.SUBJECT, UUID.randomUUID().toString())
                        .getBytes(StandardCharsets.UTF_8))
                + "." + parts[2];
        String otherTenantsHint = issueTokens(FakePasswordCredentialVerifier.SUBJECT, UUID.randomUUID().toString())
                .idToken();

        for (String hint : new String[] {tampered, user.accessToken(), otherTenantsHint, "not-a-jwt"}) {
            endSession(user.session(), hint, null, POST_LOGOUT, "s4")
                    .then().statusCode(400)
                    .header("Location", nullValue());
        }

        assertSessionAlive(user);
    }

    @Test
    @DisplayName("a client_id that is not the hint's audience is refused")
    void clientIdMismatchIsRefused() {
        SignedIn user = signInWithPassword();

        endSession(user.session(), user.idToken(), FakeClientRepository.PUBLIC_CLIENT_ID, POST_LOGOUT, "s5")
                .then().statusCode(400)
                .header("Location", nullValue());

        assertSessionAlive(user);
    }

    // ------------------------------------------------------------------ acceptance

    @Test
    @DisplayName("sign in, sign out through the relying party, sign in again asks for the password")
    void signOutEndsTheSession() {
        SignedIn user = signInWithPassword();
        assertSessionAlive(user);

        Response out = endSession(user.session(), user.idToken(), CLIENT, POST_LOGOUT, "bye state");

        out.then().statusCode(303).header("Cache-Control", "no-store");
        assertThat(out.getHeader("Location")).isEqualTo(POST_LOGOUT + "?state=bye+state");
        var cleared = out.getDetailedCookie(SessionCookies.NAME);
        assertThat(cleared.getValue()).isEmpty();
        assertThat(cleared.getMaxAge()).isZero();
        assertThat(cleared.isHttpOnly()).isTrue();
        assertThat(cleared.isSecured()).isTrue();
        assertThat(out.getHeader("Set-Cookie")).containsIgnoringCase("SameSite=Strict");

        // A browser that kept the old cookie is not signed in any more: /authorize sends it to
        // the password form instead of issuing a code.
        Response again = authorizeWithSession(user.session());
        again.then().statusCode(303);
        assertThat(URI.create(again.getHeader("Location")).getPath()).isEqualTo("/signin");

        refresh(user.refreshToken()).then().statusCode(400).body("error", equalTo("invalid_grant"));
    }

    @Test
    @DisplayName("without a redirect URI the user sees a signed-out page; a repeated logout is harmless")
    void signOutWithoutRedirect() {
        SignedIn user = signInWithPassword();

        Response out = endSessionByForm(user.session(), user.idToken(), "ignored-without-redirect");
        out.then().statusCode(200)
                .header("Location", nullValue())
                .header("Cache-Control", "no-store")
                .contentType(containsString("text/html"))
                .body(containsString("signed out"));
        assertThat(out.getDetailedCookie(SessionCookies.NAME).getMaxAge()).isZero();
        authorizeWithSession(user.session()).then().statusCode(303);

        // The relying party's link followed twice, with an expired-or-not hint, still answers.
        endSession(null, user.idToken(), null, POST_LOGOUT, null)
                .then().statusCode(303)
                .header("Location", equalTo(POST_LOGOUT));
    }

    // ------------------------------------------------------------------ helpers

    private Response endSession(String session, String hint, String clientId, String redirect, String state) {
        RequestSpecification req = given().config(noFollow()).header("X-Tenant-Id", TENANT);
        if (session != null) {
            req.cookie(SessionCookies.NAME, session);
        }
        if (hint != null) {
            req.queryParam("id_token_hint", hint);
        }
        if (clientId != null) {
            req.queryParam("client_id", clientId);
        }
        if (redirect != null) {
            req.queryParam("post_logout_redirect_uri", redirect);
        }
        if (state != null) {
            req.queryParam("state", state);
        }
        return req.when().get("/end_session");
    }

    private Response endSessionByForm(String session, String hint, String state) {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .cookie(SessionCookies.NAME, session)
                .contentType("application/x-www-form-urlencoded")
                .formParam("id_token_hint", hint)
                .formParam("state", state)
                .when().post("/end_session");
    }

    /** Asserts the session still signs the user in: {@code /authorize} issues a code with no password. */
    private void assertSessionAlive(SignedIn user) {
        Response authorize = authorizeWithSession(user.session());
        authorize.then().statusCode(302);
        assertThat(queryOf(authorize.getHeader("Location"))).containsKey("code");
    }

    private Response authorizeWithSession(String session) {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .cookie(SessionCookies.NAME, session)
                .queryParam("response_type", "code")
                .queryParam("client_id", CLIENT)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(newVerifier()))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
    }

    /**
     * The browser path: {@code /authorize} without a session goes to tessera's sign-in page, the
     * password is posted there, and the code that comes back is redeemed by the relying party.
     */
    private SignedIn signInWithPassword() {
        String verifier = newVerifier();
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .queryParam("response_type", "code")
                .queryParam("client_id", CLIENT)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid offline_access")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        authorize.then().statusCode(303);
        String txn = queryOf(authorize.getHeader("Location")).get("txn");
        String binding = authorize.getCookie(SignInCookies.NAME);

        Response page = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .cookie(SignInCookies.NAME, binding)
                .queryParam("txn", txn)
                .when().get("/signin");
        Matcher csrf = CSRF.matcher(page.asString());
        assertThat(csrf.find()).isTrue();

        Response signedIn = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .header("Sec-Fetch-Site", "same-origin")
                .cookie(SignInCookies.NAME, binding)
                .contentType("application/x-www-form-urlencoded")
                .formParam("txn", txn)
                .formParam("csrf", csrf.group(1))
                .formParam("username", FakePasswordCredentialVerifier.USERNAME)
                .formParam("password", FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .when().post("/signin");
        signedIn.then().statusCode(303);
        String session = signedIn.getCookie(SessionCookies.NAME);
        assertThat(session).isNotBlank();

        Response token = tokenWithDpop(CLIENT, queryOf(signedIn.getHeader("Location")).get("code"),
                REDIRECT_URI, verifier, dpop.proof(TOKEN_ENDPOINT));
        token.then().statusCode(200);
        assertThat(token.jsonPath().getString("refresh_token")).isNotBlank();
        return new SignedIn(session, token.jsonPath().getString("id_token"),
                token.jsonPath().getString("access_token"), token.jsonPath().getString("refresh_token"));
    }

    /** Tokens for {@code subject} through the trusted subject header, in {@code tenant} (default: {@link #TENANT}). */
    private SignedIn issueTokens(String subject, String tenant) {
        String realm = tenant == null ? TENANT : tenant;
        String verifier = newVerifier();
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", realm)
                .header("X-Subject-Id", subject)
                .queryParam("response_type", "code")
                .queryParam("client_id", CLIENT)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "st-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        authorize.then().statusCode(302);
        Map<String, String> query = queryOf(authorize.getHeader("Location"));
        Response token = given().config(noFollow())
                .header("X-Tenant-Id", realm)
                .header("DPoP", dpop.proof(TOKEN_ENDPOINT))
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", query.get("code"))
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", CLIENT)
                .formParam("code_verifier", verifier)
                .when().post("/token");
        token.then().statusCode(200);
        return new SignedIn(null, token.jsonPath().getString("id_token"), token.jsonPath().getString("access_token"),
                null);
    }

    private Response refresh(String refreshToken) {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("client_id", CLIENT)
                .when().post("/token");
    }
}
