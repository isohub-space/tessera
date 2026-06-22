package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.FakeKeyProvider;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import jakarta.inject.Inject;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * End-to-end {@code /authorize} → {@code /token} Authorization Code + PKCE flow over HTTP.
 *
 * <p>Boots the REST adapter with in-process fakes for the ports owned by other layers
 * (client repository, secret verifier, key provider — the last generates a real Ed25519 key
 * so the issued JWTs are genuinely verifiable). Covers the happy path (public and confidential
 * clients) plus the security-critical denial paths: a replayed code, a PKCE mismatch, a
 * {@code redirect_uri} mismatch, a wrong client secret, an unknown client, an
 * {@code unauthorized_client}, and missing parameters.
 */
@QuarkusTest
@DisplayName("/authorize -> /token Authorization Code + PKCE flow")
class AuthorizationCodeFlowTest {

    private static final String TENANT = UUID.randomUUID().toString();
    private static final String REDIRECT_URI = "https://client.example/callback";
    private static final String ISSUER = "https://issuer.test.example";

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    @Inject
    FakeKeyProvider keyProvider;

    // ----------------------------------------------------------------- happy paths

    @Test
    @DisplayName("public client: authorize issues a code, token returns a verifiable at+jwt + id_token")
    void publicClientHappyPath() throws Exception {
        String verifier = newVerifier();
        String challenge = s256(verifier);

        Response authorize = authorize(FakeClientRepository.PUBLIC_CLIENT_ID,
                REDIRECT_URI, "openid profile", "state-123", "nonce-abc", challenge, "S256",
                "user-sub-1");
        authorize.then().statusCode(302);

        Map<String, String> params = queryOf(authorize.getHeader("Location"));
        assertThat(params).containsKey("code");
        assertThat(params.get("state")).isEqualTo("state-123");
        assertThat(params.get("iss")).isEqualTo(ISSUER);

        Response token = given()
                .config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", params.get("code"))
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", FakeClientRepository.PUBLIC_CLIENT_ID)
                .formParam("code_verifier", verifier)
                .when().post("/token");

        token.then().statusCode(200)
                .header("Cache-Control", "no-store")
                .body("token_type", org.hamcrest.Matchers.equalTo("Bearer"))
                .body("scope", org.hamcrest.Matchers.equalTo("openid profile"));

        String accessToken = token.jsonPath().getString("access_token");
        String idToken = token.jsonPath().getString("id_token");
        assertThat(accessToken).isNotBlank();
        assertThat(idToken).isNotBlank();

        // The access token is a verifiable RFC 9068 JWT (typ at+jwt) with the right claims.
        assertThat(verifySignature(accessToken)).isTrue();
        Map<String, Object> atHeader = jsonPart(accessToken, 0);
        Map<String, Object> atClaims = jsonPart(accessToken, 1);
        assertThat(atHeader.get("typ")).isEqualTo("at+jwt");
        assertThat(atHeader.get("alg")).isEqualTo("EdDSA");
        assertThat(atHeader.get("kid")).isEqualTo("test-key-1");
        assertThat(atClaims.get("iss")).isEqualTo(ISSUER);
        assertThat(atClaims.get("sub")).isEqualTo("user-sub-1");
        assertThat(atClaims.get("client_id")).isEqualTo(FakeClientRepository.PUBLIC_CLIENT_ID);
        assertThat(atClaims.get("scope")).isEqualTo("openid profile");
        assertThat(atClaims).containsKey("jti").containsKey("exp").containsKey("iat");

        // The ID token binds the nonce from the authorization request (OIDC Core §3.1.3.6).
        assertThat(verifySignature(idToken)).isTrue();
        Map<String, Object> idClaims = jsonPart(idToken, 1);
        assertThat(idClaims.get("nonce")).isEqualTo("nonce-abc");
        assertThat(idClaims.get("aud")).isEqualTo(FakeClientRepository.PUBLIC_CLIENT_ID);
        assertThat(idClaims.get("sub")).isEqualTo("user-sub-1");
    }

    @Test
    @DisplayName("confidential client: a correct secret authenticates and yields tokens")
    void confidentialClientHappyPath() {
        String verifier = newVerifier();
        String code = authorizeAndExtractCode(FakeClientRepository.CONFIDENTIAL_CLIENT_ID,
                verifier, "state-c", "nonce-c");

        token(FakeClientRepository.CONFIDENTIAL_CLIENT_ID, code, REDIRECT_URI, verifier,
                FakeClientSecretVerifier.CORRECT_SECRET)
                .then().statusCode(200)
                .body("access_token", org.hamcrest.Matchers.not(org.hamcrest.Matchers.emptyOrNullString()));
    }

    // ----------------------------------------------------------------- denial paths

    @Test
    @DisplayName("a code is single-use: the second redemption is invalid_grant")
    void replayedCodeIsRejected() {
        String verifier = newVerifier();
        String code = authorizeAndExtractCode(FakeClientRepository.PUBLIC_CLIENT_ID,
                verifier, "state-r", "nonce-r");

        token(FakeClientRepository.PUBLIC_CLIENT_ID, code, REDIRECT_URI, verifier, null)
                .then().statusCode(200);

        token(FakeClientRepository.PUBLIC_CLIENT_ID, code, REDIRECT_URI, verifier, null)
                .then().statusCode(400)
                .body("error", org.hamcrest.Matchers.equalTo("invalid_grant"));
    }

    @Test
    @DisplayName("a wrong PKCE verifier is invalid_grant")
    void pkceMismatchIsRejected() {
        String verifier = newVerifier();
        String code = authorizeAndExtractCode(FakeClientRepository.PUBLIC_CLIENT_ID,
                verifier, "state-p", "nonce-p");

        // A different (well-formed) verifier whose S256 does not match the stored challenge.
        token(FakeClientRepository.PUBLIC_CLIENT_ID, code, REDIRECT_URI, newVerifier(), null)
                .then().statusCode(400)
                .body("error", org.hamcrest.Matchers.equalTo("invalid_grant"));
    }

    @Test
    @DisplayName("a redirect_uri that differs from the one bound to the code is invalid_grant")
    void redirectUriMismatchIsRejected() {
        String verifier = newVerifier();
        String code = authorizeAndExtractCode(FakeClientRepository.PUBLIC_CLIENT_ID,
                verifier, "state-u", "nonce-u");

        token(FakeClientRepository.PUBLIC_CLIENT_ID, code,
                "https://client.example/OTHER", verifier, null)
                .then().statusCode(400)
                .body("error", org.hamcrest.Matchers.equalTo("invalid_grant"));
    }

    @Test
    @DisplayName("a confidential client presenting a wrong secret is invalid_client (401)")
    void wrongClientSecretIsRejected() {
        String verifier = newVerifier();
        String code = authorizeAndExtractCode(FakeClientRepository.CONFIDENTIAL_CLIENT_ID,
                verifier, "state-w", "nonce-w");

        token(FakeClientRepository.CONFIDENTIAL_CLIENT_ID, code, REDIRECT_URI, verifier,
                "wrong-secret")
                .then().statusCode(401)
                .body("error", org.hamcrest.Matchers.equalTo("invalid_client"));
    }

    @Test
    @DisplayName("authorize with a missing code_challenge is a non-redirectable 400 invalid_request")
    void missingPkceChallengeIsRejected() {
        // PKCE is mandatory; the error is NOT redirected (the redirect_uri is unvalidated at
        // /authorize), so it surfaces as a 400 body rather than an error redirect.
        authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI,
                "openid", "state-m", "nonce-m", null, null, "user-sub-1")
                .then().statusCode(400)
                .header("Location", org.hamcrest.Matchers.nullValue())
                .body("error", org.hamcrest.Matchers.equalTo("invalid_request"));
    }

    @Test
    @DisplayName("authorize for an unknown client is a non-redirectable 400 (untrusted redirect_uri)")
    void unknownClientIsNonRedirectable() {
        authorize("does-not-exist", REDIRECT_URI, "openid", "state-x", "nonce-x",
                s256(newVerifier()), "S256", "user-sub-1")
                .then().statusCode(400)
                .body("error", org.hamcrest.Matchers.equalTo("invalid_request"));
    }

    @Test
    @DisplayName("authorize for a client not allowed the code grant is unauthorized_client")
    void unauthorizedClientGrantIsRejected() {
        // A resolved client not permitted the authorization_code grant is refused; like every
        // authorize-time error it is a 400 (not redirected to the unvalidated redirect_uri).
        authorize(FakeClientRepository.NO_CODE_CLIENT_ID, REDIRECT_URI, "openid", "state-n",
                "nonce-n", s256(newVerifier()), "S256", "user-sub-1")
                .then().statusCode(400)
                .body("error", org.hamcrest.Matchers.equalTo("unauthorized_client"));
    }

    @Test
    @DisplayName("token with an unsupported grant_type is unsupported_grant_type")
    void unsupportedGrantTypeIsRejected() {
        given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "password")
                .formParam("code", "x").formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", FakeClientRepository.PUBLIC_CLIENT_ID)
                .formParam("code_verifier", newVerifier())
                .when().post("/token")
                .then().statusCode(400)
                .body("error", org.hamcrest.Matchers.equalTo("unsupported_grant_type"));
    }

    // ----------------------------------------------------------------- helpers

    private Response authorize(String clientId, String redirectUri, String scope, String state,
            String nonce, String challenge, String method, String subject) {
        var req = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", scope)
                .queryParam("state", state)
                .queryParam("nonce", nonce);
        if (challenge != null) {
            req.queryParam("code_challenge", challenge);
        }
        if (method != null) {
            req.queryParam("code_challenge_method", method);
        }
        if (subject != null) {
            req.header("X-Subject-Id", subject);
        }
        return req.when().get("/authorize");
    }

    private String authorizeAndExtractCode(String clientId, String verifier, String state,
            String nonce) {
        Response authorize = authorize(clientId, REDIRECT_URI, "openid", state, nonce,
                s256(verifier), "S256", "user-sub-1");
        authorize.then().statusCode(302);
        String code = queryOf(authorize.getHeader("Location")).get("code");
        assertThat(code).isNotBlank();
        return code;
    }

    private Response token(String clientId, String code, String redirectUri, String verifier,
            String secret) {
        var req = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", redirectUri)
                .formParam("client_id", clientId)
                .formParam("code_verifier", verifier);
        if (secret != null) {
            req.formParam("client_secret", secret);
        }
        return req.when().post("/token");
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }

    private static Map<String, String> queryOf(String location) {
        assertThat(location).isNotBlank();
        String query = URI.create(location).getQuery();
        java.util.Map<String, String> out = new java.util.LinkedHashMap<>();
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            String k = java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String v = java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            out.put(k, v);
        }
        return out;
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

    private boolean verifySignature(String jws) throws Exception {
        int firstDot = jws.indexOf('.');
        int lastDot = jws.lastIndexOf('.');
        byte[] signingInput = jws.substring(0, lastDot).getBytes(StandardCharsets.US_ASCII);
        byte[] sig = B64URL_DEC.decode(jws.substring(lastDot + 1));
        assertThat(firstDot).isLessThan(lastDot);
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(keyProvider.publicKey());
        verifier.update(signingInput);
        return verifier.verify(sig);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> jsonPart(String jws, int index) {
        String part = jws.split("\\.")[index];
        String json = new String(B64URL_DEC.decode(part), StandardCharsets.UTF_8);
        return io.restassured.path.json.JsonPath.from(json).getMap("$");
    }
}
