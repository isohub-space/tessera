package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The {@code iam.authflow.require-sender-constraint=false} policy: a secret-authenticated
 * confidential client that presents no client certificate is issued a plain Bearer token
 * (no {@code cnf}), while a presented certificate still binds the token exactly as under the
 * default policy. The default ({@code true}) is exercised by
 * {@link AuthorizationCodeFlowTest#confidentialClientMissingCertIsRejected}.
 *
 * <p>Also proves the realm-asserting ID token: with the {@code profile} scope granted the
 * ID token carries {@code realm_tenant} and {@code realm_baseline}, which is what a relying
 * party that scopes its own data by tenant reads.
 */
@QuarkusTest
@TestProfile(BearerTokenPolicyTest.BearerAllowed.class)
@DisplayName("Sender-constraint policy — opt-out issues Bearer tokens to secret-authenticated clients")
class BearerTokenPolicyTest {

    public static class BearerAllowed implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("iam.authflow.require-sender-constraint", "false");
        }
    }

    private static final String TENANT = UUID.randomUUID().toString();
    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    @Test
    @DisplayName("no certificate: secret-authenticated confidential client gets an unbound Bearer token")
    void noCertificateYieldsBearer() {
        String verifier = newVerifier();
        String code = authorizeAndExtractCode(verifier, "openid profile");

        Response token = tokenRequest(code, verifier, null);

        token.then().statusCode(200)
                .body("token_type", org.hamcrest.Matchers.equalTo("Bearer"))
                .body("access_token", org.hamcrest.Matchers.not(org.hamcrest.Matchers.emptyOrNullString()))
                .body("id_token", org.hamcrest.Matchers.not(org.hamcrest.Matchers.emptyOrNullString()));

        Map<String, Object> atClaims = jsonPart(token.jsonPath().getString("access_token"), 1);
        assertThat(atClaims).doesNotContainKey("cnf");
        assertThat(atClaims.get("scope")).isEqualTo("openid profile");

        Map<String, Object> idClaims = jsonPart(token.jsonPath().getString("id_token"), 1);
        assertThat(idClaims.get("realm_tenant")).isEqualTo(TENANT);
        assertThat(idClaims.get("realm_baseline")).isEqualTo(new UUID(0L, 0L).toString());
    }

    @Test
    @DisplayName("a presented certificate still binds the token under the opt-out policy")
    void certificateStillBinds() {
        String verifier = newVerifier();
        String code = authorizeAndExtractCode(verifier, "openid");

        Response token = tokenRequest(code, verifier, TestClientCertificate.PEM);

        token.then().statusCode(200).body("token_type", org.hamcrest.Matchers.equalTo("Bearer"));
        Map<String, Object> atClaims = jsonPart(token.jsonPath().getString("access_token"), 1);
        @SuppressWarnings("unchecked")
        Map<String, Object> cnf = (Map<String, Object>) atClaims.get("cnf");
        assertThat(cnf).isNotNull();
        assertThat(cnf.get("x5t#S256")).isEqualTo(TestClientCertificate.X5T_S256);

        Map<String, Object> idClaims = jsonPart(token.jsonPath().getString("id_token"), 1);
        assertThat(idClaims).doesNotContainKey("realm_tenant");
    }

    // ----------------------------------------------------------------- helpers

    private String authorizeAndExtractCode(String verifier, String scope) {
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .header("X-Subject-Id", "user-sub-1")
                .queryParam("response_type", "code")
                .queryParam("client_id", FakeClientRepository.CONFIDENTIAL_CLIENT_ID)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", scope)
                .queryParam("state", "state-b")
                .queryParam("nonce", "nonce-b")
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        authorize.then().statusCode(302);
        String code = queryOf(authorize.getHeader("Location")).get("code");
        assertThat(code).isNotBlank();
        return code;
    }

    private Response tokenRequest(String code, String verifier, String certificate) {
        var req = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", FakeClientRepository.CONFIDENTIAL_CLIENT_ID)
                .formParam("code_verifier", verifier)
                .formParam("client_secret", FakeClientSecretVerifier.CORRECT_SECRET);
        if (certificate != null) {
            req.header("X-Client-Certificate", certificate);
        }
        return req.when().post("/token");
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }

    private static Map<String, String> queryOf(String location) {
        assertThat(location).isNotBlank();
        Map<String, String> out = new LinkedHashMap<>();
        for (String pair : URI.create(location).getQuery().split("&")) {
            int eq = pair.indexOf('=');
            out.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return out;
    }

    private static String newVerifier() {
        byte[] bytes = new byte[48];
        new SecureRandom().nextBytes(bytes);
        return B64URL.encodeToString(bytes);
    }

    private static String s256(String verifier) {
        try {
            return B64URL.encodeToString(MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static Map<String, Object> jsonPart(String jws, int index) {
        String json = new String(B64URL_DEC.decode(jws.split("\\.")[index]), StandardCharsets.UTF_8);
        return io.restassured.path.json.JsonPath.from(json).getMap("$");
    }
}
