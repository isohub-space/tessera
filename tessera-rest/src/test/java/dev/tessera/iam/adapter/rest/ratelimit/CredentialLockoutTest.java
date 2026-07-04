package dev.tessera.iam.adapter.rest.ratelimit;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import io.restassured.response.Response;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the credential brute-force lockout on the Argon2 path. With {@code max-failures=3}, after
 * three consecutive wrong secrets for one {@code (tenant, client_id)} the credential check
 * short-circuits to {@code invalid_client} <em>without invoking the delegate verifier</em> — the
 * property that relieves the hashing pool under a flood.
 *
 * <p>The bypass is proven behaviourally: once locked, presenting the <em>correct</em> secret still
 * yields {@code invalid_client}. Were the delegate ({@link FakeClientSecretVerifier}, which accepts
 * the correct secret) still consulted, that request would succeed with a token.
 */
@QuarkusTest
@TestProfile(CredentialLockoutTest.Profile.class)
@DisplayName("LockoutClientSecretVerifier — brute-force lockout short-circuits the Argon2 path")
class CredentialLockoutTest {

    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    /**
     * Lockout after 3 failures; ingress buckets left generous so the ~5 request cycles here never
     * trip them — only the credential tier is under test.
     */
    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "iam.ratelimit.enabled", "true",
                    "iam.ratelimit.credential-max-failures", "3",
                    "iam.ratelimit.credential-lockout", "PT5M",
                    "iam.ratelimit.token-capacity", "100",
                    "iam.ratelimit.authorize-capacity", "100");
        }
    }

    @Test
    @DisplayName("after max failures, even the correct secret is refused (delegate bypassed)")
    void locksOutAndBypassesDelegate() {
        String tenant = UUID.randomUUID().toString();

        // Three consecutive wrong secrets — each a real (delegate-consulted) invalid_client.
        for (int i = 0; i < 3; i++) {
            redeemWithSecret(tenant, "wrong-secret-" + i)
                    .then().statusCode(401)
                    .body("error", Matchers.equalTo("invalid_client"));
        }

        // Now locked: the CORRECT secret must still be refused. If the delegate were consulted it
        // would accept and mint a token — so a 401 here proves the Argon2 path was short-circuited.
        redeemWithSecret(tenant, FakeClientSecretVerifier.CORRECT_SECRET)
                .then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
    }

    @Test
    @DisplayName("a different tenant is not affected by another tenant's lockout")
    void lockoutIsPerTenant() {
        String locked = UUID.randomUUID().toString();
        for (int i = 0; i < 3; i++) {
            redeemWithSecret(locked, "nope-" + i);
        }
        redeemWithSecret(locked, FakeClientSecretVerifier.CORRECT_SECRET).then().statusCode(401);

        // A fresh tenant with the correct secret authenticates normally (200).
        redeemWithSecret(UUID.randomUUID().toString(), FakeClientSecretVerifier.CORRECT_SECRET)
                .then().statusCode(200);
    }

    // ------------------------------------------------------------------- flow helpers

    /** Runs a full authorize→token cycle for the confidential client, presenting {@code secret}. */
    private Response redeemWithSecret(String tenant, String secret) {
        String verifier = newVerifier();
        String code = authorizeAndExtractCode(tenant, verifier);
        return given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", FakeClientRepository.CONFIDENTIAL_CLIENT_ID)
                .formParam("client_secret", secret)
                .formParam("code_verifier", verifier)
                .when().post("/token");
    }

    private String authorizeAndExtractCode(String tenant, String verifier) {
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("X-Subject-Id", "user-sub-1")
                .queryParam("response_type", "code")
                .queryParam("client_id", FakeClientRepository.CONFIDENTIAL_CLIENT_ID)
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "state-" + UUID.randomUUID())
                .queryParam("nonce", "nonce-" + UUID.randomUUID())
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize");
        authorize.then().statusCode(302);
        String location = authorize.getHeader("Location");
        String query = URI.create(location).getQuery();
        String code = null;
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            if ("code".equals(pair.substring(0, eq))) {
                code = java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        assertThat(code).isNotBlank();
        return code;
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

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }
}
