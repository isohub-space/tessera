package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
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
 * End-to-end {@code POST /revoke} flow over HTTP (Docker-free, in-memory store), RFC 7009: revoking
 * a refresh token burns its whole family and is idempotent; the endpoint is a non-oracle (always
 * {@code 200} for a live, unknown, malformed, cross-tenant, or other-client token); and the only
 * non-{@code 200} is a {@code 401} on client-authentication failure.
 */
@QuarkusTest
@DisplayName("POST /revoke — RFC 7009 revocation, idempotent, non-oracle, client-authenticated")
class RevokeFlowTest {

    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final String REFRESH_CLIENT = FakeClientRepository.REFRESH_CLIENT_ID;
    private static final String CONFIDENTIAL_CLIENT = FakeClientRepository.CONFIDENTIAL_CLIENT_ID;
    private static final String CORRECT_SECRET = FakeClientSecretVerifier.CORRECT_SECRET;
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Test
    @DisplayName("revoking a refresh token returns 200 (empty, no-store) and burns the family")
    void revokeBurnsFamilyAndIsIdempotent() {
        String tenant = UUID.randomUUID().toString();
        String refresh = initialRefreshToken(tenant);

        revoke(tenant, REFRESH_CLIENT, null, refresh).then()
                .statusCode(200).header("Cache-Control", "no-store").body(Matchers.emptyOrNullString());

        // The family is burned: the token no longer redeems.
        refresh(tenant, refresh).then().statusCode(400).body("error", Matchers.equalTo("invalid_grant"));

        // Idempotent: revoking again (now-revoked token) still succeeds.
        revoke(tenant, REFRESH_CLIENT, null, refresh).then().statusCode(200);
    }

    @Test
    @DisplayName("unknown, malformed, and blank tokens all return 200 (no oracle)")
    void unrecognisedTokensSucceedSilently() {
        String tenant = UUID.randomUUID().toString();
        // A syntactically-valid but unknown refresh token (right shape, random family id + secret).
        String unknown = B64URL.encodeToString(uuidBytes(UUID.randomUUID())) + ".deadbeefsecret";

        revoke(tenant, REFRESH_CLIENT, null, unknown).then().statusCode(200);
        revoke(tenant, REFRESH_CLIENT, null, "not-a-refresh-token").then().statusCode(200);
        revoke(tenant, REFRESH_CLIENT, null, "").then().statusCode(200);
    }

    @Test
    @DisplayName("revoking under a different tenant is a no-op; the token still works in its own tenant")
    void crossTenantRevokeIsNoop() {
        String tenantA = UUID.randomUUID().toString();
        String refresh = initialRefreshToken(tenantA);

        String tenantB = UUID.randomUUID().toString();
        revoke(tenantB, REFRESH_CLIENT, null, refresh).then().statusCode(200);

        // Not burned: the token still redeems in tenant A.
        refresh(tenantA, refresh).then().statusCode(200);
    }

    @Test
    @DisplayName("a different (even authenticated) client cannot revoke another client's family")
    void otherClientCannotRevoke() {
        String tenant = UUID.randomUUID().toString();
        String refresh = initialRefreshToken(tenant);

        // The confidential client authenticates correctly but does not own this refresh family.
        revoke(tenant, CONFIDENTIAL_CLIENT, CORRECT_SECRET, refresh).then().statusCode(200);

        // Not burned: the owning client's token still redeems.
        refresh(tenant, refresh).then().statusCode(200);
    }

    @Test
    @DisplayName("client-authentication failure is the only non-200: 401 invalid_client")
    void clientAuthFailureIsUnauthorized() {
        String tenant = UUID.randomUUID().toString();

        // Confidential client, wrong secret.
        revoke(tenant, CONFIDENTIAL_CLIENT, "wrong-secret", "anything").then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));

        // Confidential client, no secret.
        revoke(tenant, CONFIDENTIAL_CLIENT, null, "anything").then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));

        // No client_id at all.
        given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", "anything")
                .when().post("/revoke")
                .then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));
    }

    // --------------------------------------------------------------------- helpers

    private String initialRefreshToken(String tenant) {
        String verifier = newVerifier();
        String code = authorizeCode(tenant, verifier);
        Response token = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("DPoP", new dev.tessera.iam.adapter.rest.support.DpopTestClient()
                        .proof("https://issuer.test.example/token"))
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", REFRESH_CLIENT)
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
                .header("X-Subject-Id", UUID.randomUUID().toString())
                .queryParam("response_type", "code")
                .queryParam("client_id", REFRESH_CLIENT)
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
                .formParam("client_id", REFRESH_CLIENT)
                .when().post("/token");
    }

    private Response revoke(String tenant, String clientId, String clientSecret, String token) {
        var request = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token)
                .formParam("client_id", clientId);
        if (clientSecret != null) {
            request = request.formParam("client_secret", clientSecret);
        }
        return request.when().post("/revoke");
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }

    private static byte[] uuidBytes(UUID u) {
        return java.nio.ByteBuffer.allocate(16)
                .putLong(u.getMostSignificantBits())
                .putLong(u.getLeastSignificantBits())
                .array();
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
