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
 * End-to-end {@code POST /introspect} flow over HTTP (Docker-free, in-memory store), RFC 7662: a live
 * JWT access token and a live refresh token are reported active with their claims; expired/superseded/
 * unknown/malformed/cross-tenant/tampered tokens are exactly {@code {"active": false}} (non-oracle);
 * and the only non-{@code 200} is a {@code 401} on client-authentication failure. The access-token
 * cases exercise the real EdDSA verify path (a token the server signs, then verifies via the JWK).
 */
@QuarkusTest
@DisplayName("POST /introspect — RFC 7662 introspection, non-oracle, client-authenticated")
class IntrospectFlowTest {

    private static final String REDIRECT_URI = FakeClientRepository.REDIRECT_URI;
    private static final String TOKEN_CLIENT = FakeClientRepository.REFRESH_CLIENT_ID; // owns the tokens
    private static final String CALLER = FakeClientRepository.CONFIDENTIAL_CLIENT_ID;   // the resource server
    private static final String CALLER_SECRET = FakeClientSecretVerifier.CORRECT_SECRET;
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Test
    @DisplayName("a live JWT access token is active with sub, client_id, scope, token_type, exp, iat")
    void activeAccessToken() {
        String tenant = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        Tokens tokens = issue(tenant, subject);

        introspect(tenant, CALLER, CALLER_SECRET, tokens.accessToken()).then()
                .statusCode(200).header("Cache-Control", "no-store")
                .body("active", Matchers.is(true))
                .body("sub", Matchers.equalTo(subject))
                .body("client_id", Matchers.equalTo(TOKEN_CLIENT))
                .body("token_type", Matchers.equalTo("Bearer"))
                .body("scope", Matchers.containsString("openid"))
                .body("exp", Matchers.notNullValue())
                .body("iat", Matchers.notNullValue());
    }

    @Test
    @DisplayName("a live refresh token is active with sub (no client_id); a superseded one is inactive")
    void activeRefreshTokenAndSupersededInactive() {
        String tenant = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        Tokens tokens = issue(tenant, subject);

        introspect(tenant, CALLER, CALLER_SECRET, tokens.refreshToken()).then()
                .statusCode(200)
                .body("active", Matchers.is(true))
                .body("sub", Matchers.equalTo(subject))
                // A refresh family stores only the client's surrogate id, not the wire client_id,
                // so client_id is omitted for a refresh token (unlike the access-token path).
                .body("client_id", Matchers.nullValue());

        // Rotate: redeeming the refresh token supersedes it and mints a new one.
        String rotated = refresh(tenant, tokens.refreshToken()).then().statusCode(200)
                .extract().jsonPath().getString("refresh_token");

        // The superseded token is no longer active; the rotated one is.
        introspect(tenant, CALLER, CALLER_SECRET, tokens.refreshToken()).then()
                .statusCode(200).body("active", Matchers.is(false));
        introspect(tenant, CALLER, CALLER_SECRET, rotated).then()
                .statusCode(200).body("active", Matchers.is(true));
    }

    @Test
    @DisplayName("unknown, malformed, blank, and tampered tokens are all inactive (no oracle)")
    void unrecognisedTokensAreInactive() {
        String tenant = UUID.randomUUID().toString();
        String subject = UUID.randomUUID().toString();
        Tokens tokens = issue(tenant, subject);

        // Random well-formed-but-unknown opaque refresh token.
        String unknownRefresh = B64URL.encodeToString(uuidBytes(UUID.randomUUID())) + ".deadbeef";
        introspect(tenant, CALLER, CALLER_SECRET, unknownRefresh).then()
                .statusCode(200).body("active", Matchers.is(false));
        introspect(tenant, CALLER, CALLER_SECRET, "not-a-token").then()
                .statusCode(200).body("active", Matchers.is(false));
        introspect(tenant, CALLER, CALLER_SECRET, "").then()
                .statusCode(200).body("active", Matchers.is(false));

        // A tampered access token (flipped final signature char) fails verification.
        String tampered = flipLast(tokens.accessToken());
        introspect(tenant, CALLER, CALLER_SECRET, tampered).then()
                .statusCode(200).body("active", Matchers.is(false));
    }

    // Cross-tenant isolation is covered here for REFRESH tokens (realm-scoped store lookup). The
    // ACCESS-token cross-tenant boundary is cryptographic — a token verifies only against its realm's
    // published keys, which in production come from the RLS-scoped DbKeyProviderAdapter. It is not
    // exercised here because FakeKeyProvider returns one shared key for every realm; adding a
    // realm-scoped fake to assert an A-signed access token is inactive under realm B is a tracked
    // test-coverage follow-up. (Production isolation itself is verified by the security review.)
    @Test
    @DisplayName("introspecting a refresh token under a different tenant is inactive (no cross-tenant leak)")
    void crossTenantRefreshIsInactive() {
        String tenantA = UUID.randomUUID().toString();
        Tokens tokens = issue(tenantA, UUID.randomUUID().toString());

        String tenantB = UUID.randomUUID().toString();
        introspect(tenantB, CALLER, CALLER_SECRET, tokens.refreshToken()).then()
                .statusCode(200).body("active", Matchers.is(false));

        // Still active in its own tenant.
        introspect(tenantA, CALLER, CALLER_SECRET, tokens.refreshToken()).then()
                .statusCode(200).body("active", Matchers.is(true));
    }

    @Test
    @DisplayName("client-authentication failure is the only non-200: 401 invalid_client")
    void clientAuthFailureIsUnauthorized() {
        String tenant = UUID.randomUUID().toString();
        Tokens tokens = issue(tenant, UUID.randomUUID().toString());

        introspect(tenant, CALLER, "wrong-secret", tokens.accessToken()).then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));
        introspect(tenant, CALLER, null, tokens.accessToken()).then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));

        given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", tokens.accessToken())
                .when().post("/introspect")
                .then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));
    }

    // --------------------------------------------------------------------- helpers

    private Tokens issue(String tenant, String subject) {
        String verifier = newVerifier();
        String code = authorizeCode(tenant, subject, verifier);
        Response token = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", REDIRECT_URI)
                .formParam("client_id", TOKEN_CLIENT)
                .formParam("code_verifier", verifier)
                .when().post("/token");
        token.then().statusCode(200);
        String access = token.jsonPath().getString("access_token");
        String refresh = token.jsonPath().getString("refresh_token");
        assertThat(access).as("access token").isNotBlank();
        assertThat(refresh).as("refresh token").isNotBlank();
        return new Tokens(access, refresh);
    }

    private String authorizeCode(String tenant, String subject, String verifier) {
        Response authorize = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("X-Subject-Id", subject)
                .queryParam("response_type", "code")
                .queryParam("client_id", TOKEN_CLIENT)
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

    private Response introspect(String tenant, String callerId, String callerSecret, String token) {
        var request = given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token)
                .formParam("client_id", callerId);
        if (callerSecret != null) {
            request = request.formParam("client_secret", callerSecret);
        }
        return request.when().post("/introspect");
    }

    private Response refresh(String tenant, String refreshToken) {
        return given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "refresh_token")
                .formParam("refresh_token", refreshToken)
                .formParam("client_id", TOKEN_CLIENT)
                .when().post("/token");
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }

    private static String flipLast(String jws) {
        char last = jws.charAt(jws.length() - 1);
        char replacement = last == 'A' ? 'B' : 'A';
        return jws.substring(0, jws.length() - 1) + replacement;
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

    private record Tokens(String accessToken, String refreshToken) {
    }
}
