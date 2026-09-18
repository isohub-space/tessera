package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.DpopTestClient;
import dev.tessera.iam.adapter.rest.support.FakeKeyProvider;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
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

/**
 * Shared fixture for the {@code /authorize} → {@code /token} Authorization Code + PKCE
 * tests: the realm and client constants, the DPoP client, and the request builders.
 *
 * <p>Extracted so the flow tests can be split across focused classes without either
 * duplicating the request plumbing or growing one file past the repository's 500-line
 * limit. It holds no assertions about behaviour — every test that matters lives in a
 * subclass.
 */
abstract class AuthorizationCodeFlowSupport {

    protected static final String TENANT = UUID.randomUUID().toString();
    protected static final String REDIRECT_URI = "https://client.example/callback";
    protected static final String ISSUER = "https://issuer.test.example";
    protected static final String TOKEN_ENDPOINT = ISSUER + "/token";

    /** The realm this test issues under: {@link #TENANT} at the zero (default) baseline. */
    protected static final RealmKey REALM =
            new RealmKey(TenantId.fromString(TENANT), new BaselineId(new UUID(0L, 0L)));

    /** A fresh DPoP client per test method — a public client's sender-constraining key. */
    protected final DpopTestClient dpop = new DpopTestClient();

    protected static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();
    protected static final Base64.Decoder B64URL_DEC = Base64.getUrlDecoder();

    @Inject
    FakeKeyProvider keyProvider;

        protected Response authorize(String clientId, String redirectUri, String scope, String state,
            String nonce, String challenge, String method, String subject) {
        var req = given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam("redirect_uri", redirectUri)
                .queryParam("scope", scope)
                .queryParam("state", state);
        // nonce is OPTIONAL in the code flow, so a null one sends no parameter at all
        // rather than an empty one — the two are different requests.
        if (nonce != null) {
            req.queryParam("nonce", nonce);
        }
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

    protected String authorizeAndExtractCode(String clientId, String verifier, String state,
            String nonce) {
        Response authorize = authorize(clientId, REDIRECT_URI, "openid", state, nonce,
                s256(verifier), "S256", "user-sub-1");
        authorize.then().statusCode(302);
        String code = queryOf(authorize.getHeader("Location")).get("code");
        assertThat(code).isNotBlank();
        return code;
    }

    protected Response token(String clientId, String code, String redirectUri, String verifier,
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

    /** A public-client token request carrying a DPoP proof header. */
    protected Response tokenWithDpop(String clientId, String code, String redirectUri,
            String verifier, String dpopProof) {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .header("DPoP", dpopProof)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .formParam("code", code)
                .formParam("redirect_uri", redirectUri)
                .formParam("client_id", clientId)
                .formParam("code_verifier", verifier)
                .when().post("/token");
    }

    protected static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }

    protected static Map<String, String> queryOf(String location) {
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

    protected static String newVerifier() {
        byte[] bytes = new byte[48];
        new java.security.SecureRandom().nextBytes(bytes);
        return B64URL.encodeToString(bytes);
    }

    protected static String s256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return B64URL.encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    protected boolean verifySignature(String jws) throws Exception {
        int firstDot = jws.indexOf('.');
        int lastDot = jws.lastIndexOf('.');
        byte[] signingInput = jws.substring(0, lastDot).getBytes(StandardCharsets.US_ASCII);
        byte[] sig = B64URL_DEC.decode(jws.substring(lastDot + 1));
        assertThat(firstDot).isLessThan(lastDot);
        Signature verifier = Signature.getInstance("Ed25519");
        verifier.initVerify(keyProvider.publicKey(REALM));
        verifier.update(signingInput);
        return verifier.verify(sig);
    }

    @SuppressWarnings("unchecked")
    protected static Map<String, Object> jsonPart(String jws, int index) {
        String part = jws.split("\\.")[index];
        String json = new String(B64URL_DEC.decode(part), StandardCharsets.UTF_8);
        return io.restassured.path.json.JsonPath.from(json).getMap("$");
    }
}
