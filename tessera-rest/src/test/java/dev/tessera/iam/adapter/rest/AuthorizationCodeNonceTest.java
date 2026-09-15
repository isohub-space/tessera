package dev.tessera.iam.adapter.rest;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The {@code nonce} parameter over the full code flow.
 *
 * <p>OIDC Core §3.1.2.1 makes {@code nonce} OPTIONAL for the authorization-code flow, and
 * this endpoint accepts {@code response_type=code} and nothing else — the implicit and
 * hybrid flows, the ones where §3.2.2.1 and §3.3.2.1 make {@code nonce} REQUIRED, are
 * structurally unreachable here. So there is no response type this server serves for which
 * a missing {@code nonce} would be a protocol violation.
 *
 * <p>Separate from {@link AuthorizationCodeFlowTest} so neither file outgrows the
 * repository's 500-line limit; both share {@link AuthorizationCodeFlowSupport}.
 */
@QuarkusTest
@DisplayName("/authorize -> /token — the optional nonce")
class AuthorizationCodeNonceTest extends AuthorizationCodeFlowSupport {

    @Test
    @DisplayName("a code-flow request omitting nonce succeeds and its ID token carries no nonce claim")
    void codeFlowWithoutNonceIsAccepted() throws Exception {
        // OIDC Core §3.1.2.1 makes nonce OPTIONAL for the authorization-code
        // flow; this endpoint used to reject its absence with a 400, turning away
        // spec-conformant relying parties. Fails against main at the authorize step.
        //
        // What the ID token must NOT do is invent a nonce: §3.1.3.6 binds the claim to the
        // request's value, so with nothing sent there is nothing to echo, and a null or
        // empty claim is something a client could mistake for a value.
        String verifier = newVerifier();

        Response authorize = authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI,
                "openid", "state-no-nonce", null, s256(verifier), "S256", "user-sub-1");
        authorize.then().statusCode(302);

        Map<String, String> params = queryOf(authorize.getHeader("Location"));
        assertThat(params).containsKey("code");
        assertThat(params.get("state")).isEqualTo("state-no-nonce");

        Response token = tokenWithDpop(FakeClientRepository.PUBLIC_CLIENT_ID, params.get("code"),
                REDIRECT_URI, verifier, dpop.proof(TOKEN_ENDPOINT));
        token.then().statusCode(200);

        String idToken = token.jsonPath().getString("id_token");
        assertThat(idToken).isNotBlank();
        assertThat(verifySignature(idToken)).isTrue();

        Map<String, Object> idClaims = jsonPart(idToken, 1);
        assertThat(idClaims).doesNotContainKey("nonce");
        // Every §2 required claim is still present — the token is a valid ID token, just
        // one with nothing to bind back.
        assertThat(idClaims.get("iss")).isEqualTo(ISSUER);
        assertThat(idClaims.get("sub")).isEqualTo("user-sub-1");
        assertThat(idClaims.get("aud")).isEqualTo(FakeClientRepository.PUBLIC_CLIENT_ID);
        assertThat(idClaims).containsKey("iat").containsKey("exp");
    }

    @Test
    @DisplayName("an empty nonce= is treated as omitted, per RFC 6749 §3.1")
    void emptyNonceParameterIsTreatedAsOmitted() {
        // RFC 6749 §3.1: "Parameters sent without a value MUST be treated as if they were
        // omitted from the request." So `?nonce=` is an absent nonce, not a malformed one,
        // and must behave exactly like sending no nonce at all — a 302, and an ID token
        // with no nonce claim rather than an empty one.
        //
        // The domain record still refuses to represent a blank nonce; that guard is what
        // stops an empty value ever reaching the ID token if this normalisation is removed.
        String verifier = newVerifier();

        Response authorize = authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI,
                "openid", "state-empty-nonce", "", s256(verifier), "S256", "user-sub-1");
        authorize.then().statusCode(302);

        Response token = tokenWithDpop(FakeClientRepository.PUBLIC_CLIENT_ID,
                queryOf(authorize.getHeader("Location")).get("code"),
                REDIRECT_URI, verifier, dpop.proof(TOKEN_ENDPOINT));
        token.then().statusCode(200);

        Map<String, Object> idClaims = jsonPart(token.jsonPath().getString("id_token"), 1);
        assertThat(idClaims).doesNotContainKey("nonce");
    }

    @Test
    @DisplayName("PKCE stays mandatory when nonce is omitted")
    void pkceStillMandatoryWithoutNonce() {
        // Relaxing nonce must not relax the check that actually binds a code to a client.
        authorize(FakeClientRepository.PUBLIC_CLIENT_ID, REDIRECT_URI, "openid",
                "state-no-nonce-no-pkce", null, null, null, "user-sub-1")
                .then().statusCode(400)
                .body("error", org.hamcrest.Matchers.equalTo("invalid_request"));
    }
}
