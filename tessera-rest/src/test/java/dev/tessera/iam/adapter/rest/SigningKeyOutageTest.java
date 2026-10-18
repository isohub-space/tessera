package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Fail-closed on a signing-key provider outage. With the realm's provider unavailable, {@code /token}
 * issues nothing (no unsigned or fallback token) and {@code /introspect} never reports a token
 * active from keys it can no longer read. One method, because the outage is permanent for this
 * class's realm once switched on.
 */
@QuarkusTest
@DisplayName("Signing-key provider outage: /token and /introspect deny, never serve unsigned or stale")
class SigningKeyOutageTest extends AuthorizationCodeFlowSupport {

    @Test
    @DisplayName("during an outage /token issues no token and /introspect reports nothing active")
    void outageDeniesTokenAndIntrospection() {
        // Before the outage: a live access token, and a fresh code still to redeem.
        String verifier = newVerifier();
        String accessToken = tokenWithDpop(FakeClientRepository.PUBLIC_CLIENT_ID,
                authorizeAndExtractCode(FakeClientRepository.PUBLIC_CLIENT_ID, verifier, "s-1", "n-1"),
                REDIRECT_URI, verifier, dpop.proof(TOKEN_ENDPOINT))
                .then().statusCode(200).extract().jsonPath().getString("access_token");
        introspect(accessToken).then().statusCode(200).body("active", org.hamcrest.Matchers.is(true));

        String pendingVerifier = newVerifier();
        String pendingCode = authorizeAndExtractCode(
                FakeClientRepository.PUBLIC_CLIENT_ID, pendingVerifier, "s-2", "n-2");

        keyProvider.makeUnavailable(REALM);

        Response token = tokenWithDpop(FakeClientRepository.PUBLIC_CLIENT_ID, pendingCode,
                REDIRECT_URI, pendingVerifier, dpop.proof(TOKEN_ENDPOINT));
        assertThat(token.statusCode()).as("/token during an outage").isGreaterThanOrEqualTo(500);
        assertThat(token.asString())
                .doesNotContain("\"access_token\":", "\"id_token\":", "\"refresh_token\":");

        Response introspection = introspect(accessToken);
        assertThat(introspection.statusCode()).as("/introspect during an outage")
                .isGreaterThanOrEqualTo(500);
        // Test mode renders a 5xx with a diagnostic body; it must still carry no introspection claim.
        assertThat(introspection.asString())
                .doesNotContain("\"active\":true", "\"sub\":", "\"scope\":");
    }

    private Response introspect(String token) {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token)
                .formParam("client_id", FakeClientRepository.CONFIDENTIAL_CLIENT_ID)
                .formParam("client_secret", FakeClientSecretVerifier.CORRECT_SECRET)
                .when().post("/introspect");
    }
}
