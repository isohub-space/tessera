// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.AssertionTestClient;
import dev.tessera.iam.adapter.rest.support.FakeClientKeySource;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code POST /token} with a JWT client assertion (RFC 7523 §2.2) on the {@code client_credentials}
 * grant: a {@code private_key_jwt} client authenticates with its registered key, each client only
 * with the method it is registered for, and every refusal looks the same.
 */
@QuarkusTest
@DisplayName("POST /token — private_key_jwt client authentication (RFC 7523)")
class ClientAssertionFlowTest extends AuthorizationCodeFlowSupport {

    private static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String KEYED = FakeClientRepository.KEYED_CLIENT_ID;
    private static final AssertionTestClient KEY = FakeClientKeySource.CLIENT;

    private static RequestSpecification request() {
        return given().config(noFollow())
                .header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials");
    }

    private static String assertionFor(String clientId) {
        return KEY.sign(AssertionTestClient.claims(clientId, ISSUER, Instant.now()).build());
    }

    private static Response withAssertion(String assertion) {
        return request().formParam("client_assertion_type", JWT_BEARER).formParam("client_assertion", assertion)
                .when().post("/token");
    }

    @Test
    @DisplayName("a private_key_jwt client with a registered JWKS gets a token for itself, client_id optional")
    void keyedClientGetsAToken() {
        Response response = withAssertion(assertionFor(KEYED));
        response.then().statusCode(200).body("token_type", Matchers.equalTo("Bearer"));
        assertThat(jsonPart(response.jsonPath().getString("access_token"), 1))
                .containsEntry("sub", KEYED).containsEntry("client_id", KEYED);

        request().formParam("client_id", KEYED)
                .formParam("client_assertion_type", JWT_BEARER).formParam("client_assertion", assertionFor(KEYED))
                .when().post("/token").then().statusCode(200);
    }

    @Test
    @DisplayName("method mismatch: a secret client's assertion and a keyed client's secret are invalid_client")
    void eachClientUsesOnlyItsMethod() {
        withAssertion(assertionFor(FakeClientRepository.MACHINE_CLIENT_ID)).then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
        String basic = "Basic " + Base64.getEncoder().encodeToString(
                (KEYED + ":" + FakeClientSecretVerifier.CORRECT_SECRET).getBytes(StandardCharsets.UTF_8));
        request().header("Authorization", basic).when().post("/token").then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
    }

    @Test
    @DisplayName("an assertion and a secret together are invalid_request; an assertion on another grant is refused")
    void oneMethodPerRequest() {
        request().formParam("client_secret", FakeClientSecretVerifier.CORRECT_SECRET)
                .formParam("client_assertion_type", JWT_BEARER).formParam("client_assertion", assertionFor(KEYED))
                .when().post("/token").then().statusCode(400).body("error", Matchers.equalTo("invalid_request"));
        given().config(noFollow()).header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "refresh_token").formParam("refresh_token", "r")
                .formParam("client_assertion_type", JWT_BEARER).formParam("client_assertion", assertionFor(KEYED))
                .when().post("/token").then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));
    }

    @Test
    @DisplayName("a replayed assertion is refused")
    void replayIsRefused() {
        String assertion = assertionFor(KEYED);
        withAssertion(assertion).then().statusCode(200);
        withAssertion(assertion).then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));
    }

    @Test
    @DisplayName("unknown client, foreign key, bad claim and wrong assertion type answer identically")
    void refusalsLookAlike() {
        Instant now = Instant.now();
        List<Response> refusals = List.of(
                withAssertion(assertionFor("nobody")),
                withAssertion(new AssertionTestClient().sign(AssertionTestClient.claims(KEYED, ISSUER, now).build())),
                withAssertion(KEY.sign(AssertionTestClient.claims(KEYED, "https://elsewhere.example", now).build())),
                request().formParam("client_assertion_type", "urn:other").formParam("client_assertion", assertionFor(KEYED))
                        .when().post("/token"));
        String first = refusals.get(0).asString();
        assertThat(refusals).allSatisfy(refusal -> {
            assertThat(refusal.statusCode()).isEqualTo(401);
            assertThat(refusal.asString()).isEqualTo(first);
        });
    }

    @Test
    @DisplayName("discovery lists exactly the implemented client authentication methods and assertion algorithms")
    void discoveryListsExactlyTheImplementedMethods() {
        given().header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                .when().get("/.well-known/openid-configuration")
                .then().statusCode(200)
                .body("token_endpoint_auth_methods_supported",
                        Matchers.contains("client_secret_basic", "client_secret_post", "private_key_jwt"))
                .body("token_endpoint_auth_signing_alg_values_supported", Matchers.contains("ES256", "PS256", "RS256"));
    }
}
