// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;

import dev.tessera.iam.adapter.rest.support.AssertionTestClient;
import dev.tessera.iam.adapter.rest.support.FakeClientKeySource;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.time.Instant;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code /introspect} and {@code /revoke} spend assertion {@code jti}s against a replay budget of
 * their own: a resource server whose introspection calls, driven by whatever tokens its own callers
 * present, fill that budget is refused there and nowhere else, and still obtains its tokens at
 * {@code /token}. The introspection cap is set to two here so the budget fills in a few requests.
 */
@QuarkusTest
@TestProfile(AssertionReplayBudgetFlowTest.SmallIntrospectionBudget.class)
@DisplayName("Client assertion replay budgets — introspection load never locks a client out of /token")
class AssertionReplayBudgetFlowTest extends AuthorizationCodeFlowSupport {

    private static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String TENANT = FakeClientRepository.MACHINE_TENANT;
    private static final String KEYED = FakeClientRepository.KEYED_CLIENT_ID;

    public static class SmallIntrospectionBudget implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("iam.client-assertion.introspection-replay-cache-max-entries-per-client", "2");
        }
    }

    private static String assertion() {
        return FakeClientKeySource.CLIENT.sign(AssertionTestClient.claims(KEYED, ISSUER, Instant.now()).build());
    }

    private static RequestSpecification form() {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded");
    }

    private static Response withAssertion(String endpoint) {
        return form()
                .formParam("token", "a.b.c")
                .formParam("client_assertion_type", JWT_BEARER)
                .formParam("client_assertion", assertion())
                .when().post(endpoint);
    }

    private static Response clientCredentials() {
        return form()
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .formParam("grant_type", "client_credentials")
                .formParam("client_assertion_type", JWT_BEARER)
                .formParam("client_assertion", assertion())
                .when().post("/token");
    }

    @Test
    @DisplayName("a full introspection budget refuses /introspect and /revoke, fail-closed, and /token still issues")
    void fullIntrospectionBudgetLeavesTokenServed() {
        // /introspect and /revoke draw on one budget: two fresh assertions fill it.
        withAssertion("/introspect").then().statusCode(200).body("active", Matchers.is(false));
        withAssertion("/revoke").then().statusCode(200);

        withAssertion("/introspect").then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));
        withAssertion("/revoke").then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));

        // The same client's client_credentials grant draws on the /token budget, untouched.
        for (int i = 0; i < 3; i++) {
            clientCredentials().then().statusCode(200).body("access_token", Matchers.notNullValue());
        }
        withAssertion("/introspect").then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));
    }
}
