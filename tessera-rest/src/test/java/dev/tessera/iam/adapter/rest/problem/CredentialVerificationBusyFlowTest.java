package dev.tessera.iam.adapter.rest.problem;

import static io.restassured.RestAssured.given;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Over HTTP, a saturated verifier is a 503 with Retry-After on every credential endpoint, never an OAuth error. */
@QuarkusTest
@TestProfile(CredentialVerificationBusyFlowTest.BusyVerifier.class)
@DisplayName("Saturated credential verification — 503 on /token, /introspect and /revoke")
class CredentialVerificationBusyFlowTest {

    public static class BusyVerifier implements QuarkusTestProfile {
        @Override
        public String getConfigProfile() {
            return "test,busy-verifier";
        }
    }

    @Test
    @DisplayName("each credential endpoint answers 503 problem+json with Retry-After")
    void busyIsServiceUnavailableEverywhere() {
        for (String endpoint : new String[] {"/token", "/introspect", "/revoke"}) {
            given().header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                    .contentType("application/x-www-form-urlencoded")
                    .formParam("grant_type", "client_credentials")
                    .formParam("token", "a.b.c")
                    .formParam("client_id", FakeClientRepository.MACHINE_CLIENT_ID)
                    .formParam("client_secret", "any")
                    .when().post(endpoint)
                    .then().statusCode(503)
                    .contentType(ProblemResponse.MEDIA_TYPE)
                    .header("Retry-After", "1")
                    .header("Cache-Control", "no-store");
        }
    }
}
