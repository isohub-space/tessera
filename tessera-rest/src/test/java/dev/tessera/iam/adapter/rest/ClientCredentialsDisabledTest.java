package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** With the grant switched off, {@code /token} refuses it and discovery does not advertise it. */
@QuarkusTest
@TestProfile(ClientCredentialsDisabledTest.Disabled.class)
@DisplayName("client_credentials disabled — neither served nor advertised")
class ClientCredentialsDisabledTest {

    public static class Disabled implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("iam.client-credentials.enabled", "false");
        }
    }

    @Test
    @DisplayName("grant_type=client_credentials is unsupported_grant_type")
    void grantIsNotServed() {
        given().header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .formParam("client_id", FakeClientRepository.MACHINE_CLIENT_ID)
                .formParam("client_secret", FakeClientSecretVerifier.CORRECT_SECRET)
                .when().post("/token")
                .then().statusCode(400).body("error", Matchers.equalTo("unsupported_grant_type"));
    }

    @Test
    @DisplayName("discovery does not list client_credentials")
    void grantIsNotAdvertised() {
        given().header("X-Tenant-Id", FakeClientRepository.MACHINE_TENANT)
                .when().get("/.well-known/openid-configuration")
                .then().statusCode(200)
                .body("grant_types_supported", Matchers.not(Matchers.hasItem("client_credentials")));
    }
}
