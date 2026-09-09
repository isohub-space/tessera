package dev.tessera.iam.adapter.rest.login;

import static io.restassured.RestAssured.given;

import dev.tessera.iam.adapter.rest.support.FakePasswordCredentialVerifier;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.response.Response;
import java.util.Map;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the login path reuses the existing credential failure-budget throttle
 * ({@link dev.tessera.iam.adapter.rest.ratelimit.ThrottlingPasswordCredentialVerifier}, the
 * same mechanism as the client-secret path's
 * {@code ThrottlingClientSecretVerifier}/{@code CredentialThrottleTest}) rather than a second
 * one. With a failure burst of 3 and a negligible refill, after three wrong passwords for one
 * {@code (tenant, username)} the budget is spent, so the next attempt short-circuits to
 * {@code invalid_credentials} <em>without invoking the delegate verifier</em> — proven
 * behaviourally exactly as {@code CredentialThrottleTest} proves it for {@code /token}: once
 * spent, even the CORRECT password is refused.
 */
@QuarkusTest
@TestProfile(LoginThrottleTest.Profile.class)
@DisplayName("ThrottlingPasswordCredentialVerifier — failure budget short-circuits the login path")
class LoginThrottleTest {

    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "iam.ratelimit.enabled", "true",
                    "iam.ratelimit.credential-failure-burst", "3",
                    "iam.ratelimit.credential-refill-per-minute", "1",
                    "iam.ratelimit.authorize-capacity", "100",
                    "iam.ratelimit.token-capacity", "100");
        }
    }

    @Test
    @DisplayName("after the failure budget is spent, even the correct password is refused (delegate bypassed)")
    void spentBudgetBypassesDelegate() {
        String tenant = UUID.randomUUID().toString();

        for (int i = 0; i < 3; i++) {
            login(tenant, FakePasswordCredentialVerifier.USERNAME, "wrong-" + i)
                    .then().statusCode(401).body("error", Matchers.equalTo("invalid_credentials"));
        }

        login(tenant, FakePasswordCredentialVerifier.USERNAME, FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .then().statusCode(401).body("error", Matchers.equalTo("invalid_credentials"));
    }

    @Test
    @DisplayName("a different tenant is not affected by another tenant's spent budget")
    void throttleIsPerTenant() {
        String throttled = UUID.randomUUID().toString();
        for (int i = 0; i < 3; i++) {
            login(throttled, FakePasswordCredentialVerifier.USERNAME, "nope-" + i);
        }
        login(throttled, FakePasswordCredentialVerifier.USERNAME, FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .then().statusCode(401);

        login(UUID.randomUUID().toString(), FakePasswordCredentialVerifier.USERNAME,
                FakePasswordCredentialVerifier.CORRECT_PASSWORD)
                .then().statusCode(204);
    }

    private static Response login(String tenant, String username, String password) {
        return given().header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded")
                .formParam("username", username)
                .formParam("password", password)
                .when().post("/login");
    }
}
