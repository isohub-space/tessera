package dev.tessera.iam.adapter.rest.ratelimit;

import static io.restassured.RestAssured.given;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Boots the REST adapter with the limiter <em>enabled</em> and tiny caps (via {@link Profile}) and
 * proves the ingress throttle: after the bucket drains a request is refused with a
 * {@code 429 application/problem+json} carrying {@code Retry-After}, and buckets are independent
 * per tenant. Each test uses a fresh random tenant so the app-scoped buckets don't leak between
 * methods.
 */
@QuarkusTest
@TestProfile(RateLimitFilterTest.Profile.class)
@DisplayName("RateLimitFilter — ingress throttling on /authorize and /token")
class RateLimitFilterTest {

    /** capacity 3, negligible refill — so a 4th request in a burst is always refused. */
    public static class Profile implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of(
                    "iam.ratelimit.enabled", "true",
                    "iam.ratelimit.authorize-capacity", "3",
                    "iam.ratelimit.authorize-refill-per-minute", "1",
                    "iam.ratelimit.token-capacity", "3",
                    "iam.ratelimit.token-refill-per-minute", "1");
        }
    }

    @Test
    @DisplayName("/authorize: the 4th request in a burst is 429 problem+json with Retry-After")
    void authorizeThrottled() {
        String tenant = UUID.randomUUID().toString();
        for (int i = 0; i < 3; i++) {
            authorize(tenant, FakeClientRepository.PUBLIC_CLIENT_ID)
                    .then().statusCode(Matchers.not(429));
        }
        authorize(tenant, FakeClientRepository.PUBLIC_CLIENT_ID)
                .then().statusCode(429)
                .contentType("application/problem+json")
                .header("Retry-After", Matchers.notNullValue())
                .body("status", Matchers.equalTo(429));
    }

    @Test
    @DisplayName("a different tenant keeps its own fresh allowance")
    void perTenantIndependent() {
        String drained = UUID.randomUUID().toString();
        for (int i = 0; i < 4; i++) {
            authorize(drained, FakeClientRepository.PUBLIC_CLIENT_ID);
        }
        // The drained tenant is now throttled...
        authorize(drained, FakeClientRepository.PUBLIC_CLIENT_ID).then().statusCode(429);
        // ...but a different tenant is unaffected.
        authorize(UUID.randomUUID().toString(), FakeClientRepository.PUBLIC_CLIENT_ID)
                .then().statusCode(Matchers.not(429));
    }

    @Test
    @DisplayName("/token: the 4th HTTP-Basic request in a burst is 429 with no-store")
    void tokenThrottled() {
        String tenant = UUID.randomUUID().toString();
        String basic = "Basic " + Base64.getEncoder()
                .encodeToString(("client-x:secret").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        for (int i = 0; i < 3; i++) {
            postToken(tenant, basic).then().statusCode(Matchers.not(429));
        }
        postToken(tenant, basic).then().statusCode(429)
                .contentType("application/problem+json")
                .header("Cache-Control", "no-store")
                .header("Retry-After", Matchers.notNullValue());
    }

    // ------------------------------------------------------------------- helpers

    private static io.restassured.response.Response authorize(String tenant, String clientId) {
        // Deliberately minimal: the request need not be well-formed — the limiter runs before the
        // resource, so a throttled request is 429 and an allowed one is some 4xx from the resource
        // (never 429). Only the 429/not-429 distinction is under test.
        return given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .queryParam("client_id", clientId)
                .when().get("/authorize");
    }

    private static io.restassured.response.Response postToken(String tenant, String basicAuth) {
        return given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("Authorization", basicAuth)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "authorization_code")
                .when().post("/token");
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }
}
