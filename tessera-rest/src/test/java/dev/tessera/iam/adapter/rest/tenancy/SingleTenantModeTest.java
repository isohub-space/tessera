package dev.tessera.iam.adapter.rest.tenancy;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.containsString;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.restassured.RestAssured;
import io.restassured.config.RedirectConfig;
import io.restassured.config.RestAssuredConfig;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Single-tenant mode ({@code iam.tenancy.fixed-tenant} set): every tenant-scoped route binds
 * the fixed tenant and the ingress headers are ignored — a request with no
 * {@code X-Tenant-Id}, or a malformed one, is served under the fixed tenant instead of being
 * refused, and a caller cannot select another tenant by sending one.
 */
@QuarkusTest
@TestProfile(SingleTenantModeTest.FixedTenant.class)
@DisplayName("Single-tenant mode — the fixed tenant replaces the ingress headers")
class SingleTenantModeTest {

    static final String FIXED = "33333333-3333-4333-8333-333333333333";

    public static class FixedTenant implements QuarkusTestProfile {
        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.of("iam.tenancy.fixed-tenant", FIXED);
        }
    }

    @Test
    @DisplayName("discovery is served with no tenant header at all")
    void discoveryWithoutHeader() {
        given().when().get("/.well-known/openid-configuration")
                .then().statusCode(200)
                .body("issuer", not(equalTo("")));
    }

    @Test
    @DisplayName("a malformed X-Tenant-Id is ignored rather than rejected")
    void malformedHeaderIgnored() {
        given().header("X-Tenant-Id", "not-a-uuid")
                .when().get("/.well-known/jwks.json")
                .then().statusCode(200);
    }

    @Test
    @DisplayName("/authorize runs under the fixed tenant: the tenant chokepoint no longer refuses, the flow does")
    void authorizeBindsFixedTenant() {
        // With no session there is no subject, so the flow answers access_denied as JSON —
        // never the problem+json 400 the tenant chokepoint emits for a missing header.
        given().config(noFollow())
                .header("X-Tenant-Id", UUID.randomUUID().toString())
                .queryParam("response_type", "code")
                .queryParam("client_id", "confidential-web")
                .queryParam("redirect_uri", "https://client.example/callback")
                .queryParam("scope", "openid")
                .queryParam("state", "s")
                .queryParam("nonce", "n")
                .queryParam("code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
                .queryParam("code_challenge_method", "S256")
                .when().get("/authorize")
                .then().statusCode(400)
                .contentType(not(containsString("problem+json")))
                .body("error", equalTo("access_denied"));
    }

    private static RestAssuredConfig noFollow() {
        return RestAssured.config().redirect(RedirectConfig.redirectConfig().followRedirects(false));
    }
}
