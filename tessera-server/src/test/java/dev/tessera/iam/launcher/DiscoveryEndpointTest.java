package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.not;

import io.quarkus.test.junit.QuarkusTest;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Boots the assembly (no datasource needed — discovery reads only configuration) and
 * exercises the OIDC discovery endpoint: the document is generated from the enforced
 * capability set, so it never advertises a capability the server does not enforce, and
 * the issuer is the configured value rather than the request Host.
 */
@QuarkusTest
@DisplayName("OIDC discovery endpoint — generated from the enforced capability set")
class DiscoveryEndpointTest {

    private static final String CONFIGURED_ISSUER = "https://issuer.test.example";

    @Test
    @DisplayName("issuer is the CONFIGURED value, never the request Host header")
    void issuerIsConfiguredNotHost() {
        given()
                .header("X-Tenant-Id", UUID.randomUUID().toString())
                // A spoofed Host must not influence the advertised issuer.
                .header("Host", "evil.attacker.example")
                .when()
                .get("/.well-known/openid-configuration")
                .then()
                .statusCode(200)
                .body("issuer", equalTo(CONFIGURED_ISSUER))
                .body("jwks_uri", equalTo(CONFIGURED_ISSUER + "/jwks"))
                .body("token_endpoint", equalTo(CONFIGURED_ISSUER + "/token"))
                .body("authorization_endpoint", equalTo(CONFIGURED_ISSUER + "/authorize"))
                .body("userinfo_endpoint", equalTo(CONFIGURED_ISSUER + "/userinfo"));
    }

    @Test
    @DisplayName("a disabled capability never appears; the enforced one does")
    void disabledCapabilitiesNeverAppear() {
        String body = given()
                .header("X-Tenant-Id", UUID.randomUUID().toString())
                .when()
                .get("/.well-known/openid-configuration")
                .then()
                .statusCode(200)
                // Code-flow + PKCE S256 are enforced and advertised.
                .body("grant_types_supported", hasItem("authorization_code"))
                .body("code_challenge_methods_supported", contains("S256"))
                .extract()
                .asString();

        // Insecure capabilities must not appear anywhere in the document.
        org.assertj.core.api.Assertions.assertThat(body)
                .doesNotContain("implicit")
                .doesNotContain("password")
                .doesNotContain("plain")
                .contains("S256")
                .contains("authorization_code");
    }

    @Test
    @DisplayName("no symmetric HS* signing algorithm is ever advertised")
    void noSymmetricSigningAlg() {
        given()
                .header("X-Tenant-Id", UUID.randomUUID().toString())
                .when()
                .get("/.well-known/openid-configuration")
                .then()
                .statusCode(200)
                .body("id_token_signing_alg_values_supported", contains("EdDSA", "ES256"))
                .body("id_token_signing_alg_values_supported", not(hasItem(containsString("HS"))));
    }

    @Test
    @DisplayName("the discovery response carries a Cache-Control max-age")
    void cacheControlHeaderPresent() {
        given()
                .header("X-Tenant-Id", UUID.randomUUID().toString())
                .when()
                .get("/.well-known/openid-configuration")
                .then()
                .statusCode(200)
                .header("Cache-Control", containsString("max-age="));
    }
}
