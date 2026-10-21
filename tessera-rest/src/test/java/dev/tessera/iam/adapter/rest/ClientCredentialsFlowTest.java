package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code POST /token} with {@code grant_type=client_credentials} (RFC 6749 §4.4), end to end over
 * HTTP: the client authenticates with {@code client_secret_basic} or {@code client_secret_post}
 * and gets an access token for itself, bound to its tenant, that introspects as active.
 */
@QuarkusTest
@DisplayName("POST /token — client_credentials grant (RFC 6749 §4.4)")
class ClientCredentialsFlowTest extends AuthorizationCodeFlowSupport {

    private static final String CLIENT = FakeClientRepository.MACHINE_CLIENT_ID;
    private static final String SECRET = FakeClientSecretVerifier.CORRECT_SECRET;
    private static final String MACHINE_TENANT = FakeClientRepository.MACHINE_TENANT;

    private static RequestSpecification request(String tenant) {
        return given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials");
    }

    private static String basic(String clientId, String secret) {
        return "Basic " + Base64.getEncoder()
                .encodeToString((clientId + ":" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private static Response withBasic(String tenant, String clientId, String secret) {
        return request(tenant).header("Authorization", basic(clientId, secret)).when().post("/token");
    }

    @Test
    @SuppressWarnings("unchecked")
    @DisplayName("client_secret_basic: a token for the client itself, with its scopes, audiences, roles and tenant")
    void issuesATokenWithBasicAuthentication() {
        Response response = withBasic(MACHINE_TENANT, CLIENT, SECRET);
        response.then().statusCode(200)
                .header("Cache-Control", "no-store")
                .body("token_type", Matchers.equalTo("Bearer"))
                .body("expires_in", Matchers.equalTo(300))
                .body("scope", Matchers.equalTo("orders.read orders.write"))
                .body("refresh_token", Matchers.nullValue())
                .body("id_token", Matchers.nullValue());

        String accessToken = response.jsonPath().getString("access_token");
        assertThat(jsonPart(accessToken, 0)).containsEntry("typ", "at+jwt");
        Map<String, Object> claims = jsonPart(accessToken, 1);
        assertThat(claims)
                .containsEntry("iss", ISSUER)
                .containsEntry("sub", CLIENT)
                .containsEntry("client_id", CLIENT)
                .containsEntry("roles", FakeClientRepository.MACHINE_ROLES)
                .containsEntry("realm_tenant", MACHINE_TENANT)
                .containsEntry("realm_baseline", new UUID(0L, 0L).toString());
        assertThat((List<Object>) claims.get("aud"))
                .containsExactlyElementsOf(List.copyOf(FakeClientRepository.MACHINE_AUDIENCES));
        assertThat((Map<String, Object>) claims.get("cnf"))
                .containsEntry("x5t#S256", TestClientCertificate.X5T_S256);
    }

    @Test
    @DisplayName("client_secret_post authenticates the same client")
    void issuesATokenWithPostAuthentication() {
        request(MACHINE_TENANT).formParam("client_id", CLIENT).formParam("client_secret", SECRET)
                .when().post("/token")
                .then().statusCode(200).body("access_token", Matchers.notNullValue());
    }

    @Test
    @DisplayName("scope and resource narrow the token; outside the registration they are invalid_scope / invalid_target")
    void scopeAndResourceNarrowButNeverWiden() {
        Response narrowed = request(MACHINE_TENANT).header("Authorization", basic(CLIENT, SECRET))
                .formParam("scope", "orders.read")
                .formParam("resource", "https://orders.example")
                .when().post("/token");
        narrowed.then().statusCode(200).body("scope", Matchers.equalTo("orders.read"));
        assertThat(jsonPart(narrowed.jsonPath().getString("access_token"), 1))
                .containsEntry("aud", "https://orders.example");

        request(MACHINE_TENANT).header("Authorization", basic(CLIENT, SECRET)).formParam("scope", "admin")
                .when().post("/token")
                .then().statusCode(400).body("error", Matchers.equalTo("invalid_scope"));
        request(MACHINE_TENANT).header("Authorization", basic(CLIENT, SECRET))
                .formParam("resource", "https://elsewhere.example")
                .when().post("/token")
                .then().statusCode(400).body("error", Matchers.equalTo("invalid_target"));
    }

    @Test
    @DisplayName("unknown client, wrong secret, no credentials and a public client are invalid_client (401)")
    void clientAuthenticationFailures() {
        withBasic(MACHINE_TENANT, "nobody", SECRET).then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
        withBasic(MACHINE_TENANT, CLIENT, "wrong").then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
        request(MACHINE_TENANT).when().post("/token").then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
        request(MACHINE_TENANT).formParam("client_id", FakeClientRepository.PUBLIC_CLIENT_ID)
                .when().post("/token").then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
    }

    @Test
    @DisplayName("a client not registered for the grant is unauthorized_client")
    void unauthorizedClients() {
        withBasic(MACHINE_TENANT, FakeClientRepository.CONFIDENTIAL_CLIENT_ID, SECRET).then().statusCode(400)
                .body("error", Matchers.equalTo("unauthorized_client"));
    }

    @Test
    @DisplayName("the client of one tenant gets no token under another tenant")
    void clientIsBoundToItsTenant() {
        withBasic(UUID.randomUUID().toString(), CLIENT, SECRET).then().statusCode(401)
                .body("error", Matchers.equalTo("invalid_client"));
        withBasic(MACHINE_TENANT, CLIENT, SECRET).then().statusCode(200);
    }

    @Test
    @DisplayName("without a client certificate the request is refused while sender-constraint is required")
    void certificateIsRequiredByDefault() {
        given().config(noFollow())
                .header("X-Tenant-Id", MACHINE_TENANT)
                .header("Authorization", basic(CLIENT, SECRET))
                .contentType("application/x-www-form-urlencoded")
                .formParam("grant_type", "client_credentials")
                .when().post("/token")
                .then().statusCode(400).body("error", Matchers.equalTo("invalid_request"));
    }

    @Test
    @DisplayName("the token introspects as active; revoking it is accepted and leaves it active until expiry")
    void introspectionAndRevocation() {
        String accessToken = withBasic(MACHINE_TENANT, CLIENT, SECRET).jsonPath().getString("access_token");

        given().config(noFollow())
                .header("X-Tenant-Id", MACHINE_TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", accessToken)
                .formParam("client_id", CLIENT).formParam("client_secret", SECRET)
                .when().post("/introspect")
                .then().statusCode(200)
                .body("active", Matchers.is(true))
                .body("sub", Matchers.equalTo(CLIENT))
                .body("client_id", Matchers.equalTo(CLIENT))
                .body("scope", Matchers.equalTo("orders.read orders.write"));

        given().config(noFollow())
                .header("X-Tenant-Id", MACHINE_TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", accessToken)
                .formParam("client_id", CLIENT).formParam("client_secret", SECRET)
                .when().post("/revoke")
                .then().statusCode(200);

        // Revocation is a no-op for a self-contained access token: it stays active until it expires.
        given().config(noFollow())
                .header("X-Tenant-Id", MACHINE_TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", accessToken)
                .formParam("client_id", CLIENT).formParam("client_secret", SECRET)
                .when().post("/introspect")
                .then().statusCode(200).body("active", Matchers.is(true));
    }

    @Test
    @DisplayName("discovery advertises client_credentials while the grant is enabled")
    void discoveryAdvertisesTheGrant() {
        given().header("X-Tenant-Id", MACHINE_TENANT)
                .when().get("/.well-known/openid-configuration")
                .then().statusCode(200)
                .body("grant_types_supported", Matchers.hasItem("client_credentials"));
    }
}
