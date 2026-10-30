// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;

import dev.tessera.iam.adapter.rest.support.AssertionTestClient;
import dev.tessera.iam.adapter.rest.support.FakeClientKeySource;
import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.adapter.rest.support.TestClientCertificate;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.application.refresh.RefreshTokenCodec;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import io.restassured.specification.RequestSpecification;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code POST /revoke} and {@code POST /introspect} with a JWT client assertion (RFC 7523 §2.2): a
 * {@code private_key_jwt} client authenticates there exactly as at {@code /token}, through the same
 * verifier and its replay store, within the request's realm. A refresh family is revoked only for the
 * client it was issued to.
 *
 * <p>No grant issues a refresh token to an assertion client yet, so its families are created in the
 * store directly, as the authorization-code grant would create them.
 */
@QuarkusTest
@DisplayName("POST /revoke and /introspect — private_key_jwt client authentication (RFC 7523)")
class AssertionClientRevokeIntrospectFlowTest extends AuthorizationCodeFlowSupport {

    private static final String JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final String TENANT_OF_CLIENT = FakeClientRepository.MACHINE_TENANT;
    private static final String KEYED = FakeClientRepository.KEYED_CLIENT_ID;
    private static final RealmKey CLIENT_REALM =
            new RealmKey(TenantId.fromString(TENANT_OF_CLIENT), new BaselineId(new UUID(0L, 0L)));

    @Inject
    RefreshTokenStorePort refreshStore;

    private static String assertion() {
        return FakeClientKeySource.CLIENT.sign(AssertionTestClient.claims(KEYED, ISSUER, Instant.now()).build());
    }

    private static RequestSpecification form(String tenant) {
        return given().config(noFollow())
                .header("X-Tenant-Id", tenant)
                .contentType("application/x-www-form-urlencoded");
    }

    private static Response withAssertion(String tenant, String endpoint, String assertion, String token) {
        return form(tenant)
                .formParam("token", token)
                .formParam("client_assertion_type", JWT_BEARER)
                .formParam("client_assertion", assertion)
                .when().post(endpoint);
    }

    /** A live refresh family of {@code owner} in the keyed client's realm, as its wire token. */
    private String refreshTokenOf(ClientId owner) {
        FamilyId id = new FamilyId(UUID.randomUUID());
        String secret = UUID.randomUUID().toString().replace("-", "");
        Instant now = Instant.now();
        refreshStore.createFamily(new RefreshTokenFamily(id, CLIENT_REALM, UUID.randomUUID().toString(), owner,
                RefreshTokenCodec.sha256(secret), null, 0, false, now, now.plus(Duration.ofHours(1))))
                .await().indefinitely();
        return RefreshTokenCodec.assemble(id, secret);
    }

    private static Response introspectAsMachine(String token) {
        return form(TENANT_OF_CLIENT)
                .formParam("token", token)
                .formParam("client_id", FakeClientRepository.MACHINE_CLIENT_ID)
                .formParam("client_secret", FakeClientSecretVerifier.CORRECT_SECRET)
                .when().post("/introspect");
    }

    @Test
    @DisplayName("an assertion client revokes its refresh token: 200, empty, and the family is no longer active")
    void assertionClientRevokesItsRefreshToken() {
        String refresh = refreshTokenOf(FakeClientRepository.KEYED_IDENTITY);
        withAssertion(TENANT_OF_CLIENT, "/introspect", assertion(), refresh).then()
                .statusCode(200).body("active", Matchers.is(true));

        withAssertion(TENANT_OF_CLIENT, "/revoke", assertion(), refresh).then()
                .statusCode(200).header("Cache-Control", "no-store").body(Matchers.emptyOrNullString());

        withAssertion(TENANT_OF_CLIENT, "/introspect", assertion(), refresh).then()
                .statusCode(200).body("active", Matchers.is(false));
        introspectAsMachine(refresh).then().statusCode(200).body("active", Matchers.is(false));
    }

    @Test
    @DisplayName("an assertion client cannot revoke another client's refresh token (RFC 7009 §2.1): 200 and a no-op")
    void otherClientsRefreshTokenIsKept() {
        String othersRefresh = refreshTokenOf(FakeClientRepository.MACHINE_IDENTITY);

        withAssertion(TENANT_OF_CLIENT, "/revoke", assertion(), othersRefresh).then()
                .statusCode(200).body(Matchers.emptyOrNullString());

        introspectAsMachine(othersRefresh).then().statusCode(200).body("active", Matchers.is(true));
    }

    @Test
    @DisplayName("an assertion client introspects its client_credentials access token, client_id optional")
    void assertionClientIntrospectsAToken() {
        String accessToken = form(TENANT_OF_CLIENT)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .formParam("grant_type", "client_credentials")
                .formParam("client_assertion_type", JWT_BEARER)
                .formParam("client_assertion", assertion())
                .when().post("/token")
                .then().statusCode(200).extract().jsonPath().getString("access_token");

        withAssertion(TENANT_OF_CLIENT, "/introspect", assertion(), accessToken).then()
                .statusCode(200).header("Cache-Control", "no-store")
                .body("active", Matchers.is(true))
                .body("client_id", Matchers.equalTo(KEYED))
                .body("sub", Matchers.equalTo(KEYED));

        form(TENANT_OF_CLIENT)
                .formParam("token", accessToken)
                .formParam("client_id", KEYED)
                .formParam("client_assertion_type", JWT_BEARER)
                .formParam("client_assertion", assertion())
                .when().post("/introspect")
                .then().statusCode(200).body("active", Matchers.is(true));
    }

    @Test
    @DisplayName("a replayed assertion is refused on /introspect and /revoke, also after its first use at /token")
    void replayedAssertionIsRefused() {
        String refresh = refreshTokenOf(FakeClientRepository.KEYED_IDENTITY);

        String used = assertion();
        withAssertion(TENANT_OF_CLIENT, "/introspect", used, refresh).then().statusCode(200);
        withAssertion(TENANT_OF_CLIENT, "/introspect", used, refresh).then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));
        withAssertion(TENANT_OF_CLIENT, "/revoke", used, refresh).then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));

        // The token endpoint and these two share one replay store.
        String spentAtToken = assertion();
        form(TENANT_OF_CLIENT)
                .header("X-Client-Certificate", TestClientCertificate.PEM)
                .formParam("grant_type", "client_credentials")
                .formParam("client_assertion_type", JWT_BEARER)
                .formParam("client_assertion", spentAtToken)
                .when().post("/token").then().statusCode(200);
        withAssertion(TENANT_OF_CLIENT, "/revoke", spentAtToken, refresh).then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));
        withAssertion(TENANT_OF_CLIENT, "/introspect", spentAtToken, refresh).then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));

        // None of the refused requests revoked the family.
        introspectAsMachine(refresh).then().statusCode(200).body("active", Matchers.is(true));
    }

    @Test
    @DisplayName("an assertion presented in another realm is refused: the client does not exist there")
    void wrongRealmAssertionIsRefused() {
        String refresh = refreshTokenOf(FakeClientRepository.KEYED_IDENTITY);
        String otherTenant = UUID.randomUUID().toString();

        withAssertion(otherTenant, "/revoke", assertion(), refresh).then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));
        withAssertion(otherTenant, "/introspect", assertion(), refresh).then()
                .statusCode(401).body("error", Matchers.equalTo("invalid_client"));

        introspectAsMachine(refresh).then().statusCode(200).body("active", Matchers.is(true));
    }

    @Test
    @DisplayName("an assertion with a secret is invalid_request; a wrong assertion type or a public client's assertion is invalid_client")
    void malformedPresentationsAreRefused() {
        for (String endpoint : new String[] {"/introspect", "/revoke"}) {
            form(TENANT_OF_CLIENT)
                    .formParam("token", "a.b.c")
                    .formParam("client_secret", FakeClientSecretVerifier.CORRECT_SECRET)
                    .formParam("client_assertion_type", JWT_BEARER)
                    .formParam("client_assertion", assertion())
                    .when().post(endpoint)
                    .then().statusCode(400).header("Cache-Control", "no-store")
                    .body("error", Matchers.equalTo("invalid_request"));
            form(TENANT_OF_CLIENT)
                    .formParam("token", "a.b.c")
                    .formParam("client_assertion_type", "urn:other")
                    .formParam("client_assertion", assertion())
                    .when().post(endpoint)
                    .then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));
            form(TENANT_OF_CLIENT)
                    .formParam("token", "a.b.c")
                    .formParam("client_id", FakeClientRepository.PUBLIC_CLIENT_ID)
                    .formParam("client_assertion_type", JWT_BEARER)
                    .formParam("client_assertion", assertion())
                    .when().post(endpoint)
                    .then().statusCode(401).body("error", Matchers.equalTo("invalid_client"));
        }
    }
}
