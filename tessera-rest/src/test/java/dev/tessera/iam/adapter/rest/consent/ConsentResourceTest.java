package dev.tessera.iam.adapter.rest.consent;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.application.port.in.ConsentUseCase;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** {@code POST /consent} — records consent for an already-authenticated subject. */
@QuarkusTest
@DisplayName("POST /consent — records per-(subject, client) consent")
class ConsentResourceTest {

    @Inject
    ConsentUseCase consentUseCase;

    @Test
    @DisplayName("a request with X-Subject-Id records consent, visible via ConsentUseCase")
    void recordsConsent() {
        String tenant = UUID.randomUUID().toString();
        String subject = "sub-consent-1";

        given().header("X-Tenant-Id", tenant)
                .header("X-Subject-Id", subject)
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", FakeClientRepository.CONFIDENTIAL_IDENTITY.value().toString())
                .formParam("scope", "openid profile")
                .when().post("/consent")
                .then().statusCode(204);

        // The zero baseline is the convention when no X-Baseline-Id header is sent (see
        // TenantHeaders), which is what this test's requests do.
        RealmKey realm = new RealmKey(new TenantId(UUID.fromString(tenant)), new BaselineId(new UUID(0L, 0L)));
        boolean covered = consentUseCase
                .hasConsented(realm, subject, FakeClientRepository.CONFIDENTIAL_IDENTITY, Set.of("openid"))
                .await().indefinitely();
        assertThat(covered).isTrue();
    }

    @Test
    @DisplayName("no X-Subject-Id is access_denied — the same refusal shape as /authorize with no subject")
    void noSubjectIsAccessDenied() {
        given().header("X-Tenant-Id", UUID.randomUUID().toString())
                .contentType("application/x-www-form-urlencoded")
                .formParam("client_id", FakeClientRepository.CONFIDENTIAL_IDENTITY.value().toString())
                .formParam("scope", "openid")
                .when().post("/consent")
                .then().statusCode(401).body("error", org.hamcrest.Matchers.equalTo("access_denied"));
    }

    @Test
    @DisplayName("a missing client_id is a 400")
    void missingClientIdIsBadRequest() {
        given().header("X-Tenant-Id", UUID.randomUUID().toString())
                .header("X-Subject-Id", "sub-1")
                .contentType("application/x-www-form-urlencoded")
                .formParam("scope", "openid")
                .when().post("/consent")
                .then().statusCode(400);
    }
}
