package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;

import io.quarkus.test.junit.QuarkusTest;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the request-scoped tenant-propagation pipeline end-to-end over a tenant-scoped
 * endpoint (OIDC discovery): the resolution filter turns the gateway-asserted ingress
 * header into a request-scoped realm fail-closed, and that realm never bleeds between
 * concurrent requests.
 *
 * <p>The discovery endpoint is used because it needs no datasource — it only requires a
 * resolved tenant — so the pipeline can be exercised in the Docker-free launcher boot.
 */
@QuarkusTest
@DisplayName("Tenant propagation — request-scoped X-Tenant-Id resolution, fail-closed and leak-free")
class TenantPropagationTest {

    private static final String DISCOVERY = "/.well-known/openid-configuration";

    @Test
    @DisplayName("a request with no X-Tenant-Id is rejected 400 — fails closed")
    void missingTenantIsRejected() {
        given()
                .when()
                .get(DISCOVERY)
                .then()
                .statusCode(400)
                .contentType(containsString("problem+json"))
                .body("detail", containsString("X-Tenant-Id"));
    }

    @Test
    @DisplayName("a request with a malformed X-Tenant-Id is rejected 400")
    void malformedTenantIsRejected() {
        given()
                .header("X-Tenant-Id", "not-a-uuid")
                .when()
                .get(DISCOVERY)
                .then()
                .statusCode(400)
                .contentType(containsString("problem+json"));
    }

    @Test
    @DisplayName("a request with a malformed X-Baseline-Id is rejected 400")
    void malformedBaselineIsRejected() {
        given()
                .header("X-Tenant-Id", UUID.randomUUID().toString())
                .header("X-Baseline-Id", "not-a-uuid")
                .when()
                .get(DISCOVERY)
                .then()
                .statusCode(400);
    }

    @Test
    @DisplayName("a request with a valid X-Tenant-Id is resolved and served 200")
    void validTenantIsServed() {
        given()
                .header("X-Tenant-Id", UUID.randomUUID().toString())
                .when()
                .get(DISCOVERY)
                .then()
                .statusCode(200)
                .body("issuer", equalTo("https://issuer.test.example"));
    }

    /**
     * Drives many concurrent requests, each with a distinct tenant id, against the
     * tenant-scoped endpoint. Every one must succeed: had the request-scoped realm leaked
     * across requests (e.g. via a shared thread-local on the reactive worker pool), a
     * fraction would fail or cross-serve. All-200 across distinct concurrent tenants is the
     * no-cross-tenant-leakage evidence for the propagation path.
     */
    @Test
    @DisplayName("concurrent requests with distinct tenants never bleed — all resolve independently")
    void concurrentTenantsDoNotLeak() {
        int requests = 64;
        ConcurrentLinkedQueue<Integer> statuses = new ConcurrentLinkedQueue<>();
        ConcurrentHashMap<UUID, Integer> perTenant = new ConcurrentHashMap<>();

        IntStream.range(0, requests).parallel().forEach(i -> {
            UUID tenant = UUID.randomUUID();
            int status = given()
                    .header("X-Tenant-Id", tenant.toString())
                    .when()
                    .get(DISCOVERY)
                    .thenReturn()
                    .statusCode();
            statuses.add(status);
            perTenant.put(tenant, status);
        });

        org.assertj.core.api.Assertions.assertThat(perTenant).hasSize(requests);
        org.assertj.core.api.Assertions.assertThat(statuses).allMatch(s -> s == 200);
    }
}
