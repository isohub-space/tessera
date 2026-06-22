package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import dev.tessera.iam.adapter.persistence.signingkey.KeyRotationService;
import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Boots the full assembly over a real PostgreSQL and exercises the JWKS endpoint:
 * a seeded realm's published (ACTIVE + RETIRING) public keys are served as a JWK Set,
 * and no private material ever appears in the document.
 */
@QuarkusTest
@TestProfile(DatabaseBackedProfile.class)
@QuarkusTestResource(value = PostgresLauncherTestResource.class, restrictToAnnotatedClass = true)
@DisplayName("JWKS endpoint — serves published public keys, never private material")
class JwksEndpointIT {

    @Inject
    KeyRotationService rotation;

    private static RealmKey realm(UUID tenant) {
        return new RealmKey(new TenantId(tenant), new BaselineId(new UUID(0L, 0L)));
    }

    @Test
    @DisplayName("GET /jwks returns the ACTIVE key as an OKP/Ed25519 JWK, no private members")
    void jwksServesPublishedKey() {
        UUID tenant = UUID.randomUUID();
        RealmKey realm = realm(tenant);
        // Seed a realm with one ACTIVE key (mint PENDING, then promote).
        rotation.mintPending(realm, KeyId.of("active-kid"))
                .chain(() -> rotation.promoteToActive(
                        realm, KeyId.of("active-kid"), Instant.parse("2026-06-22T10:00:00Z")))
                .await().atMost(Duration.ofSeconds(30));

        given()
                .header("X-Tenant-Id", tenant.toString())
                .when()
                .get("/jwks")
                .then()
                .statusCode(200)
                .body("keys.kid", contains("active-kid"))
                .body("keys.kty", everyItem(equalTo("OKP")))
                .body("keys.crv", everyItem(equalTo("Ed25519")))
                .body("keys.alg", everyItem(equalTo("EdDSA")))
                .body("keys.use", everyItem(equalTo("sig")))
                .body("keys.x", everyItem(notNullValue()))
                // No private members are ever serialised.
                .body("keys.d", everyItem(nullValue()));
    }

    @Test
    @DisplayName("the well-known alias /.well-known/jwks.json serves the same document")
    void wellKnownAliasServesJwks() {
        UUID tenant = UUID.randomUUID();
        RealmKey realm = realm(tenant);
        rotation.mintPending(realm, KeyId.of("wk-kid"))
                .chain(() -> rotation.promoteToActive(realm, KeyId.of("wk-kid"), Instant.now()))
                .await().atMost(Duration.ofSeconds(30));

        given()
                .header("X-Tenant-Id", tenant.toString())
                .when()
                .get("/.well-known/jwks.json")
                .then()
                .statusCode(200)
                .body("keys.kid", contains("wk-kid"));
    }

    @Test
    @DisplayName("a PENDING key is published before it signs (publish-before-sign)")
    void pendingKeyIsPublishedBeforeSigning() {
        UUID tenant = UUID.randomUUID();
        RealmKey realm = realm(tenant);
        // Mint only — the key stays PENDING and has never signed.
        rotation.mintPending(realm, KeyId.of("pending-kid"))
                .await().atMost(Duration.ofSeconds(30));

        given()
                .header("X-Tenant-Id", tenant.toString())
                .when()
                .get("/jwks")
                .then()
                .statusCode(200)
                // The PENDING key is pre-published so verifiers can trust it before it signs.
                .body("keys.kid", contains("pending-kid"))
                .body("keys.use", everyItem(equalTo("sig")))
                .body("keys.d", everyItem(nullValue()));
    }

    @Test
    @DisplayName("a realm with no keys gets an empty JWK Set, and never another realm's keys")
    void emptyRealmIsIsolated() {
        UUID empty = UUID.randomUUID();
        given()
                .header("X-Tenant-Id", empty.toString())
                .when()
                .get("/jwks")
                .then()
                .statusCode(200)
                .body("keys", not(contains("active-kid")));
    }
}
