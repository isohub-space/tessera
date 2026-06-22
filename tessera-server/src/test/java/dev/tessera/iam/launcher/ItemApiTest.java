package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * End-to-end {@code @QuarkusTest}: boots the full application (REST resource +
 * in-memory persistence adapter, discovered across modules via Jandex) and
 * exercises the read API plus RFC 7807 error handling. This is the
 * sample placeholder surface — replaced by the real OIDC endpoints in the
 * protocol stories.
 */
@QuarkusTest
@DisplayName("IAM service — item API + health (end-to-end)")
class ItemApiTest {

    @Test
    @DisplayName("GET /q/health reports UP")
    void healthIsUp() {
        given().when().get("/q/health").then().statusCode(200).body("status", equalTo("UP"));
    }

    @Test
    @DisplayName("GET /api/v1/items lists the seeded items")
    void listItems() {
        given()
                .when()
                .get("/api/v1/items")
                .then()
                .statusCode(200)
                .body("size()", greaterThanOrEqualTo(2))
                .body("[0].name", equalTo("First Sample"));
    }

    @Test
    @DisplayName("GET /api/v1/items/{id} returns a seeded item")
    void getKnownItem() {
        given()
                .when()
                .get("/api/v1/items/00000000-0000-0000-0000-000000000001")
                .then()
                .statusCode(200)
                .body("name", equalTo("First Sample"));
    }

    @Test
    @DisplayName("GET /api/v1/items/{id} for an unknown id returns RFC 7807 404")
    void getUnknownItem() {
        given()
                .when()
                .get("/api/v1/items/99999999-9999-9999-9999-999999999999")
                .then()
                .statusCode(404)
                .contentType("application/problem+json")
                .body("title", equalTo("Item Not Found"));
    }

    @Test
    @DisplayName("GET /api/v1/items/{id} for a malformed id returns RFC 7807 400")
    void rejectsMalformedId() {
        given()
                .when()
                .get("/api/v1/items/not-a-uuid")
                .then()
                .statusCode(400)
                .contentType("application/problem+json");
    }
}
