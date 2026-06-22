package dev.tessera.iam.launcher;

import static io.restassured.RestAssured.given;

import io.quarkus.test.junit.QuarkusTest;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import jakarta.inject.Inject;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Guards the publish-before-sign cache margin: the JWKS / discovery
 * {@code Cache-Control} max-age must be strictly less than the PENDING dwell, so a
 * verifier's cached key set always expires — forcing a re-fetch that picks up a
 * {@code PENDING} key — before that key is promoted to {@code ACTIVE} and signs.
 */
@QuarkusTest
@DisplayName("Cache TTL is strictly less than the PENDING dwell (publish-before-sign margin)")
class JwksCacheTtlVsDwellTest {

    private static final Pattern MAX_AGE = Pattern.compile("max-age=(\\d+)");

    @Inject
    OidcDiscoveryConfig config;

    @Test
    @DisplayName("configured cache TTL < configured PENDING dwell")
    void ttlLessThanDwell() {
        Assertions.assertThat(config.jwks().cacheTtlSeconds())
                .as("JWKS cache TTL must be strictly below the PENDING dwell")
                .isLessThan(config.pendingDwellSeconds());
    }

    @Test
    @DisplayName("the served Cache-Control max-age is strictly less than the PENDING dwell")
    void servedMaxAgeLessThanDwell() {
        String cacheControl = given()
                .header("X-Tenant-Id", UUID.randomUUID().toString())
                .when()
                .get("/.well-known/openid-configuration")
                .then()
                .statusCode(200)
                .extract()
                .header("Cache-Control");

        Matcher m = MAX_AGE.matcher(cacheControl);
        Assertions.assertThat(m.find()).as("Cache-Control carries a max-age").isTrue();
        long maxAge = Long.parseLong(m.group(1));
        Assertions.assertThat(maxAge).isLessThan(config.pendingDwellSeconds());
    }
}
