package dev.tessera.iam.launcher;

import io.quarkus.test.junit.QuarkusTestProfile;
import java.util.Map;

/**
 * Test profile that re-activates the datasource for the Testcontainers-backed JWKS
 * endpoint test.
 *
 * <p>The default {@code %test} configuration runs the Docker-free launcher tests with
 * no datasource (so they boot on the in-memory adapter alone). This profile flips the
 * datasource, Hibernate and Flyway back on, restricts Flyway to the migration location,
 * and enables the signing-key readiness check, so the full DB-backed assembly boots
 * over the container supplied by {@link PostgresLauncherTestResource}.
 */
public class DatabaseBackedProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        return Map.of(
                "quarkus.datasource.active", "true",
                "quarkus.hibernate-orm.active", "true",
                "quarkus.flyway.active", "true",
                "quarkus.flyway.migrate-at-start", "true",
                "quarkus.flyway.locations", "db/migration",
                "quarkus.datasource.devservices.enabled", "false",
                "iam.readiness.signing-key.enabled", "false");
    }
}
