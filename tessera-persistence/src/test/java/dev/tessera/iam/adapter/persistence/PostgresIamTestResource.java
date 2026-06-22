package dev.tessera.iam.adapter.persistence;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import java.util.Map;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Starts a throwaway PostgreSQL 16 container and points the Quarkus reactive
 * datasource (runtime) and JDBC datasource (Flyway) at it for the duration of a
 * {@code @QuarkusTest}.
 *
 * <p>Build-time
 * settings ({@code db-kind}, {@code hibernate-orm.database.generation},
 * {@code flyway.migrate-at-start/locations}) live in
 * {@code src/test/resources/application.properties}; only the runtime connection
 * coordinates are supplied here. Docker is therefore required only by the {@code *IT}
 * failsafe tests that declare this resource.</p>
 */
public class PostgresIamTestResource implements QuarkusTestResourceLifecycleManager {

    @SuppressWarnings("resource")
    private static final PostgreSQLContainer POSTGRES =
            new PostgreSQLContainer("postgres:16-alpine")
                    .withDatabaseName("iam_test")
                    .withUsername("iam")
                    .withPassword("iam")
                    .withInitScript("db/init/iam_app_role.sql");

    @Override
    public Map<String, String> start() {
        POSTGRES.start();
        int port = POSTGRES.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT);
        String reactiveUrl = "postgresql://" + POSTGRES.getHost() + ":" + port + "/"
                + POSTGRES.getDatabaseName();
        // Three-role model: the runtime (reactive + agroal) connects as
        // iam_app and Flyway as iam_migrator — BOTH non-superusers, so RLS (incl.
        // FORCE, against the migrator-owned tables) is actually enforced. The
        // container superuser is used only by the init script (role creation).
        return Map.of(
                "quarkus.datasource.username", "iam_app",
                "quarkus.datasource.password", "iam_app",
                "quarkus.datasource.reactive.url", reactiveUrl,
                "quarkus.datasource.jdbc.url", POSTGRES.getJdbcUrl(),
                "quarkus.flyway.username", "iam_migrator",
                "quarkus.flyway.password", "iam_migrator");
    }

    @Override
    public void stop() {
        POSTGRES.stop();
    }
}
