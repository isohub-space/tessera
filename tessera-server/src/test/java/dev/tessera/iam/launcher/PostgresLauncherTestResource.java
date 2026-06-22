package dev.tessera.iam.launcher;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import java.util.Map;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Starts a throwaway PostgreSQL container and points the launcher's reactive (runtime)
 * and JDBC (Flyway) datasources at it for the JWKS endpoint integration test.
 *
 * <p>Uses the same three-role model as the persistence module's integration tests so
 * row-level security is actually enforced: Flyway connects as {@code iam_migrator} and
 * the runtime as {@code iam_app}, both non-superusers.
 */
public class PostgresLauncherTestResource implements QuarkusTestResourceLifecycleManager {

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
