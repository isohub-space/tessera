package dev.tessera.iam.adapter.persistence.db;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.Map;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * A PostgreSQL container reached by the reactive pool through a {@link ResettingTcpProxy}, so a
 * test can kill the pooled connection's network path while the database stays up.
 *
 * <p>Flyway (JDBC) connects directly; only the runtime reactive pool goes through the proxy. The
 * pool is limited to one connection so the connection a test dooms is the one the next request
 * borrows.
 */
public class ResettingProxyPostgresResource implements QuarkusTestResourceLifecycleManager {

    static final String ADMIN_PORT = "test.resetting-proxy.admin-port";

    @SuppressWarnings("resource")
    private final PostgreSQLContainer postgres =
            new PostgreSQLContainer("postgres:16-alpine")
                    .withDatabaseName("iam_test")
                    .withUsername("iam")
                    .withPassword("iam")
                    .withInitScript("db/init/iam_app_role.sql");

    private ResettingTcpProxy proxy;

    @Override
    public Map<String, String> start() {
        postgres.start();
        try {
            proxy = new ResettingTcpProxy(postgres.getHost(),
                    postgres.getMappedPort(PostgreSQLContainer.POSTGRESQL_PORT));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        String reactiveUrl = "postgresql://127.0.0.1:" + proxy.port() + "/" + postgres.getDatabaseName();
        return Map.of(
                "quarkus.datasource.username", "iam_app",
                "quarkus.datasource.password", "iam_app",
                "quarkus.datasource.reactive.url", reactiveUrl,
                "quarkus.datasource.reactive.max-size", "1",
                "quarkus.datasource.jdbc.url", postgres.getJdbcUrl(),
                "quarkus.flyway.username", "iam_migrator",
                "quarkus.flyway.password", "iam_migrator",
                ADMIN_PORT, String.valueOf(proxy.adminPort()));
    }

    @Override
    public void stop() {
        try {
            if (proxy != null) {
                proxy.close();
            }
        } catch (IOException ignored) {
            // the container goes next anyway
        }
        postgres.stop();
    }
}
