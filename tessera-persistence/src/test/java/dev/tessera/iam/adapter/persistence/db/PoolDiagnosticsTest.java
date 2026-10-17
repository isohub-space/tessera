package dev.tessera.iam.adapter.persistence.db;

import static org.assertj.core.api.Assertions.assertThat;

import io.vertx.core.Future;
import io.vertx.pgclient.PgConnectOptions;
import io.vertx.sqlclient.SqlConnectOptions;
import io.vertx.sqlclient.SqlConnection;
import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("PoolDiagnostics — connection attempts are matched to the connections they open")
class PoolDiagnosticsTest {

    private static final long MS = 1_000_000L;

    private final AtomicLong now = new AtomicLong();
    private final PoolDiagnostics diagnostics = new PoolDiagnostics(Duration.ofSeconds(1), now::get);
    private final Supplier<Future<SqlConnectOptions>> attempts =
            diagnostics.connectAttempts(List.of(new PgConnectOptions()));

    PoolDiagnosticsTest() {
        diagnostics.attach(null, 4, Duration.ofSeconds(15));
    }

    private static SqlConnection connection() {
        return (SqlConnection) Proxy.newProxyInstance(PoolDiagnosticsTest.class.getClassLoader(),
                new Class<?>[] {SqlConnection.class}, (proxy, method, args) -> null);
    }

    private void at(long millis) {
        now.set(millis * MS);
    }

    @Test
    @DisplayName("a connection is measured from its own attempt")
    void measuresTheAttempt() {
        at(0);
        attempts.get();
        at(250);
        diagnostics.opened(connection());
        assertThat(diagnostics.lastOpenNanos()).isEqualTo(250 * MS);
        assertThat(diagnostics.connectionsOpened()).isEqualTo(1);
    }

    @Test
    @DisplayName("an attempt that never opened is dropped once it is stale, not matched to a later connection")
    void failedAttemptDoesNotSkewLaterOnes() {
        at(0);
        attempts.get(); // fails; the pool does not report it
        at(20_000);
        attempts.get();
        at(20_100);
        diagnostics.opened(connection());
        assertThat(diagnostics.lastOpenNanos()).as("measured from the second attempt").isEqualTo(100 * MS);
        assertThat(diagnostics.attemptsDropped()).isEqualTo(1);
        assertThat(diagnostics.state()).contains("given up 1");
    }

    @Test
    @DisplayName("overlapping attempts are matched oldest first")
    void overlappingAttempts() {
        at(0);
        attempts.get();
        at(50);
        attempts.get();
        at(200);
        diagnostics.opened(connection());
        assertThat(diagnostics.lastOpenNanos()).isEqualTo(200 * MS);
        at(300);
        diagnostics.opened(connection());
        assertThat(diagnostics.lastOpenNanos()).isEqualTo(250 * MS);
        assertThat(diagnostics.attemptsDropped()).isZero();
    }
}
