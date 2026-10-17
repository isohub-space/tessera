package dev.tessera.iam.adapter.persistence.db;

import static org.assertj.core.api.Assertions.assertThat;

import io.smallrye.mutiny.CompositeException;
import io.vertx.core.impl.NoStackTraceThrowable;
import io.vertx.sqlclient.ClosedConnectionException;
import java.net.SocketException;
import java.util.List;
import java.util.concurrent.CompletionException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ConnectionFailures — only a failed connection counts, not failed SQL")
class ConnectionFailuresTest {

    @Test
    @DisplayName("a reset wrapped by the transaction layer is a connection failure")
    void wrappedReset() {
        Throwable failure = new IllegalStateException("Failed to start a transaction",
                new SocketException("Connection reset by peer"));
        assertThat(ConnectionFailures.isConnectionFailure(failure)).isTrue();
    }

    @Test
    @DisplayName("a closed connection is a connection failure")
    void closedConnection() {
        assertThat(ConnectionFailures.isConnectionFailure(ClosedConnectionException.INSTANCE)).isTrue();
    }

    @Test
    @DisplayName("a reset reported beside another failure is still found")
    void composite() {
        Throwable failure = new CompositeException(List.of(
                new IllegalStateException("Live transaction detected while closing the connection"),
                new SocketException("Connection reset by peer")));
        assertThat(ConnectionFailures.isConnectionFailure(failure)).isTrue();
    }

    @Test
    @DisplayName("SQL errors, other timeouts and null are not connection failures")
    void notConnectionFailures() {
        assertThat(ConnectionFailures.isConnectionFailure(null)).isFalse();
        assertThat(ConnectionFailures.isConnectionFailure(
                new IllegalStateException("duplicate key value violates unique constraint"))).isFalse();
        assertThat(ConnectionFailures.isConnectionFailure(new RuntimeException("Timeout"))).isFalse();
    }

    @Test
    @DisplayName("the pool's acquisition timeout is recognised, wrapped or not, and only that")
    void acquisitionTimeout() {
        Throwable timeout = new NoStackTraceThrowable("Timeout");
        assertThat(ConnectionFailures.isAcquisitionTimeout(timeout)).isTrue();
        assertThat(ConnectionFailures.isAcquisitionTimeout(new CompletionException(timeout))).isTrue();
        assertThat(ConnectionFailures.isRetryableForRead(timeout)).isTrue();
        assertThat(ConnectionFailures.isConnectionFailure(timeout)).isFalse();
        assertThat(ConnectionFailures.isAcquisitionTimeout(new NoStackTraceThrowable("Pool closed"))).isFalse();
        assertThat(ConnectionFailures.isAcquisitionTimeout(new RuntimeException("Timeout"))).isFalse();
        assertThat(ConnectionFailures.isAcquisitionTimeout(new SocketException("Connection reset"))).isFalse();
    }

    @Test
    @DisplayName("a self-referencing cause chain terminates")
    void cycleTerminates() {
        RuntimeException a = new RuntimeException("a");
        RuntimeException b = new RuntimeException("b", a);
        a.initCause(b);
        assertThat(ConnectionFailures.isConnectionFailure(a)).isFalse();
    }
}
