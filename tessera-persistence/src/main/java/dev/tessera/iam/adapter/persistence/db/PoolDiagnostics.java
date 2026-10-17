package dev.tessera.iam.adapter.persistence.db;

import io.vertx.core.Future;
import io.vertx.pgclient.PgConnectOptions;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.SqlConnectOptions;
import io.vertx.sqlclient.SqlConnection;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Supplier;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Makes slow database connections visible, so the two ways a request can wait for one are told apart
 * in the logs: every pooled connection busy or stuck (the pool is full and no new connection is being
 * opened), or a new connection that is slow to open (attempts started but not completed).
 *
 * <p>It counts the pool's connection attempts and the connections it opened, logs a connection that
 * took longer than {@code iam.db.slow-log-threshold} to open, and lets the tenant-scoped session log a
 * request that waited longer than that for its connection. Messages carry durations and counts only.
 * The time to open a connection is measured from the oldest attempt still pending, so it is approximate
 * when attempts overlap or fail.
 */
@Singleton
public class PoolDiagnostics {

    private static final Logger LOG = Logger.getLogger(PoolDiagnostics.class);

    private final long slowNanos;
    private final AtomicLong attemptsStarted = new AtomicLong();
    private final AtomicLong connectionsOpened = new AtomicLong();
    private final Queue<Long> pendingAttempts = new ConcurrentLinkedQueue<>();
    private volatile Pool pool;
    private volatile int maxSize;

    public PoolDiagnostics(
            @ConfigProperty(name = "iam.db.slow-log-threshold", defaultValue = "PT1S") Duration slowThreshold) {
        if (slowThreshold == null || slowThreshold.isNegative()) {
            throw new IllegalArgumentException("iam.db.slow-log-threshold must not be negative");
        }
        this.slowNanos = slowThreshold.toNanos();
    }

    /** The driver's source of connect options: round robin over {@code options}, counting each attempt. */
    Supplier<Future<SqlConnectOptions>> connectAttempts(List<PgConnectOptions> options) {
        List<PgConnectOptions> targets = List.copyOf(options);
        AtomicInteger next = new AtomicInteger();
        return () -> {
            attemptsStarted.incrementAndGet();
            pendingAttempts.add(System.nanoTime());
            return Future.succeededFuture(targets.get(Math.floorMod(next.getAndIncrement(), targets.size())));
        };
    }

    /** Records the pool whose state {@link #state()} reports. */
    void attach(Pool pool, int maxSize) {
        this.pool = pool;
        this.maxSize = maxSize;
    }

    /**
     * The pool's handler for each new connection. The pool hands the connection over only once it is
     * released here.
     */
    void opened(SqlConnection connection) {
        connectionsOpened.incrementAndGet();
        Long started = pendingAttempts.poll();
        if (started != null) {
            long elapsed = System.nanoTime() - started;
            if (elapsed >= slowNanos) {
                LOG.warnf("Opened a database connection in %d ms (%s)", elapsed / 1_000_000, state());
            }
        }
        connection.close();
    }

    /**
     * Logs a request that waited at least the threshold for its connection and the transaction to begin.
     *
     * @param elapsedNanos the wait, in nanoseconds
     */
    public void waited(long elapsedNanos) {
        if (elapsedNanos >= slowNanos) {
            LOG.warnf("Waited %d ms for a database connection (%s)", elapsedNanos / 1_000_000, state());
        }
    }

    /** @return the pool's state in counts: connections open of the maximum, attempts started and opened */
    public String state() {
        Pool current = pool;
        return (current == null ? "pool not created" : "pool " + current.size() + " of " + maxSize + " open")
                + "; connection attempts started " + attemptsStarted.get() + ", opened " + connectionsOpened.get();
    }

    long attemptsStarted() {
        return attemptsStarted.get();
    }

    long connectionsOpened() {
        return connectionsOpened.get();
    }
}
