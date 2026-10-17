package dev.tessera.iam.adapter.persistence.db;

import io.vertx.core.Future;
import io.vertx.pgclient.PgConnectOptions;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.SqlConnectOptions;
import io.vertx.sqlclient.SqlConnection;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;
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
 *
 * <p>The pool reports a connection that opened but not an attempt that failed, so the time to open a
 * connection is measured from the oldest attempt still pending, and an attempt older than the longest
 * one can take to succeed (the connect timeout plus the acquisition timeout) is dropped as failed. The
 * measurement is therefore approximate while attempts overlap, and a failed attempt can skew it only
 * until it is dropped.
 */
@Singleton
public class PoolDiagnostics {

    private static final Logger LOG = Logger.getLogger(PoolDiagnostics.class);

    private final long slowNanos;
    private final AtomicLong attemptsStarted = new AtomicLong();
    private final AtomicLong connectionsOpened = new AtomicLong();
    private final AtomicLong attemptsDropped = new AtomicLong();
    private final Queue<Long> pendingAttempts = new ConcurrentLinkedQueue<>();
    private final LongSupplier clock;
    private volatile Pool pool;
    private volatile int maxSize;
    private volatile long staleNanos = Long.MAX_VALUE;
    private volatile long lastOpenNanos = -1;

    @Inject
    public PoolDiagnostics(
            @ConfigProperty(name = "iam.db.slow-log-threshold", defaultValue = "PT1S") Duration slowThreshold) {
        this(slowThreshold, System::nanoTime);
    }

    PoolDiagnostics(Duration slowThreshold, LongSupplier clock) {
        this.clock = clock;
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
            long now = clock.getAsLong();
            dropStale(now);
            pendingAttempts.add(now);
            return Future.succeededFuture(targets.get(Math.floorMod(next.getAndIncrement(), targets.size())));
        };
    }

    /**
     * Records the pool whose state {@link #state()} reports.
     *
     * @param staleAfter the longest a connection attempt can take to succeed; older pending attempts
     *                   are dropped as failed
     */
    void attach(Pool pool, int maxSize, Duration staleAfter) {
        this.pool = pool;
        this.maxSize = maxSize;
        this.staleNanos = staleAfter.toNanos();
    }

    private void dropStale(long now) {
        Long oldest;
        while ((oldest = pendingAttempts.peek()) != null && now - oldest > staleNanos) {
            if (pendingAttempts.remove(oldest)) {
                attemptsDropped.incrementAndGet();
            }
        }
    }

    /**
     * The pool's handler for each new connection. The pool hands the connection over only once it is
     * released here.
     */
    void opened(SqlConnection connection) {
        connectionsOpened.incrementAndGet();
        long now = clock.getAsLong();
        dropStale(now);
        Long started = pendingAttempts.poll();
        if (started != null) {
            long elapsed = now - started;
            lastOpenNanos = elapsed;
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
                + "; connection attempts started " + attemptsStarted.get() + ", opened " + connectionsOpened.get()
                + ", given up " + attemptsDropped.get();
    }

    long attemptsStarted() {
        return attemptsStarted.get();
    }

    long connectionsOpened() {
        return connectionsOpened.get();
    }

    long attemptsDropped() {
        return attemptsDropped.get();
    }

    long lastOpenNanos() {
        return lastOpenNanos;
    }
}
