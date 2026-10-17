package dev.tessera.iam.adapter.persistence.db;

import io.smallrye.mutiny.Uni;
import io.vertx.core.Context;
import io.vertx.core.Vertx;
import io.vertx.core.impl.NoStackTraceThrowable;
import io.vertx.sqlclient.ClosedConnectionException;
import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.Set;
import java.util.function.Predicate;

/**
 * Recognises a failure of the database connection itself, as opposed to a failure of the SQL it
 * carried.
 *
 * <p>A pooled connection whose network path was dropped fails on its next use with an I/O error
 * ({@code Connection reset by peer}, a broken pipe, the TCP user timeout, a connect timeout) or a
 * closed-connection error, typically wrapped by Hibernate Reactive ("Failed to start a
 * transaction"). Those are worth one more attempt on a fresh connection. So is the pool's
 * acquisition timeout, which means no connection was handed over at all. A constraint violation,
 * a syntax error or a row-level security refusal is not: retrying it would fail the same way.
 */
public final class ConnectionFailures {

    private static final int MAX_VISITED = 32;

    // The pause before a retry. The failure reaches the caller while the client is still handling
    // the reset; the pool drops the dead connection only once the channel's close has run, a few
    // event-loop tasks later. Retrying at once can borrow the same dead connection again (seen in
    // the reset test); a timer on the same context runs after those tasks.
    private static final long RETRY_PAUSE_MILLIS = 50;

    private ConnectionFailures() {
    }

    /**
     * @param failure a failure (may be {@code null})
     * @return {@code true} if an I/O or closed-connection error is among its causes or suppressed
     *         exceptions (Hibernate Reactive may report the reset alongside a secondary failure)
     */
    public static boolean isConnectionFailure(Throwable failure) {
        return anyCause(failure, t -> t instanceof IOException || t instanceof ClosedConnectionException);
    }

    /**
     * Recognises the pool's acquisition timeout: no connection was handed to the request within the
     * pool's connection timeout.
     *
     * <p>In Vert.x 4.5 it is the bare {@code NoStackTraceThrowable("Timeout")} that
     * {@code SqlConnectionPool}'s pool request completes the caller's promise with, from its timer,
     * and only after the pool confirmed that the waiter was cancelled. The promise completes once,
     * so a caller that receives this failure never received a connection, and nothing was sent to
     * the database on its behalf.
     *
     * @param failure a failure (may be {@code null})
     * @return {@code true} if the acquisition timeout is among its causes or suppressed exceptions
     */
    public static boolean isAcquisitionTimeout(Throwable failure) {
        return anyCause(failure, t -> t instanceof NoStackTraceThrowable && "Timeout".equals(t.getMessage()));
    }

    /**
     * @param failure a failure (may be {@code null})
     * @return {@code true} if a read that failed this way before it started may run again
     */
    public static boolean isRetryableForRead(Throwable failure) {
        return isConnectionFailure(failure) || isAcquisitionTimeout(failure);
    }

    private static boolean anyCause(Throwable failure, Predicate<Throwable> test) {
        Deque<Throwable> pending = new ArrayDeque<>();
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        if (failure != null) {
            pending.add(failure);
        }
        while (!pending.isEmpty() && seen.size() < MAX_VISITED) {
            Throwable t = pending.poll();
            if (!seen.add(t)) {
                continue;
            }
            if (test.test(t)) {
                return true;
            }
            if (t.getCause() != null) {
                pending.add(t.getCause());
            }
            pending.addAll(Arrays.asList(t.getSuppressed()));
        }
        return false;
    }

    /**
     * A short pause before retrying after a connection failure, on the caller's Vert.x context so
     * the retry stays on the thread the reactive session requires. Off a Vert.x context it does not
     * pause.
     *
     * @return a {@link Uni} completing when the retry may start
     */
    public static Uni<Void> pauseBeforeRetry() {
        Context context = Vertx.currentContext();
        if (context == null) {
            return Uni.createFrom().voidItem();
        }
        return Uni.createFrom().emitter(emitter ->
                context.owner().setTimer(RETRY_PAUSE_MILLIS, id -> emitter.complete(null)));
    }
}
