package dev.tessera.iam.adapter.persistence.db;

import io.quarkus.reactive.pg.client.PgPoolCreator;
import io.vertx.pgclient.PgBuilder;
import io.vertx.pgclient.PgConnectOptions;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.PoolOptions;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Creates the reactive PostgreSQL pool with socket options that keep a database connection's
 * network path alive and detect a dead one.
 *
 * <p>A connection that crosses a NAT or firewall can be dropped there after a period of silence
 * while both ends still consider it open. Two kernel options address that:
 * <ul>
 *   <li><b>TCP keepalive</b> ({@code SO_KEEPALIVE} with {@code TCP_KEEPIDLE}, {@code TCP_KEEPINTVL},
 *       {@code TCP_KEEPCNT}): after {@code iam.db.tcp-keepalive.idle} without traffic the kernel sends
 *       a probe. The probe keeps the flow alive on the path, so it is not dropped as idle, and a
 *       path that has died anyway is noticed while the connection sits in the pool, not when a
 *       request borrows it.</li>
 *   <li><b>{@code TCP_USER_TIMEOUT}</b>: how long sent data may stay unacknowledged before the
 *       kernel closes the connection. It turns a statement written into a dead path into an error
 *       instead of a hang. When both are set, Linux lets the user timeout decide when an unanswered
 *       keepalive probe ends the connection (tcp(7)); the probe count matters only when the user
 *       timeout is off.</li>
 * </ul>
 * Pool lifetimes ({@code quarkus.datasource.reactive.idle-timeout}, {@code max-lifetime}) still
 * retire connections, but only when the pool's cleaner timer runs.
 *
 * <p>It also bounds the two waits Quarkus has no property for: the TCP connect of a new connection
 * ({@code iam.db.connect-timeout}, Vert.x default 60 s) and a request's wait for a pooled connection
 * ({@code iam.db.acquire-timeout}, Vert.x default 30 s). The connect timeout must be the shorter, or
 * a stalled connect would only ever surface as the acquisition timeout.
 *
 * <p>Vert.x applies these options on the native epoll transport (Linux) only; with the NIO
 * transport they are ignored without an error. Everything else about the pool is Quarkus' own
 * configuration, passed through unchanged.
 */
@Singleton
public class TesseraPgPoolCreator implements PgPoolCreator {

    private static final Logger LOG = Logger.getLogger(TesseraPgPoolCreator.class);

    private final int tcpUserTimeoutMillis;
    private final int keepAliveIdleSeconds;
    private final int keepAliveIntervalSeconds;
    private final int keepAliveCount;
    private final int connectTimeoutMillis;
    private final int acquireTimeoutMillis;
    private final PoolDiagnostics diagnostics;

    // The connect options of the pool this creator built, for tests to check what reached the driver.
    private volatile List<PgConnectOptions> configured = List.of();
    private volatile PoolOptions configuredPool;

    public TesseraPgPoolCreator(
            @ConfigProperty(name = "iam.db.tcp-user-timeout", defaultValue = "PT5S") Duration tcpUserTimeout,
            @ConfigProperty(name = "iam.db.tcp-keepalive.idle", defaultValue = "PT30S") Duration keepAliveIdle,
            @ConfigProperty(name = "iam.db.tcp-keepalive.interval", defaultValue = "PT10S") Duration keepAliveInterval,
            @ConfigProperty(name = "iam.db.tcp-keepalive.count", defaultValue = "3") int keepAliveCount,
            @ConfigProperty(name = "iam.db.connect-timeout", defaultValue = "PT5S") Duration connectTimeout,
            @ConfigProperty(name = "iam.db.acquire-timeout", defaultValue = "PT10S") Duration acquireTimeout,
            @ConfigProperty(name = "quarkus.datasource.credentials-provider") Optional<String> credentialsProvider,
            PoolDiagnostics diagnostics) {
        // Quarkus applies a credentials provider in the connect options supplier it builds when no
        // creator is present; this creator builds its own and would silently connect without it.
        if (credentialsProvider.isPresent()) {
            throw new IllegalStateException("quarkus.datasource.credentials-provider is set, but the database pool "
                    + "creator does not apply credentials providers; configure the username and password instead");
        }
        this.diagnostics = diagnostics;
        this.tcpUserTimeoutMillis = Math.toIntExact(nonNegative(tcpUserTimeout, "iam.db.tcp-user-timeout").toMillis());
        this.keepAliveIdleSeconds = wholeSeconds(keepAliveIdle, "iam.db.tcp-keepalive.idle");
        this.keepAliveIntervalSeconds = wholeSeconds(keepAliveInterval, "iam.db.tcp-keepalive.interval");
        this.keepAliveCount = keepAliveCount;
        this.connectTimeoutMillis = Math.toIntExact(positive(connectTimeout, "iam.db.connect-timeout").toMillis());
        this.acquireTimeoutMillis = Math.toIntExact(positive(acquireTimeout, "iam.db.acquire-timeout").toMillis());
        if (acquireTimeoutMillis <= connectTimeoutMillis) {
            throw new IllegalArgumentException("iam.db.acquire-timeout must be longer than iam.db.connect-timeout");
        }
        if (keepAliveIdleSeconds > 0 && (keepAliveIntervalSeconds < 1 || keepAliveCount < 1)) {
            throw new IllegalArgumentException("with iam.db.tcp-keepalive.idle set, iam.db.tcp-keepalive.interval "
                    + "must be at least 1 s and iam.db.tcp-keepalive.count at least 1");
        }
    }

    private static Duration nonNegative(Duration value, String name) {
        if (value == null || value.isNegative()) {
            throw new IllegalArgumentException(name + " must not be negative");
        }
        return value;
    }

    private static Duration positive(Duration value, String name) {
        if (value == null || value.isNegative() || value.isZero()) {
            throw new IllegalArgumentException(name + " must be positive");
        }
        return value;
    }

    // The kernel takes keepalive timings in whole seconds.
    private static int wholeSeconds(Duration value, String name) {
        nonNegative(value, name);
        if (value.toMillis() % 1000 != 0) {
            throw new IllegalArgumentException(name + " must be a whole number of seconds");
        }
        return Math.toIntExact(value.toSeconds());
    }

    @Override
    public Pool create(Input input) {
        PoolOptions poolOptions = input.poolOptions()
                .setConnectionTimeout(acquireTimeoutMillis)
                .setConnectionTimeoutUnit(TimeUnit.MILLISECONDS);
        for (PgConnectOptions options : input.pgConnectOptionsList()) {
            options.setConnectTimeout(connectTimeoutMillis);
            if (tcpUserTimeoutMillis > 0) {
                options.setTcpUserTimeout(tcpUserTimeoutMillis);
            }
            if (keepAliveIdleSeconds > 0) {
                options.setTcpKeepAlive(true);
                options.setTcpKeepAliveIdleSeconds(keepAliveIdleSeconds);
                options.setTcpKeepAliveIntervalSeconds(keepAliveIntervalSeconds);
                options.setTcpKeepAliveCount(keepAliveCount);
            }
        }
        // One line with the effective options, so a deployment can confirm the creator ran and what is
        // in force. Without the native transport the socket options are silently ignored; it says so.
        LOG.infof("Database pool: max size %d, idle timeout %s, max lifetime %s, acquisition timeout %d ms, "
                + "connect timeout %d ms, TCP user timeout %d ms, keepalive %s; %s",
                poolOptions.getMaxSize(),
                millisOrNone(poolOptions.getIdleTimeoutUnit().toMillis(poolOptions.getIdleTimeout())),
                millisOrNone(poolOptions.getMaxLifetimeUnit().toMillis(poolOptions.getMaxLifetime())),
                acquireTimeoutMillis, connectTimeoutMillis, tcpUserTimeoutMillis,
                keepAliveIdleSeconds > 0
                        ? "idle " + keepAliveIdleSeconds + " s, interval " + keepAliveIntervalSeconds
                                + " s, count " + keepAliveCount
                        : "off",
                input.vertx().isNativeTransportEnabled()
                        ? "native transport, socket options applied"
                        : "no native transport, socket options ignored");
        configured = List.copyOf(input.pgConnectOptionsList());
        configuredPool = poolOptions;
        // Quarkus, with no creator, passes the driver a supplier over these same options; that
        // differs only when a datasource credentials provider is configured, which the constructor
        // refuses. This supplier is the same round robin, counting attempts.
        // The PostgreSQL driver builds the PgPool Quarkus casts the result to.
        Pool pool = PgBuilder.pool()
                .with(poolOptions)
                .connectingTo(diagnostics.connectAttempts(input.pgConnectOptionsList()))
                .withConnectHandler(diagnostics::opened)
                .using(input.vertx())
                .build();
        diagnostics.attach(pool, poolOptions.getMaxSize());
        return pool;
    }

    private static String millisOrNone(long millis) {
        return millis > 0 ? millis + " ms" : "none";
    }

    List<PgConnectOptions> configuredOptions() {
        return configured;
    }

    PoolOptions configuredPoolOptions() {
        return configuredPool;
    }
}
