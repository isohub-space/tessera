package dev.tessera.iam.adapter.persistence.db;

import io.quarkus.reactive.pg.client.PgPoolCreator;
import io.vertx.pgclient.PgConnectOptions;
import io.vertx.pgclient.spi.PgDriver;
import io.vertx.sqlclient.Pool;
import jakarta.inject.Singleton;
import java.time.Duration;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

/**
 * Creates the reactive PostgreSQL pool with a TCP user timeout on every connection.
 *
 * <p>A connection whose network path was dropped silently (a NAT or firewall forgetting an idle
 * flow) accepts a write, and the kernel then retransmits it unacknowledged for many minutes before
 * giving up; the request waiting on that connection hangs, and others queue behind it until the
 * pool's acquisition timeout. {@code TCP_USER_TIMEOUT} bounds how long sent data may stay
 * unacknowledged, so such a connection fails fast with a connection error that the read path can
 * retry on a fresh connection. Pool lifetimes ({@code quarkus.datasource.reactive.idle-timeout},
 * {@code max-lifetime}) remain the first defence: they retire connections before the path drops
 * them.
 *
 * <p>The option is honoured by the native epoll transport only (Linux). Elsewhere it is ignored,
 * which is harmless. Everything else about the pool is Quarkus' own configuration, passed through
 * unchanged.
 */
@Singleton
public class TesseraPgPoolCreator implements PgPoolCreator {

    private static final Logger LOG = Logger.getLogger(TesseraPgPoolCreator.class);

    private final int tcpUserTimeoutMillis;

    public TesseraPgPoolCreator(
            @ConfigProperty(name = "iam.db.tcp-user-timeout", defaultValue = "PT5S") Duration tcpUserTimeout) {
        if (tcpUserTimeout == null || tcpUserTimeout.isNegative()) {
            throw new IllegalArgumentException("iam.db.tcp-user-timeout must not be negative");
        }
        this.tcpUserTimeoutMillis = Math.toIntExact(tcpUserTimeout.toMillis());
    }

    @Override
    public Pool create(Input input) {
        // Without the native transport the option is silently ignored; say which case applies, so
        // a deployment can confirm the bound is in force.
        if (tcpUserTimeoutMillis > 0) {
            LOG.infof("Database connections: TCP user timeout %d ms (%s)", tcpUserTimeoutMillis,
                    input.vertx().isNativeTransportEnabled()
                            ? "native transport, applied"
                            : "no native transport, ignored");
            for (PgConnectOptions options : input.pgConnectOptionsList()) {
                options.setTcpUserTimeout(tcpUserTimeoutMillis);
            }
        }
        // Quarkus, with no creator, passes the driver a supplier over these same options; that
        // differs only when a datasource credentials provider is configured, which tessera does not
        // use (a creator would bypass it). The driver returns the PgPool Quarkus casts the result to.
        return PgDriver.INSTANCE.createPool(
                input.vertx(), input.pgConnectOptionsList(), input.poolOptions());
    }

    int tcpUserTimeoutMillis() {
        return tcpUserTimeoutMillis;
    }
}
