package dev.tessera.iam.adapter.persistence.db;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import io.quarkus.reactive.pg.client.PgPoolCreator;
import io.vertx.core.Vertx;
import io.vertx.pgclient.PgConnectOptions;
import io.vertx.pgclient.PgPool;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.PoolOptions;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("TesseraPgPoolCreator — socket and pool options for every database connection")
class TesseraPgPoolCreatorTest {

    private static PgPoolCreator.Input input(Vertx vertx, List<PgConnectOptions> options) {
        return new PgPoolCreator.Input() {
            @Override
            public Vertx vertx() {
                return vertx;
            }

            @Override
            public PoolOptions poolOptions() {
                return new PoolOptions().setMaxSize(1);
            }

            @Override
            public List<PgConnectOptions> pgConnectOptionsList() {
                return options;
            }
        };
    }

    private static final Duration IDLE = Duration.ofSeconds(30);
    private static final Duration INTERVAL = Duration.ofSeconds(10);

    private static TesseraPgPoolCreator creator(Duration userTimeout, Duration idle, Duration interval, int count) {
        return new TesseraPgPoolCreator(userTimeout, idle, interval, count);
    }

    private static TesseraPgPoolCreator creator(Duration userTimeout) {
        return creator(userTimeout, IDLE, INTERVAL, 3);
    }

    @Test
    @DisplayName("the user timeout and keepalive are set on each connect option and the pool is the PgPool Quarkus expects")
    @SuppressWarnings("deprecation") // PgPool is deprecated in Vert.x 4.5, but Quarkus casts the pool to it
    void setsSocketOptions() {
        Vertx vertx = Vertx.vertx();
        try {
            List<PgConnectOptions> options = List.of(new PgConnectOptions(), new PgConnectOptions());
            Pool pool = creator(Duration.ofSeconds(5)).create(input(vertx, options));
            assertThat(pool).isInstanceOf(PgPool.class);
            assertThat(options).allSatisfy(o -> {
                assertThat(o.getTcpUserTimeout()).isEqualTo(5_000);
                assertThat(o.isTcpKeepAlive()).isTrue();
                assertThat(o.getTcpKeepAliveIdleSeconds()).isEqualTo(30);
                assertThat(o.getTcpKeepAliveIntervalSeconds()).isEqualTo(10);
                assertThat(o.getTcpKeepAliveCount()).isEqualTo(3);
            });
            pool.close();
        } finally {
            vertx.close();
        }
    }

    @Test
    @DisplayName("zero leaves the operating system defaults for the user timeout and keepalive")
    void zeroLeavesDefaults() {
        Vertx vertx = Vertx.vertx();
        try {
            PgConnectOptions option = new PgConnectOptions();
            PgConnectOptions untouched = new PgConnectOptions();
            creator(Duration.ZERO, Duration.ZERO, INTERVAL, 3).create(input(vertx, List.of(option))).close();
            assertThat(option.getTcpUserTimeout()).isEqualTo(untouched.getTcpUserTimeout());
            assertThat(option.isTcpKeepAlive()).isEqualTo(untouched.isTcpKeepAlive());
            assertThat(option.getTcpKeepAliveIdleSeconds()).isEqualTo(untouched.getTcpKeepAliveIdleSeconds());
        } finally {
            vertx.close();
        }
    }

    @Test
    @DisplayName("invalid settings are refused at startup")
    void invalidRefused() {
        assertThatThrownBy(() -> creator(Duration.ofSeconds(-1))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> creator(Duration.ofSeconds(5), Duration.ofMillis(1500), INTERVAL, 3))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> creator(Duration.ofSeconds(5), IDLE, Duration.ZERO, 3))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> creator(Duration.ofSeconds(5), IDLE, INTERVAL, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
