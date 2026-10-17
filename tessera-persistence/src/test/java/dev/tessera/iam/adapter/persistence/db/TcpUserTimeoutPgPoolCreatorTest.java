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

@DisplayName("TcpUserTimeoutPgPoolCreator — every pooled connection gets the TCP user timeout")
class TcpUserTimeoutPgPoolCreatorTest {

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

    @Test
    @DisplayName("the timeout is set on each connect option and the pool is the PgPool Quarkus expects")
    @SuppressWarnings("deprecation") // PgPool is deprecated in Vert.x 4.5, but Quarkus casts the pool to it
    void setsTimeout() {
        Vertx vertx = Vertx.vertx();
        try {
            List<PgConnectOptions> options = List.of(new PgConnectOptions(), new PgConnectOptions());
            Pool pool = new TcpUserTimeoutPgPoolCreator(Duration.ofSeconds(15)).create(input(vertx, options));
            assertThat(pool).isInstanceOf(PgPool.class);
            assertThat(options).allSatisfy(o -> assertThat(o.getTcpUserTimeout()).isEqualTo(15_000));
            pool.close();
        } finally {
            vertx.close();
        }
    }

    @Test
    @DisplayName("zero leaves the operating system default")
    void zeroLeavesDefault() {
        Vertx vertx = Vertx.vertx();
        try {
            PgConnectOptions option = new PgConnectOptions();
            int before = option.getTcpUserTimeout();
            new TcpUserTimeoutPgPoolCreator(Duration.ZERO).create(input(vertx, List.of(option))).close();
            assertThat(option.getTcpUserTimeout()).isEqualTo(before);
        } finally {
            vertx.close();
        }
    }

    @Test
    @DisplayName("a negative timeout is refused at startup")
    void negativeRefused() {
        assertThatThrownBy(() -> new TcpUserTimeoutPgPoolCreator(Duration.ofSeconds(-1)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
