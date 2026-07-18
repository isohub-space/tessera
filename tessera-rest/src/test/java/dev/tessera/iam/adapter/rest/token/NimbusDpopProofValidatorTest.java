package dev.tessera.iam.adapter.rest.token;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.config.DpopConfig;
import dev.tessera.iam.adapter.rest.support.DpopTestClient;
import dev.tessera.iam.application.port.out.DpopProofValidatorPort.Request;
import dev.tessera.iam.application.port.out.DpopProofValidatorPort.Result;
import io.vertx.mutiny.core.Vertx;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NimbusDpopProofValidator — RFC 9449 proof validation")
class NimbusDpopProofValidatorTest {

    private static final String HTU = "https://issuer.test.example/token";
    private static final Duration MAX_AGE = Duration.ofMinutes(1);
    private static final Duration SKEW = Duration.ofSeconds(5);

    private Vertx vertx;
    private NimbusDpopProofValidator validator;
    private DpopTestClient client;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();
        validator = new NimbusDpopProofValidator();
        validator.vertx = vertx;
        validator.config = new DpopConfig() {
            @Override public Duration proofMaxAge() { return MAX_AGE; }
            @Override public Duration clockSkew() { return SKEW; }
        };
        client = new DpopTestClient();
    }

    @AfterEach
    void tearDown() {
        vertx.closeAndAwait();
    }

    private Result validate(String proof, Instant now) {
        return validator.validate(new Request(proof, "POST", HTU, now)).await().indefinitely();
    }

    @Test
    @DisplayName("a well-formed, fresh, correctly-bound proof yields the client's jkt")
    void validProof() {
        Instant now = Instant.now();
        Result result = validate(client.proof(HTU), now);
        assertThat(result).isInstanceOf(Result.Valid.class);
        assertThat(((Result.Valid) result).jkt()).isEqualTo(client.jkt());
    }

    @Test
    @DisplayName("the same proof (same jti) is rejected on second presentation — single use")
    void replayRejected() {
        Instant now = Instant.now();
        String proof = client.proof("POST", HTU, now, UUID.randomUUID().toString());
        assertThat(validate(proof, now)).isInstanceOf(Result.Valid.class);
        assertThat(validate(proof, now)).isInstanceOf(Result.Invalid.class);
    }

    @Test
    @DisplayName("a proof bound to a different htu is rejected")
    void wrongHtuRejected() {
        Instant now = Instant.now();
        String proof = client.proof("POST", "https://issuer.test.example/OTHER", now,
                UUID.randomUUID().toString());
        assertThat(validate(proof, now)).isInstanceOf(Result.Invalid.class);
    }

    @Test
    @DisplayName("a proof bound to a different htm is rejected")
    void wrongHtmRejected() {
        Instant now = Instant.now();
        String proof = client.proof("GET", HTU, now, UUID.randomUUID().toString());
        assertThat(validate(proof, now)).isInstanceOf(Result.Invalid.class);
    }

    @Test
    @DisplayName("a proof whose iat is older than the acceptance window is rejected")
    void staleIatRejected() {
        Instant now = Instant.now();
        Instant old = now.minus(MAX_AGE).minusSeconds(30);
        String proof = client.proof("POST", HTU, old, UUID.randomUUID().toString());
        assertThat(validate(proof, now)).isInstanceOf(Result.Invalid.class);
    }

    @Test
    @DisplayName("a proof whose iat is too far in the future is rejected")
    void futureIatRejected() {
        Instant now = Instant.now();
        Instant future = now.plus(SKEW).plusSeconds(30);
        String proof = client.proof("POST", HTU, future, UUID.randomUUID().toString());
        assertThat(validate(proof, now)).isInstanceOf(Result.Invalid.class);
    }

    @Test
    @DisplayName("a malformed proof string is rejected, not thrown")
    void malformedRejected() {
        assertThat(validate("not-a-jwt", Instant.now())).isInstanceOf(Result.Invalid.class);
    }
}
