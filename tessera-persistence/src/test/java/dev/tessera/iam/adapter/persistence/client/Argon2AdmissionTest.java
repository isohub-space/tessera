package dev.tessera.iam.adapter.persistence.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.application.port.out.CredentialVerificationBusyException;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.core.WorkerExecutor;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Argon2Admission — bounded wait, then 'busy', the same for every caller")
class Argon2AdmissionTest {

    private static final UUID TENANT_A = UUID.randomUUID();
    private static final UUID TENANT_B = UUID.randomUUID();

    private final Vertx vertx = Vertx.vertx();
    private final WorkerExecutor oneWorker = vertx.createSharedWorkerExecutor("argon2-test", 1);
    private final CountDownLatch release = new CountDownLatch(1);

    @AfterEach
    void close() {
        release.countDown();
        oneWorker.closeAndAwait();
        vertx.closeAndAwait();
    }

    /** One worker, {@code waiting} queue slots, a per-tenant share and a wait deadline. */
    private Argon2Admission admission(int waiting, double tenantShare, Duration deadline) {
        return new Argon2Admission(vertx, oneWorker, 1, waiting, tenantShare, deadline);
    }

    /** Occupies the single worker until {@link #release} opens. */
    private void blockWorker(Argon2Admission admission, UUID tenant) {
        start(admission.run(tenant, () -> release.await(10, TimeUnit.SECONDS)));
    }

    /** Subscribes once, as a verifier's caller does, and hands back that one outcome. */
    private static <T> CompletableFuture<T> start(Uni<T> uni) {
        return uni.subscribeAsCompletionStage();
    }

    private static <T> T await(CompletableFuture<T> started) throws Exception {
        try {
            return started.get(5, TimeUnit.SECONDS);
        } catch (ExecutionException failed) {
            throw (Exception) failed.getCause();
        }
    }

    @Test
    @DisplayName("past the global cap a request is refused at once, without running its work")
    void globalCapRefusesAtOnce() throws Exception {
        Argon2Admission admission = admission(1, 1.0, Duration.ofSeconds(5));
        blockWorker(admission, TENANT_A);
        CompletableFuture<String> queued = start(admission.run(TENANT_B, () -> "ran"));
        Thread.sleep(50);

        AtomicBoolean ran = new AtomicBoolean();
        assertThatThrownBy(() -> await(start(admission.run(TENANT_B, () -> ran.getAndSet(true)))))
                .isInstanceOf(CredentialVerificationBusyException.class);
        assertThat(ran).isFalse();

        release.countDown();
        assertThat(await(queued)).isEqualTo("ran");
        assertThat(await(start(admission.run(TENANT_B, () -> "after")))).isEqualTo("after");
    }

    @Test
    @DisplayName("one tenant cannot take more than its share; another tenant still gets in")
    void tenantShareLeavesRoomForOthers() throws Exception {
        // Cap 1 running + 3 waiting = 4; a tenant may hold half of it.
        Argon2Admission admission = admission(3, 0.5, Duration.ofSeconds(5));
        blockWorker(admission, TENANT_A);
        start(admission.run(TENANT_A, () -> "a2"));
        Thread.sleep(50);

        assertThatThrownBy(() -> await(start(admission.run(TENANT_A, () -> "a3"))))
                .isInstanceOf(CredentialVerificationBusyException.class);
        CompletableFuture<String> other = start(admission.run(TENANT_B, () -> "b1"));
        release.countDown();
        assertThat(await(other)).isEqualTo("b1");
    }

    @Test
    @DisplayName("a request that waits past the deadline is refused, and its work never runs")
    void waitDeadlineRefusesAndSkipsTheWork() throws Exception {
        Argon2Admission admission = admission(4, 1.0, Duration.ofMillis(100));
        blockWorker(admission, TENANT_A);

        AtomicBoolean ran = new AtomicBoolean();
        long started = System.nanoTime();
        assertThatThrownBy(() -> await(start(admission.run(TENANT_B, () -> ran.getAndSet(true)))))
                .isInstanceOf(CredentialVerificationBusyException.class);
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));

        release.countDown();
        assertThat(await(start(admission.run(TENANT_B, () -> "after")))).isEqualTo("after");
        assertThat(ran).isFalse();
    }

    @Test
    @DisplayName("a refusal tells the caller when to retry")
    void refusalCarriesRetryAfter() throws Exception {
        Argon2Admission admission = admission(0, 1.0, Duration.ofMillis(1500));
        blockWorker(admission, TENANT_A);
        assertThatThrownBy(() -> await(start(admission.run(TENANT_B, () -> "x"))))
                .isInstanceOfSatisfying(CredentialVerificationBusyException.class,
                        busy -> assertThat(busy.retryAfterSeconds()).isEqualTo(2));
    }

    @Test
    @DisplayName("an exception from the work reaches the caller and frees the slot")
    void failuresPropagateAndRelease() throws Exception {
        Argon2Admission admission = admission(0, 1.0, Duration.ofSeconds(1));
        assertThatThrownBy(() -> await(start(admission.<String>run(TENANT_A, () -> {
            throw new IllegalStateException("boom");
        })))).hasMessageContaining("boom");
        assertThat(await(start(admission.run(TENANT_A, () -> "next")))).isEqualTo("next");
    }
}
