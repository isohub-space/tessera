package dev.tessera.iam.adapter.persistence.client;

import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.core.WorkerExecutor;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Disposes;
import jakarta.enterprise.inject.Produces;
import jakarta.inject.Named;

/**
 * Produces the dedicated {@code argon2} worker executor used by {@link Argon2ClientSecretVerifier}
 * to run Argon2id off the reactive event loop on its own bounded pool — isolating the CPU/memory-
 * hard hashing from the shared Vert.x worker pool so an invalid-credential flood cannot starve
 * other blocking work.
 *
 * <p>{@code createSharedWorkerExecutor} is reference-counted; the {@link Disposes} observer releases
 * it when the application-scoped bean is destroyed at shutdown.
 */
@ApplicationScoped
public class Argon2ExecutorProducer {

    @Produces
    @ApplicationScoped
    @Named("argon2")
    WorkerExecutor argon2Executor(Vertx vertx, Argon2PoolConfig config) {
        return vertx.createSharedWorkerExecutor("argon2", config.poolSize());
    }

    void closeArgon2Executor(@Disposes @Named("argon2") WorkerExecutor executor) {
        executor.close();
    }
}
