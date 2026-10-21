package dev.tessera.iam.adapter.persistence.client;

import dev.tessera.iam.application.port.out.CredentialVerificationBusyException;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.core.WorkerExecutor;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Admission control in front of the {@code argon2} worker pool, shared by client-secret and
 * password verification.
 *
 * <p>Every verification costs one Argon2id pass, also for a {@code client_id} that does not exist,
 * so that the cost does not reveal whether it exists. Without a bound, a flood of made-up ids would
 * queue on the pool without limit and slow every authentication on the node. This class bounds it:
 * <ul>
 *   <li>at most {@code poolSize + maxWaiting} verifications are admitted at once (running plus
 *       waiting); past that a request is refused immediately;</li>
 *   <li>one tenant may hold at most {@code tenantShare} of that cap, so a flood through one tenant
 *       leaves room for the others;</li>
 *   <li>a request that is still waiting for a worker after {@code waitDeadline} is refused, and its
 *       verification never runs.</li>
 * </ul>
 * A refusal is a {@link CredentialVerificationBusyException}, answered {@code 503} with
 * {@code Retry-After}. It depends only on load, never on the client or its credential, so it
 * reveals nothing about either.
 *
 * <p>The tenant is the one the request was resolved to: the fixed tenant, or the gateway-asserted
 * {@code X-Tenant-Id}. In header mode the per-tenant share is only as strong as the edge's
 * stripping of a client-supplied {@code X-Tenant-Id}, since a caller who can set it can spread a
 * flood across made-up tenants; it firms up once unknown tenants are refused.
 */
@ApplicationScoped
public class Argon2Admission {

    private static final int WAITING = 0;
    private static final int STARTED = 1;
    private static final int ABANDONED = 2;

    private final Vertx vertx;
    private final WorkerExecutor executor;
    private final int cap;
    private final int tenantCap;
    private final Duration waitDeadline;
    private final AtomicInteger admitted = new AtomicInteger();
    private final ConcurrentMap<UUID, AtomicInteger> admittedByTenant = new ConcurrentHashMap<>();

    @Inject
    Argon2Admission(Vertx vertx, @Named("argon2") WorkerExecutor executor, Argon2PoolConfig config) {
        this(vertx, executor, config.poolSize(), config.maxWaiting(), config.tenantShare(), config.waitDeadline());
    }

    Argon2Admission(Vertx vertx, WorkerExecutor executor, int poolSize, int maxWaiting, double tenantShare,
            Duration waitDeadline) {
        if (poolSize < 1 || maxWaiting < 0 || tenantShare <= 0 || tenantShare > 1
                || waitDeadline.isZero() || waitDeadline.isNegative()) {
            throw new IllegalArgumentException("invalid argon2 admission settings");
        }
        this.vertx = vertx;
        this.executor = executor;
        this.cap = poolSize + maxWaiting;
        this.tenantCap = Math.max(1, (int) Math.floor(cap * tenantShare));
        this.waitDeadline = waitDeadline;
    }

    /**
     * Runs {@code work} on the {@code argon2} pool if admitted.
     *
     * @param tenant the tenant the request was resolved to
     * @param work   the blocking verification
     * @return its result, or a {@link CredentialVerificationBusyException} failure when refused
     */
    public <T> Uni<T> run(UUID tenant, Callable<T> work) {
        // Admission happens per subscription, so each subscription holds and frees its own slot.
        return Uni.createFrom().deferred(() -> admit(tenant) ? admitted(tenant, work) : Uni.createFrom().failure(busy()));
    }

    private <T> Uni<T> admitted(UUID tenant, Callable<T> work) {
        AtomicInteger state = new AtomicInteger(WAITING);
        return Uni.createFrom().emitter(emitter -> {
            long timer = vertx.setTimer(waitDeadline.toMillis(), id -> {
                if (state.compareAndSet(WAITING, ABANDONED)) {
                    emitter.fail(busy());
                }
            });
            executor.<T>executeBlocking(() -> state.compareAndSet(WAITING, STARTED) ? work.call() : null, false)
                    .subscribe().with(
                            result -> {
                                vertx.cancelTimer(timer);
                                release(tenant);
                                if (state.get() == STARTED) {
                                    emitter.complete(result);
                                }
                            },
                            failure -> {
                                vertx.cancelTimer(timer);
                                release(tenant);
                                if (state.get() == STARTED) {
                                    emitter.fail(failure);
                                }
                            });
        });
    }

    private boolean admit(UUID tenant) {
        AtomicInteger forTenant = admittedByTenant.computeIfAbsent(tenant, t -> new AtomicInteger());
        if (forTenant.incrementAndGet() > tenantCap) {
            forTenant.decrementAndGet();
            return false;
        }
        if (admitted.incrementAndGet() > cap) {
            admitted.decrementAndGet();
            forTenant.decrementAndGet();
            return false;
        }
        return true;
    }

    /** Frees the slot once the pool has dequeued the task, run or abandoned. */
    private void release(UUID tenant) {
        admitted.decrementAndGet();
        admittedByTenant.computeIfPresent(tenant, (t, count) -> count.decrementAndGet() == 0 ? null : count);
    }

    private CredentialVerificationBusyException busy() {
        return new CredentialVerificationBusyException((waitDeadline.toMillis() + 999) / 1000);
    }
}
