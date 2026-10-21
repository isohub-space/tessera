package dev.tessera.iam.adapter.persistence.client;

import dev.tessera.iam.application.port.out.CredentialVerificationBusyException;
import io.quarkus.runtime.Startup;
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
import java.util.concurrent.atomic.AtomicBoolean;
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
 * {@code X-Tenant-Id}. The share protects tenants from one flooding tenant, not from several:
 * {@code ceil(1 / tenantShare)} tenants flooding at once (two at the default half) fill the global
 * cap between them. In header mode the share is also only as strong as the edge's stripping of a
 * client-supplied {@code X-Tenant-Id}, since a caller who can set it can spread a flood across
 * made-up tenants; it firms up once unknown tenants are refused.
 *
 * <p>The settings are checked at startup ({@link Startup}), so a deployment with settings Vert.x
 * cannot honour fails to boot instead of failing its first authentication.
 */
@Startup
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
    /** Admitted verifications per tenant; an entry exists only while its count is positive. */
    private final ConcurrentMap<UUID, Integer> admittedByTenant = new ConcurrentHashMap<>();

    @Inject
    Argon2Admission(Vertx vertx, @Named("argon2") WorkerExecutor executor, Argon2PoolConfig config) {
        this(vertx, executor, config.poolSize(), config.maxWaiting(), config.tenantShare(), config.waitDeadline());
    }

    Argon2Admission(Vertx vertx, WorkerExecutor executor, int poolSize, int maxWaiting, double tenantShare,
            Duration waitDeadline) {
        if (poolSize < 1 || maxWaiting < 0) {
            throw new IllegalArgumentException("iam.argon2.pool-size must be at least 1 and max-waiting at least 0");
        }
        // Written so that NaN fails too.
        if (!(tenantShare > 0 && tenantShare <= 1)) {
            throw new IllegalArgumentException("iam.argon2.tenant-share must be in (0, 1], was " + tenantShare);
        }
        // Vert.x timers take whole milliseconds and refuse a delay below 1 ms.
        if (waitDeadline == null || waitDeadline.toMillis() < 1) {
            throw new IllegalArgumentException("iam.argon2.wait-deadline must be at least 1 ms, was " + waitDeadline);
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
        AtomicBoolean released = new AtomicBoolean();
        Runnable releaseOnce = () -> {
            if (released.compareAndSet(false, true)) {
                release(tenant);
            }
        };
        return Uni.createFrom().emitter(emitter -> {
            // A caller that goes away before a worker takes the task: skip its pass.
            emitter.onTermination(() -> state.compareAndSet(WAITING, ABANDONED));
            long timer = -1;
            try {
                timer = vertx.setTimer(waitDeadline.toMillis(), id -> {
                    if (state.compareAndSet(WAITING, ABANDONED)) {
                        emitter.fail(busy());
                    }
                });
                long armed = timer;
                executor.<T>executeBlocking(() -> state.compareAndSet(WAITING, STARTED) ? work.call() : null, false)
                        .subscribe().with(
                                result -> {
                                    vertx.cancelTimer(armed);
                                    releaseOnce.run();
                                    if (state.get() == STARTED) {
                                        emitter.complete(result);
                                    }
                                },
                                failure -> {
                                    vertx.cancelTimer(armed);
                                    releaseOnce.run();
                                    if (state.get() == STARTED || state.compareAndSet(WAITING, ABANDONED)) {
                                        emitter.fail(failure);
                                    }
                                });
            } catch (RuntimeException handOffFailed) {
                // Nothing reached the pool, so nothing will free the slot later: free it now.
                if (timer != -1) {
                    vertx.cancelTimer(timer);
                }
                releaseOnce.run();
                state.set(ABANDONED);
                emitter.fail(handOffFailed);
            }
        });
    }

    /** Admits one verification for {@code tenant} if both its share and the global cap allow it. */
    private boolean admit(UUID tenant) {
        boolean[] admittedNow = {false};
        // The tenant's check-and-increment happens inside one compute(), atomic with release's
        // decrement-and-remove, so no admission can count on an entry that is being removed.
        admittedByTenant.compute(tenant, (t, count) -> {
            int current = count == null ? 0 : count;
            if (current >= tenantCap) {
                return count;
            }
            if (admitted.incrementAndGet() > cap) {
                admitted.decrementAndGet();
                return count;
            }
            admittedNow[0] = true;
            return current + 1;
        });
        return admittedNow[0];
    }

    /** Frees one slot of {@code tenant}; called exactly once per admission. */
    private void release(UUID tenant) {
        // The global count moves inside the same compute() as the tenant's, mirroring admit(), so
        // the two never disagree for a tenant even for an instant.
        admittedByTenant.compute(tenant, (t, count) -> {
            admitted.decrementAndGet();
            return count == null || count <= 1 ? null : count - 1;
        });
    }

    /** Verifications admitted and not yet released, across tenants (for tests). */
    int admittedCount() {
        return admitted.get();
    }

    /** Tenants holding at least one admitted verification (for tests). */
    int trackedTenants() {
        return admittedByTenant.size();
    }

    private CredentialVerificationBusyException busy() {
        return new CredentialVerificationBusyException((waitDeadline.toMillis() + 999) / 1000);
    }
}
