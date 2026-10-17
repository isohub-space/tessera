package dev.tessera.iam.adapter.persistence.rls;

import dev.tessera.iam.adapter.persistence.db.ConnectionFailures;
import dev.tessera.iam.adapter.persistence.db.PoolDiagnostics;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.hibernate.reactive.mutiny.Mutiny;
import org.jboss.logging.Logger;

/**
 * The single chokepoint for tenant-scoped database access.
 *
 * <p>Every read or write of a row-level-security-protected table must go through this
 * bean so that {@code app.tenant_id} is set on the connection at the start of each
 * transaction. The PostgreSQL RLS policy compares {@code tenant_id} to that GUC, so a
 * transaction that does not bind a tenant sees nothing and may write nothing — the
 * schema fails closed. Centralising the {@code set_config(...)} call means no adapter
 * can accidentally talk to the database without a tenant bound.
 *
 * <p>A unit of work is attempted again only when it failed before its work function was called:
 * while the transaction began or the tenant was bound, with a connection failure, or because no
 * connection was handed over within the pool's acquisition timeout ({@link ConnectionFailures}).
 * The work function is called only after the server has answered the tenant binding, and its
 * statements are issued only from inside it, so at that point the server has seen at most
 * {@code BEGIN} and the transaction-local {@code set_config} of a transaction that never commits:
 * running the unit again cannot apply anything twice, for a read or for a write. A failure after
 * the work function was called, including at commit, is never retried, because the outcome of what
 * was sent is unknown.
 *
 * <p>Reads ({@link #inTenantRead}) may be attempted again {@code iam.db.read-retries} more times
 * (default 1), writes ({@link #inTenant}) {@code iam.db.write-retries} more times (default 1). Which
 * operations use which path is pinned by {@code ReadRetryScopeArchTest}.
 */
@ApplicationScoped
public class TenantScopedSession {

    private static final Logger LOG = Logger.getLogger(TenantScopedSession.class);

    // Injected lazily so this adapter does not force the persistence unit active. In a
    // Docker-free launcher profile with no datasource the session factory is an inactive
    // bean; resolving it only on use keeps the rest of the application bootable.
    @Inject
    Instance<Mutiny.SessionFactory> sessionFactory;

    @Inject
    PoolDiagnostics diagnostics;

    @ConfigProperty(name = "iam.db.read-retries", defaultValue = "1")
    int readRetries;

    @ConfigProperty(name = "iam.db.write-retries", defaultValue = "1")
    int writeRetries;

    /**
     * Runs {@code work} in a single transaction scoped to {@code tenantId}: it sets the
     * RLS GUC first, then hands the session to the supplied function. Retried only when it fails
     * before {@code work} is called (see the class description).
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param work     the unit of work to run against the scoped session
     * @param <T>      the result type
     * @return a {@link Uni} emitting the work's result
     */
    public <T> Uni<T> inTenant(UUID tenantId, Function<Mutiny.Session, Uni<T>> work) {
        return attemptWrite(tenantId, work, writeRetries);
    }

    private <T> Uni<T> attemptWrite(
            UUID tenantId, Function<Mutiny.Session, Uni<T>> work, int retriesLeft) {
        return Uni.createFrom().deferred(() -> {
            AtomicBoolean workStarted = new AtomicBoolean();
            long started = System.nanoTime();
            return transaction(tenantId, work, workStarted, started)
                    .onFailure(failure -> retriesLeft > 0
                            && !workStarted.get()
                            && ConnectionFailures.isRetryableBeforeWork(failure))
                    .recoverWithUni(failure -> {
                        LOG.infof("Database connection failed before a write started (%s; %s); none of its "
                                + "statements was sent, trying again", failure.getMessage(), diagnostics.state());
                        return ConnectionFailures.pauseBeforeRetry()
                                .chain(() -> attemptWrite(tenantId, work, retriesLeft - 1));
                    });
        });
    }

    /**
     * As {@link #inTenant}, for a unit of work that only reads. When the connection fails before
     * {@code work} has started (the transaction could not begin, or binding the tenant failed), or
     * no connection became free in time, the transaction is attempted again, at most
     * {@code iam.db.read-retries} more times. A failure after {@code work} started is never
     * retried, and neither is a failure that is not a connection failure ({@link ConnectionFailures}).
     *
     * <p>The same rule as {@link #inTenant}, with its own budget; the separate path keeps the
     * reviewed read-only operations listed apart from the writes.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param work     the read-only unit of work to run against the scoped session
     * @param <T>      the result type
     * @return a {@link Uni} emitting the work's result
     */
    public <T> Uni<T> inTenantRead(UUID tenantId, Function<Mutiny.Session, Uni<T>> work) {
        return attemptRead(tenantId, work, readRetries);
    }

    private <T> Uni<T> attemptRead(
            UUID tenantId, Function<Mutiny.Session, Uni<T>> work, int retriesLeft) {
        return Uni.createFrom().deferred(() -> {
            AtomicBoolean workStarted = new AtomicBoolean();
            long started = System.nanoTime();
            return transaction(tenantId, work, workStarted, started)
                    .onFailure(failure -> retriesLeft > 0
                            && !workStarted.get()
                            && ConnectionFailures.isRetryableBeforeWork(failure))
                    .recoverWithUni(failure -> {
                        LOG.infof("Database connection failed before a read started (%s; %s); "
                                + "trying again", failure.getMessage(), diagnostics.state());
                        return ConnectionFailures.pauseBeforeRetry()
                                .chain(() -> attemptRead(tenantId, work, retriesLeft - 1));
                    });
        });
    }

    /**
     * One unit of work in its own session and transaction. The session is opened here rather than
     * through {@code SessionFactory.withTransaction}, which joins a session already bound to the
     * current Vert.x context at the moment it is called. The retries create each attempt when it is
     * subscribed, and with {@code withTransaction} units of work subscribed concurrently in one
     * request then shared a session, its connection and its tenant binding. A session of its own does
     * not depend on when a unit of work is created.
     */
    private <T> Uni<T> transaction(UUID tenantId, Function<Mutiny.Session, Uni<T>> work,
            AtomicBoolean workStarted, long started) {
        return sessionFactory.get().openSession().chain(session -> session
                .withTransaction(tx -> {
                    diagnostics.waited(System.nanoTime() - started);
                    return setScope(session, tenantId).chain(() -> {
                        workStarted.set(true);
                        return work.apply(session);
                    });
                })
                .onTermination().call(session::close));
    }

    private static Uni<String> setScope(Mutiny.Session session, UUID tenantId) {
        return session
                .createNativeQuery("select set_config('app.tenant_id', :tid, true)", String.class)
                .setParameter("tid", tenantId.toString())
                .getSingleResult();
    }
}
