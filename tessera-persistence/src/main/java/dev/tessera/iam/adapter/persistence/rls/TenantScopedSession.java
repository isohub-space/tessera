package dev.tessera.iam.adapter.persistence.rls;

import dev.tessera.iam.adapter.persistence.db.ConnectionFailures;
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
 * <p>Read-only units of work go through {@link #inTenantRead}, which survives a pooled connection
 * that died while idle: if the connection fails before the unit of work has started (while the
 * transaction begins or the tenant is bound), the whole transaction is attempted again on a fresh
 * connection, at most {@code iam.db.read-retries} more times (default 1). Units of work that write
 * use {@link #inTenant} and are never retried, so nothing can be applied twice.
 */
@ApplicationScoped
public class TenantScopedSession {

    private static final Logger LOG = Logger.getLogger(TenantScopedSession.class);

    // Injected lazily so this adapter does not force the persistence unit active. In a
    // Docker-free launcher profile with no datasource the session factory is an inactive
    // bean; resolving it only on use keeps the rest of the application bootable.
    @Inject
    Instance<Mutiny.SessionFactory> sessionFactory;

    @ConfigProperty(name = "iam.db.read-retries", defaultValue = "1")
    int readRetries;

    /**
     * Runs {@code work} in a single transaction scoped to {@code tenantId}: it sets the
     * RLS GUC first, then hands the session to the supplied function.
     *
     * @param tenantId the owning tenant (the RLS scoping key)
     * @param work     the unit of work to run against the scoped session
     * @param <T>      the result type
     * @return a {@link Uni} emitting the work's result
     */
    public <T> Uni<T> inTenant(UUID tenantId, Function<Mutiny.Session, Uni<T>> work) {
        return sessionFactory.get().withTransaction(
                (session, tx) -> setScope(session, tenantId).chain(() -> work.apply(session)));
    }

    /**
     * As {@link #inTenant}, for a unit of work that only reads. When the connection fails before
     * {@code work} has started (the transaction could not begin, or binding the tenant failed),
     * the transaction is attempted again on a fresh connection, at most {@code iam.db.read-retries}
     * more times. A failure after {@code work} started is never retried, and neither is a failure
     * that is not a connection failure ({@link ConnectionFailures}).
     *
     * <p>Only for work that reads. A retry happens only when nothing of {@code work} ran, so it
     * could not double-apply anything even for a write; limiting it to reads keeps that guarantee
     * from depending on where a connection happens to fail.
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
            return sessionFactory.get()
                    .withTransaction((session, tx) -> setScope(session, tenantId).chain(() -> {
                        workStarted.set(true);
                        return work.apply(session);
                    }))
                    .onFailure(failure -> retriesLeft > 0
                            && !workStarted.get()
                            && ConnectionFailures.isConnectionFailure(failure))
                    .recoverWithUni(failure -> {
                        LOG.infof("Database connection failed before a read started (%s); "
                                + "retrying on a fresh connection", failure.getMessage());
                        return ConnectionFailures.pauseBeforeRetry()
                                .chain(() -> attemptRead(tenantId, work, retriesLeft - 1));
                    });
        });
    }

    private static Uni<String> setScope(Mutiny.Session session, UUID tenantId) {
        return session
                .createNativeQuery("select set_config('app.tenant_id', :tid, true)", String.class)
                .setParameter("tid", tenantId.toString())
                .getSingleResult();
    }
}
