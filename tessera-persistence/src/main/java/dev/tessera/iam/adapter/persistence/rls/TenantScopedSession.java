package dev.tessera.iam.adapter.persistence.rls;

import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.util.UUID;
import java.util.function.Function;
import org.hibernate.reactive.mutiny.Mutiny;

/**
 * The single chokepoint for tenant-scoped database access.
 *
 * <p>Every read or write of a row-level-security-protected table must go through this
 * bean so that {@code app.tenant_id} is set on the connection at the start of each
 * transaction. The PostgreSQL RLS policy compares {@code tenant_id} to that GUC, so a
 * transaction that does not bind a tenant sees nothing and may write nothing — the
 * schema fails closed. Centralising the {@code set_config(...)} call means no adapter
 * can accidentally talk to the database without a tenant bound.
 */
@ApplicationScoped
public class TenantScopedSession {

    // Injected lazily so this adapter does not force the persistence unit active. In a
    // Docker-free launcher profile with no datasource the session factory is an inactive
    // bean; resolving it only on use keeps the rest of the application bootable.
    @Inject
    Instance<Mutiny.SessionFactory> sessionFactory;

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

    private static Uni<String> setScope(Mutiny.Session session, UUID tenantId) {
        return session
                .createNativeQuery("select set_config('app.tenant_id', :tid, true)", String.class)
                .setParameter("tid", tenantId.toString())
                .getSingleResult();
    }
}
