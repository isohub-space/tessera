package dev.tessera.iam.adapter.persistence.refresh;

import dev.tessera.iam.adapter.persistence.db.ConnectionFailures;
import dev.tessera.iam.application.port.out.RefreshTokenTenantResolverPort;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import java.util.Optional;
import java.util.UUID;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.hibernate.reactive.mutiny.Mutiny;

/**
 * Persistence-backed {@link RefreshTokenTenantResolverPort}: resolves a family's authoritative realm
 * from the {@code refresh_family_directory} table, header-independently.
 *
 * <p>The directory is deliberately <strong>not</strong> tenant-scoped (see the V6 migration), so
 * this lookup runs on a plain, <em>un-scoped</em> session — it must resolve a token's tenant
 * <em>before</em> any tenant is bound. That is the whole point: a replayed or stolen refresh token
 * is detected and its family revoked even when the caller sends a wrong or absent tenant header. The
 * directory exposes only {@code (family_id → tenant, baseline)}, never token material.
 */
@ApplicationScoped
public class DbRefreshTokenTenantResolver implements RefreshTokenTenantResolverPort {

    private static final String SELECT_OWNER =
            "SELECT tenant_id, baseline_id FROM refresh_family_directory WHERE family_id = :fid";

    // Injected lazily so a Docker-free launcher profile with no datasource stays bootable.
    @Inject
    Instance<Mutiny.SessionFactory> sessionFactory;

    // A pure read, so a connection that died while idle is retried on a fresh one, like the
    // tenant-scoped reads (TenantScopedSession.inTenantRead).
    @ConfigProperty(name = "iam.db.read-retries", defaultValue = "1")
    int readRetries;

    @Override
    public Uni<Optional<RealmKey>> resolveOwningRealm(FamilyId id) {
        if (id == null) {
            throw new IllegalArgumentException("id must not be null");
        }
        // Its own session: the lookup is created at subscription, when withSession could join a
        // session another unit of work has bound to the current Vert.x context.
        Uni<Optional<RealmKey>> read = Uni.createFrom().deferred(() ->
                sessionFactory.get().openSession().chain(session ->
                        session.createNativeQuery(SELECT_OWNER, Object[].class)
                                .setParameter("fid", id.value())
                                .getSingleResultOrNull()
                                .map(DbRefreshTokenTenantResolver::toRealm)
                                .onTermination().call(session::close)));
        return withRetries(read, readRetries);
    }

    private static <T> Uni<T> withRetries(Uni<T> read, int retriesLeft) {
        if (retriesLeft <= 0) {
            return read;
        }
        return read.onFailure(ConnectionFailures::isRetryableBeforeWork)
                .recoverWithUni(failure -> ConnectionFailures.pauseBeforeRetry()
                        .chain(() -> withRetries(read, retriesLeft - 1)));
    }

    private static Optional<RealmKey> toRealm(Object[] row) {
        if (row == null) {
            return Optional.empty();
        }
        UUID tenant = (UUID) row[0];
        UUID baseline = (UUID) row[1];
        return Optional.of(new RealmKey(new TenantId(tenant), new BaselineId(baseline)));
    }
}
