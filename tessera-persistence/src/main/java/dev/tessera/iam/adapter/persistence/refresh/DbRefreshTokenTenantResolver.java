package dev.tessera.iam.adapter.persistence.refresh;

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

    @Override
    public Uni<Optional<RealmKey>> resolveOwningRealm(FamilyId id) {
        if (id == null) {
            throw new IllegalArgumentException("id must not be null");
        }
        return sessionFactory.get().withSession(session ->
                session.createNativeQuery(SELECT_OWNER, Object[].class)
                        .setParameter("fid", id.value())
                        .getSingleResultOrNull()
                        .map(DbRefreshTokenTenantResolver::toRealm));
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
