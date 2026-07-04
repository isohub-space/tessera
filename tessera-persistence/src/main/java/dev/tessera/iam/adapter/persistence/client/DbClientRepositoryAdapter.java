package dev.tessera.iam.adapter.persistence.client;

import dev.tessera.iam.adapter.persistence.repository.OAuthClientRepository;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.UUID;

/**
 * Persistence-backed {@link ClientRepositoryPort}: resolves a registered client from the
 * wire {@code client_id} within the caller's realm.
 *
 * <p>All access is routed through {@link OAuthClientRepository}, which uses the tenant-scoped
 * session chokepoint, so the {@code oauth_client} row-level-security policy scopes the lookup
 * fail-closed — a client registered under another tenant is invisible here. Being a plain
 * {@code @ApplicationScoped} bean, it replaces the fail-closed {@code @DefaultBean} fallback
 * in the assembled server (mirroring {@code DbKeyProviderAdapter}); the REST module's own
 * tests, which do not have this module on the classpath, keep the fail-closed default.
 */
@ApplicationScoped
public class DbClientRepositoryAdapter implements ClientRepositoryPort {

    @Inject
    OAuthClientRepository clients;

    @Override
    public Uni<Client> findByClientId(RealmKey realm, String clientId) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        UUID tenantId = realm.tenant().value();
        UUID baselineId = realm.baseline().value();
        return clients.findByClientKey(tenantId, baselineId, clientId)
                .map(entity -> entity == null ? null : OAuthClientMapper.toDomain(entity));
    }
}
