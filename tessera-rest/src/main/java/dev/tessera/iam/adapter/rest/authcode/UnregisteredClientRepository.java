package dev.tessera.iam.adapter.rest.authcode;

import io.quarkus.arc.DefaultBean;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Fail-closed fallback {@link ClientRepositoryPort}: resolves <em>no</em> client.
 *
 * <p>The authoritative client registry is a persistence-backed adapter (a tenant-scoped,
 * RLS-protected store) provided by the persistence layer. This fallback exists so the
 * authorization-server assembly is bootable and the flow is fully wired even before that
 * adapter is present — and it is deliberately <strong>fail-closed</strong>: every
 * {@code client_id} resolves to {@code null} (an unknown client), so the authorization and
 * token endpoints refuse every request rather than accepting an unauthenticated one. There
 * is no configuration that turns this into an "allow" — a real registry must replace it.
 *
 * <p>{@link DefaultBean} makes it active only when no other {@link ClientRepositoryPort} bean
 * exists; the persistence adapter, once on the classpath, takes precedence automatically with
 * no wiring change here.
 */
@DefaultBean
@ApplicationScoped
public class UnregisteredClientRepository implements ClientRepositoryPort {

    @Override
    public Uni<Client> findByClientId(RealmKey realm, String clientId) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        // No client store wired: every client is unknown (fail-closed).
        return Uni.createFrom().nullItem();
    }
}
