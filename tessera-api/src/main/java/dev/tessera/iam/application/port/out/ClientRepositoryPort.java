package dev.tessera.iam.application.port.out;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.tenancy.RealmKey;

/**
 * Outbound port that resolves a registered {@link Client} from the wire
 * {@code client_id} string, scoped to a realm.
 *
 * <p>The OAuth {@code client_id} on the wire is an opaque registration handle; the
 * domain reasons over the resolved {@link Client} (and its {@link dev.tessera.iam.domain.client.ClientId}),
 * not the string. Implementations <strong>must</strong> resolve within the supplied
 * {@link RealmKey}'s tenant scope (RLS fail-closed) and never return a client from
 * another tenant.
 */
public interface ClientRepositoryPort {

    /**
     * Resolves a client by its wire {@code client_id} within a realm.
     *
     * @param realm    the realm (tenant key) to resolve within (RLS-scoped)
     * @param clientId the wire {@code client_id} string presented by the client
     * @return a {@link Uni} emitting the resolved {@link Client}, or {@code null} if no
     *         such client is registered in the realm
     */
    Uni<Client> findByClientId(RealmKey realm, String clientId);
}
