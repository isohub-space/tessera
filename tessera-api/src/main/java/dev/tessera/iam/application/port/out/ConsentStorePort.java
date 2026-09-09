package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.Set;

/**
 * Outbound port for durable, tenant-scoped consent storage — backs the {@code consent}
 * table, unique on {@code (tenant, baseline, user, client)}.
 */
public interface ConsentStorePort {

    /**
     * Whether a prior recorded consent for {@code (subjectId, clientId)} covers at least
     * {@code scopes}.
     *
     * @param realm     the realm to check within (never {@code null})
     * @param subjectId the consenting end-user {@code sub} (never {@code null} or blank)
     * @param clientId  the client (never {@code null})
     * @param scopes    the scopes required (never {@code null}; may be empty)
     * @return a {@link Uni} emitting {@code true} iff a covering consent exists
     */
    Uni<Boolean> hasConsent(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes);

    /**
     * Records (or replaces) the consent for {@code (subjectId, clientId)}.
     *
     * @param realm     the realm to record within (never {@code null})
     * @param subjectId the consenting end-user {@code sub} (never {@code null} or blank)
     * @param clientId  the client (never {@code null})
     * @param scopes    the scopes consented to (never {@code null}; may be empty)
     * @return a {@link Uni} completing once the consent is durably recorded
     */
    Uni<Void> grant(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes);
}
