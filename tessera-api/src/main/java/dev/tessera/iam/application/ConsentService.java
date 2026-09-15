package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.ConsentUseCase;
import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.Set;

/**
 * Application service for the consent step. Framework-free, mirroring
 * {@link AuthorizationService}'s shape; a thin pass-through to {@link ConsentStorePort} today
 * because the granularity decision (see {@link ConsentUseCase}) leaves no further business
 * rule to enforce here yet — this is the seam a future rule (e.g. re-consent after a scope
 * addition, or consent expiry) would land in without touching callers.
 */
public final class ConsentService implements ConsentUseCase {

    private final ConsentStorePort consents;

    public ConsentService(ConsentStorePort consents) {
        if (consents == null) {
            throw new IllegalArgumentException("consents must not be null");
        }
        this.consents = consents;
    }

    @Override
    public Uni<Boolean> hasConsented(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        validate(realm, subjectId, clientId, scopes);
        return consents.hasConsent(realm, subjectId, clientId, scopes);
    }

    @Override
    public Uni<Void> recordConsent(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        validate(realm, subjectId, clientId, scopes);
        return consents.grant(realm, subjectId, clientId, scopes);
    }

    private static void validate(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        if (subjectId == null || subjectId.isBlank()) {
            throw new IllegalArgumentException("subjectId must not be blank");
        }
        if (clientId == null) {
            throw new IllegalArgumentException("clientId must not be null");
        }
        if (scopes == null) {
            throw new IllegalArgumentException("scopes must not be null");
        }
    }
}
