package dev.tessera.iam.adapter.persistence.consent;

import dev.tessera.iam.adapter.persistence.entity.ConsentEntity;
import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.repository.ConsentRepository;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Clock;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Persistence-backed {@link ConsentStorePort}, backed by the {@code consent} table (unique on
 * {@code (tenant, baseline, user, client)}) via {@link ConsentRepository}.
 *
 * <p>{@code consent.user_id} is the internal {@code iam_user.id}, while the port speaks in
 * terms of the stable {@code sub}; this adapter is where that translation happens (via
 * {@link UserRepository#findBySubject}), so callers never need to know the internal id
 * exists. A subject with no {@code iam_user} row (should not happen once a session exists,
 * but the port outlives that invariant) is treated fail-closed: no consent, and granting one
 * is a no-op — never a server error visible to a caller who is not otherwise authenticated.
 */
@ApplicationScoped
public class PersistentConsentStore implements ConsentStorePort {

    @Inject
    UserRepository users;

    @Inject
    ConsentRepository consents;

    private final Clock clock;

    /** CDI requires a no-arg constructor; uses the system UTC clock. */
    public PersistentConsentStore() {
        this(Clock.systemUTC());
    }

    /** Visible for testing: inject a fixed clock. */
    public PersistentConsentStore(Clock clock) {
        this.clock = clock;
    }

    @Override
    public Uni<Boolean> hasConsent(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        validate(realm, subjectId, clientId, scopes);
        UUID tenantId = realm.tenant().value();
        return users.findBySubject(tenantId, subjectId)
                .flatMap(user -> user == null
                        ? Uni.createFrom().item(false)
                        : consents.findByUserAndClient(tenantId, user.id, clientId.value())
                                .map(found -> covers(found, scopes)));
    }

    @Override
    public Uni<Void> grant(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        validate(realm, subjectId, clientId, scopes);
        UUID tenantId = realm.tenant().value();
        return users.findBySubject(tenantId, subjectId)
                .flatMap(user -> {
                    if (user == null) {
                        // No user row to attach the consent to — nothing durable to record.
                        // A caller only reaches here via an established session, whose
                        // subject is always backed by a user row; this is a defensive
                        // no-op, not the expected path.
                        return Uni.createFrom().voidItem();
                    }
                    return consents.persist(tenantId, newConsent(realm, user, clientId, scopes))
                            .replaceWithVoid();
                });
    }

    private ConsentEntity newConsent(RealmKey realm, UserEntity user, ClientId clientId, Set<String> scopes) {
        ConsentEntity entity = new ConsentEntity();
        entity.id = UUID.randomUUID();
        entity.tenantId = realm.tenant().value();
        entity.baselineId = realm.baseline().value();
        entity.userId = user.id;
        entity.clientId = clientId.value();
        entity.grantedScopes = String.join(" ", scopes);
        entity.grantedAt = clock.instant();
        entity.createdAt = entity.grantedAt;
        return entity;
    }

    private static boolean covers(ConsentEntity found, Set<String> requiredScopes) {
        if (found == null) {
            return requiredScopes.isEmpty();
        }
        Set<String> granted = parseScopes(found.grantedScopes);
        return granted.containsAll(requiredScopes);
    }

    private static Set<String> parseScopes(String scopes) {
        if (scopes == null || scopes.isBlank()) {
            return Set.of();
        }
        return new LinkedHashSet<>(Arrays.asList(scopes.trim().split("\\s+")));
    }

    private static void validate(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
        if (realm == null || subjectId == null || subjectId.isBlank() || clientId == null || scopes == null) {
            throw new IllegalArgumentException("realm, subjectId, clientId and scopes must not be null/blank");
        }
    }
}
