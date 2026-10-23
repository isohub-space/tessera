// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.persistence.client;

import dev.tessera.iam.adapter.persistence.entity.OAuthClientEntity;
import dev.tessera.iam.adapter.persistence.repository.OAuthClientRepository;
import dev.tessera.iam.application.port.out.ClientKeySourcePort;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Persistence-backed {@link ClientKeySourcePort}. For {@code private_key_jwt}: the client's
 * registered JWK Set, with its {@code client_id} as the assertion's expected {@code iss} and
 * {@code sub} (RFC 7523 §3). For a workload identity: the registered issuer and subject, with no
 * keys, since the issuer's apply.
 *
 * <p>The lookup is tenant-scoped through {@link OAuthClientRepository} (RLS fail-closed) and runs
 * for a sentinel id exactly as for a real one. Like {@link Argon2ClientSecretVerifier}, this plain
 * {@code @ApplicationScoped} bean replaces the fail-closed {@code @DefaultBean} fallback in the
 * assembled server.
 */
@ApplicationScoped
public class DbClientKeySource implements ClientKeySourcePort {

    @Inject
    OAuthClientRepository clients;

    @Override
    public Uni<AssertionTrust> trustFor(RealmKey realm, ClientId clientId) {
        if (realm == null || clientId == null) {
            throw new IllegalArgumentException("realm and clientId must not be null");
        }
        return clients.findById(realm.tenant().value(), clientId.value()).map(entity -> trust(entity, realm));
    }

    private static AssertionTrust trust(OAuthClientEntity entity, RealmKey realm) {
        if (entity == null || !realm.baseline().value().equals(entity.baselineId)) {
            return null;
        }
        if (ClientAuthMethod.PRIVATE_KEY_JWT.name().equals(entity.authMethod)
                && entity.jwks != null && !entity.jwks.isBlank()) {
            return new AssertionTrust(entity.clientKey, entity.clientKey, entity.jwks);
        }
        if (ClientAuthMethod.WORKLOAD_IDENTITY.name().equals(entity.authMethod)
                && present(entity.assertionIssuer) && present(entity.assertionSubject)) {
            return AssertionTrust.ofIssuer(entity.assertionIssuer, entity.assertionSubject);
        }
        return null;
    }

    private static boolean present(String value) {
        return value != null && !value.isBlank();
    }
}
