package dev.tessera.iam.adapter.persistence.client;

import dev.tessera.iam.adapter.persistence.entity.OAuthClientEntity;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.ClientCredentials;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.client.grant.RefreshToken;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Maps a persisted {@link OAuthClientEntity} to the framework-free domain {@link Client}.
 *
 * <p>The domain deliberately excludes secret material, so this mapper carries only identity,
 * realm, kind and the allowed-grant set; the client secret stays in persistence and is
 * verified separately by {@link Argon2ClientSecretVerifier}. Corrupt registry data (an
 * unknown grant token, a confidential client with no auth method) fails loudly rather than
 * degrading into a silently weaker client.
 */
final class OAuthClientMapper {

    private OAuthClientMapper() {
    }

    static Client toDomain(OAuthClientEntity entity) {
        RealmKey realm = new RealmKey(new TenantId(entity.tenantId), new BaselineId(entity.baselineId));
        Set<GrantType> grants = parseGrants(entity.allowedGrants);
        Set<String> redirectUris = parseRedirectUris(entity.redirectUris);
        ClientId id = new ClientId(entity.id);
        return switch (entity.clientType) {
            case CONFIDENTIAL -> new ConfidentialClient(id, realm, grants, authMethod(entity), redirectUris);
            case PUBLIC -> new PublicClient(id, realm, grants, redirectUris);
        };
    }

    private static Set<String> parseRedirectUris(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        Set<String> uris = new LinkedHashSet<>();
        for (String token : value.split("\\s+")) {
            String uri = token.trim();
            if (!uri.isEmpty()) {
                uris.add(uri);
            }
        }
        return uris;
    }

    private static ClientAuthMethod authMethod(OAuthClientEntity entity) {
        if (entity.authMethod == null || entity.authMethod.isBlank()) {
            throw new IllegalStateException(
                    "Confidential client " + entity.id + " has no auth_method");
        }
        return ClientAuthMethod.valueOf(entity.authMethod);
    }

    private static Set<GrantType> parseGrants(String allowedGrants) {
        if (allowedGrants == null || allowedGrants.isBlank()) {
            throw new IllegalStateException("oauth_client.allowed_grants must not be empty");
        }
        Set<GrantType> grants = new LinkedHashSet<>();
        for (String token : allowedGrants.split(",")) {
            String value = token.trim();
            if (value.isEmpty()) {
                continue;
            }
            grants.add(toGrant(value));
        }
        if (grants.isEmpty()) {
            throw new IllegalStateException("oauth_client.allowed_grants had no valid grant");
        }
        return grants;
    }

    private static GrantType toGrant(String wireValue) {
        return switch (wireValue) {
            case "authorization_code" -> new AuthorizationCode();
            case "client_credentials" -> new ClientCredentials();
            case "refresh_token" -> new RefreshToken();
            default -> throw new IllegalStateException("Unknown grant_type in registry: " + wireValue);
        };
    }
}
