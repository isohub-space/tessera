package dev.tessera.iam.adapter.persistence.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.adapter.persistence.entity.ClientType;
import dev.tessera.iam.adapter.persistence.entity.OAuthClientEntity;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.RefreshToken;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OAuthClientMapper — entity → domain Client")
class OAuthClientMapperTest {

    private static OAuthClientEntity entity(ClientType type, String authMethod, String grants) {
        OAuthClientEntity e = new OAuthClientEntity();
        e.id = UUID.randomUUID();
        e.tenantId = UUID.randomUUID();
        e.baselineId = new UUID(0L, 0L);
        e.clientKey = "client-key";
        e.clientType = type;
        e.authMethod = authMethod;
        e.allowedGrants = grants;
        e.createdAt = Instant.EPOCH;
        return e;
    }

    @Test
    @DisplayName("confidential entity maps to a ConfidentialClient with its auth method and grants")
    void mapsConfidential() {
        OAuthClientEntity e = entity(ClientType.CONFIDENTIAL, "CLIENT_SECRET",
                "authorization_code,refresh_token");
        Client client = OAuthClientMapper.toDomain(e);
        assertThat(client).isInstanceOfSatisfying(ConfidentialClient.class, c -> {
            assertThat(c.id().value()).isEqualTo(e.id);
            assertThat(c.realm().tenant().value()).isEqualTo(e.tenantId);
            assertThat(c.authMethod()).isEqualTo(ClientAuthMethod.CLIENT_SECRET);
            assertThat(c.allowedGrants())
                    .containsExactlyInAnyOrder(new AuthorizationCode(), new RefreshToken());
        });
    }

    @Test
    @DisplayName("public entity maps to a PublicClient")
    void mapsPublic() {
        Client client = OAuthClientMapper.toDomain(entity(ClientType.PUBLIC, null, "authorization_code"));
        assertThat(client).isInstanceOf(PublicClient.class);
    }

    @Test
    @DisplayName("a confidential client with no auth method is rejected (bad registry data)")
    void confidentialWithoutAuthMethodRejected() {
        OAuthClientEntity e = entity(ClientType.CONFIDENTIAL, null, "authorization_code");
        assertThatThrownBy(() -> OAuthClientMapper.toDomain(e))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("an unknown grant_type token is rejected (bad registry data)")
    void unknownGrantRejected() {
        OAuthClientEntity e = entity(ClientType.PUBLIC, null, "authorization_code,implicit");
        assertThatThrownBy(() -> OAuthClientMapper.toDomain(e))
                .isInstanceOf(IllegalStateException.class);
    }
}
