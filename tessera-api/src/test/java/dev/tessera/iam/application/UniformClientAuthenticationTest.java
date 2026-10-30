package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.in.IntrospectUseCase.IntrospectCommand;
import dev.tessera.iam.application.port.in.IntrospectUseCase.IntrospectionResult;
import dev.tessera.iam.application.port.in.RevokeUseCase.RevokeCommand;
import dev.tessera.iam.application.port.in.RevokeUseCase.RevokeResult;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort;
import dev.tessera.iam.application.port.out.ClientRepositoryPort;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.application.port.out.RefreshTokenStorePort;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.ClientAuthMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.client.ConfidentialClient;
import dev.tessera.iam.domain.client.PublicClient;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.refresh.FamilyId;
import dev.tessera.iam.domain.refresh.RefreshTokenFamily;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * {@code /introspect} and {@code /revoke} authenticate the caller at the same cost whatever the
 * outcome: the secret verifier runs exactly once, so the response time does not tell whether a
 * {@code client_id} exists. Unknown and public clients are verified against the per-id sentinel.
 * Only a confidential client introspects; a public client may still revoke its own tokens.
 */
@DisplayName("Client authentication on /introspect and /revoke — one verifier call on every path")
class UniformClientAuthenticationTest {

    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final RealmKey OTHER = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final String SECRET = "the-secret";
    private static final ClientId RESOURCE_SERVER = new ClientId(UUID.randomUUID());

    private final List<ClientId> verified = new ArrayList<>();

    private final Map<String, Client> registry = Map.of(
            "resource-server", new ConfidentialClient(RESOURCE_SERVER, REALM, Set.of(new AuthorizationCode()),
                    ClientAuthMethod.CLIENT_SECRET, Set.of()),
            "spa", new PublicClient(new ClientId(UUID.randomUUID()), REALM, Set.of(new AuthorizationCode()),
                    Set.of()));

    private final ClientRepositoryPort clients = (realm, clientId) ->
            Uni.createFrom().item(realm.equals(REALM) ? registry.get(clientId) : null);

    private final ClientSecretVerifierPort verifier = (realm, id, secret) -> {
        verified.add(id);
        return Uni.createFrom().item(RESOURCE_SERVER.equals(id) && SECRET.equals(secret));
    };

    private final RefreshTokenStorePort refreshStore = new RefreshTokenStorePort() {
        @Override
        public Uni<Void> createFamily(RefreshTokenFamily family) {
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<RefreshConsumeOutcome> consumeAndRotate(FamilyId id, RealmKey realm, String presentedHash,
                String newTokenHash, Instant now, Duration reuseGrace, String rotationSalt) {
            return Uni.createFrom().nullItem();
        }

        @Override
        public Uni<Void> revokeFamily(FamilyId id, RealmKey realm) {
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<Void> revokeFamiliesOf(RealmKey realm, String userId, ClientId clientId, Instant createdBefore) {
            return Uni.createFrom().voidItem();
        }

        @Override
        public Uni<RefreshTokenFamily> find(FamilyId id, RealmKey realm) {
            return Uni.createFrom().nullItem();
        }
    };

    private final AccessTokenIntrospectorPort accessTokens =
            (realm, token) -> Uni.createFrom().item(Optional.empty());

    private IntrospectionResult introspect(RealmKey realm, String clientId, String secret) {
        verified.clear();
        return new IntrospectService(clients, verifier, refreshStore, accessTokens, Clock.systemUTC())
                .introspect(new IntrospectCommand(realm, "a.b.c", null, clientId, secret))
                .await().indefinitely();
    }

    private RevokeResult revoke(RealmKey realm, String clientId, String secret) {
        verified.clear();
        return new RevokeService(clients, verifier, refreshStore)
                .revoke(new RevokeCommand(realm, "a.b.c", null, clientId, secret))
                .await().indefinitely();
    }

    @Test
    @DisplayName("/introspect: unknown, other-tenant, public, missing and wrong secret, and success each verify once")
    void introspectVerifiesOnceOnEveryPath() {
        assertThat(introspect(REALM, "nobody", SECRET)).isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
        assertThat(verified).containsExactly(ClientSecretVerifierPort.unknownClient("nobody"));
        assertThat(introspect(OTHER, "resource-server", SECRET))
                .isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
        assertThat(verified).containsExactly(ClientSecretVerifierPort.unknownClient("resource-server"));
        assertThat(introspect(REALM, "resource-server", null))
                .isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
        assertThat(verified).containsExactly(RESOURCE_SERVER);
        assertThat(introspect(REALM, "resource-server", "wrong"))
                .isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
        assertThat(verified).containsExactly(RESOURCE_SERVER);
        assertThat(introspect(REALM, "resource-server", SECRET)).isInstanceOf(IntrospectionResult.Inactive.class);
        assertThat(verified).containsExactly(RESOURCE_SERVER);
        // A public client cannot introspect (RFC 7662 §4): refused at the same cost, with or
        // without a secret, so the refusal does not tell a public client from an unknown one.
        assertThat(introspect(REALM, "spa", null))
                .isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
        assertThat(verified).containsExactly(ClientSecretVerifierPort.unknownClient("spa"));
        assertThat(introspect(REALM, "spa", SECRET))
                .isInstanceOf(IntrospectionResult.ClientAuthenticationFailed.class);
        assertThat(verified).containsExactly(ClientSecretVerifierPort.unknownClient("spa"));
    }

    @Test
    @DisplayName("/revoke: unknown, other-tenant, public, missing and wrong secret, and success each verify once")
    void revokeVerifiesOnceOnEveryPath() {
        assertThat(revoke(REALM, "nobody", SECRET)).isInstanceOf(RevokeResult.ClientAuthenticationFailed.class);
        assertThat(verified).containsExactly(ClientSecretVerifierPort.unknownClient("nobody"));
        assertThat(revoke(OTHER, "resource-server", SECRET)).isInstanceOf(RevokeResult.ClientAuthenticationFailed.class);
        assertThat(verified).hasSize(1);
        assertThat(revoke(REALM, "resource-server", null)).isInstanceOf(RevokeResult.ClientAuthenticationFailed.class);
        assertThat(verified).containsExactly(RESOURCE_SERVER);
        assertThat(revoke(REALM, "resource-server", "wrong")).isInstanceOf(RevokeResult.ClientAuthenticationFailed.class);
        assertThat(verified).containsExactly(RESOURCE_SERVER);
        assertThat(revoke(REALM, "resource-server", SECRET)).isInstanceOf(RevokeResult.Done.class);
        assertThat(verified).containsExactly(RESOURCE_SERVER);
        assertThat(revoke(REALM, "spa", null)).isInstanceOf(RevokeResult.Done.class);
        assertThat(verified).hasSize(1);
    }

    @Test
    @DisplayName("each presented client_id has its own sentinel, which no registration can hold")
    void sentinelsArePerIdAndReserved() {
        ClientId nobody = ClientSecretVerifierPort.unknownClient("nobody");
        assertThat(ClientSecretVerifierPort.unknownClient("nobody")).isEqualTo(nobody);
        assertThat(ClientSecretVerifierPort.unknownClient("somebody")).isNotEqualTo(nobody);
        assertThat(ClientSecretVerifierPort.isReserved(nobody.value())).isTrue();
        assertThat(ClientSecretVerifierPort.isReserved(new UUID(0L, 0L))).isTrue();
        assertThat(ClientSecretVerifierPort.isReserved(UUID.randomUUID())).isFalse();
    }
}
