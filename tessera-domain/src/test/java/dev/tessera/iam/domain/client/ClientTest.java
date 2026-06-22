package dev.tessera.iam.domain.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.ClientCredentials;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Client — sealed exhaustiveness + value invariants")
class ClientTest {

    private static RealmKey realm() {
        return new RealmKey(TenantId.generate(), BaselineId.generate());
    }

    /**
     * Exhaustive switch over the sealed {@link Client} hierarchy with no
     * {@code default} branch — adding a third client kind would break this build.
     */
    private static boolean canHoldSecret(Client client) {
        return switch (client) {
            case ConfidentialClient ignored -> true;
            case PublicClient ignored -> false;
        };
    }

    @Test
    @DisplayName("exhaustive switch distinguishes confidential from public")
    void exhaustiveSwitchOverClientKind() {
        Client confidential = new ConfidentialClient(
                ClientId.generate(), realm(), Set.of(new ClientCredentials()), ClientAuthMethod.MTLS);
        Client publicClient = new PublicClient(
                ClientId.generate(), realm(), Set.of(new AuthorizationCode()));

        assertThat(canHoldSecret(confidential)).isTrue();
        assertThat(canHoldSecret(publicClient)).isFalse();
    }

    @Test
    @DisplayName("a public client has no secret/auth-method field by construction")
    void publicClientHasNoAuthMethod() {
        // Compile-time guarantee: PublicClient simply has no ClientAuthMethod
        // component. We assert the type-level fact by reflection-free shape check.
        PublicClient publicClient = new PublicClient(
                ClientId.generate(), realm(), Set.of(new AuthorizationCode()));
        assertThat(publicClient.getClass().getRecordComponents())
                .extracting(java.lang.reflect.RecordComponent::getName)
                .containsExactlyInAnyOrder("id", "realm", "allowedGrants");
    }

    @Test
    @DisplayName("allowedGrants is defensively copied and unmodifiable")
    void allowedGrantsDefensivelyCopiedAndUnmodifiable() {
        Set<GrantType> mutable = new HashSet<>();
        mutable.add(new AuthorizationCode());

        ConfidentialClient client = new ConfidentialClient(
                ClientId.generate(), realm(), mutable, ClientAuthMethod.PRIVATE_KEY_JWT);

        // Mutating the source set after construction must not affect the client.
        mutable.add(new ClientCredentials());
        assertThat(client.allowedGrants()).hasSize(1);

        // And the exposed set is unmodifiable.
        assertThatThrownBy(() -> client.allowedGrants().add(new ClientCredentials()))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("rejects null/empty mandatory components")
    void rejectsInvalidComponents() {
        assertThatThrownBy(() -> new ConfidentialClient(
                null, realm(), Set.of(new ClientCredentials()), ClientAuthMethod.MTLS))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ConfidentialClient(
                ClientId.generate(), realm(), Set.of(), ClientAuthMethod.MTLS))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new ConfidentialClient(
                ClientId.generate(), realm(), Set.of(new ClientCredentials()), null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new PublicClient(
                ClientId.generate(), null, Set.of(new AuthorizationCode())))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
