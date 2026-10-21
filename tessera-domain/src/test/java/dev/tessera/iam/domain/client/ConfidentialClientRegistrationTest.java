package dev.tessera.iam.domain.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.client.grant.ClientCredentials;
import dev.tessera.iam.domain.client.grant.GrantType;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("ConfidentialClient — client_credentials scopes, audiences and roles")
class ConfidentialClientRegistrationTest {

    private static final Set<GrantType> CC = Set.of(new ClientCredentials());

    private static ConfidentialClient client(Set<String> scopes, Set<String> audiences, List<String> roles) {
        return new ConfidentialClient(ClientId.generate(), new RealmKey(TenantId.generate(), BaselineId.generate()),
                CC, ClientAuthMethod.CLIENT_SECRET, Set.of(), scopes, audiences, roles);
    }

    @Test
    @DisplayName("the five-argument form means nothing is registered")
    void fiveArgumentFormRegistersNothing() {
        ConfidentialClient client = new ConfidentialClient(ClientId.generate(),
                new RealmKey(TenantId.generate(), BaselineId.generate()), CC, ClientAuthMethod.CLIENT_SECRET,
                Set.of());
        assertThat(client.allowedScopes()).isEmpty();
        assertThat(client.audiences()).isEmpty();
        assertThat(client.roles()).isEmpty();
    }

    @Test
    @DisplayName("the lists are defensive, unmodifiable copies that keep their order")
    void listsAreDefensiveCopies() {
        Set<String> scopes = new LinkedHashSet<>(List.of("orders.read", "orders.write"));
        Set<String> audiences = new LinkedHashSet<>(List.of("https://orders.example", "https://billing.example"));
        List<String> roles = new ArrayList<>(List.of("ops", "reader"));
        ConfidentialClient client = client(scopes, audiences, roles);

        scopes.add("admin");
        audiences.clear();
        roles.add("root");

        assertThat(client.allowedScopes()).containsExactly("orders.read", "orders.write");
        assertThat(client.audiences()).containsExactly("https://orders.example", "https://billing.example");
        assertThat(client.roles()).containsExactly("ops", "reader");
        assertThatThrownBy(() -> client.allowedScopes().add("admin"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> client.audiences().add("https://other.example"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> client.roles().add("root")).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("null lists are refused")
    void nullListsAreRefused() {
        assertThatThrownBy(() -> client(null, Set.of(), List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client(Set.of(), null, List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client(Set.of(), Set.of(), null)).isInstanceOf(IllegalArgumentException.class);
    }

    @ParameterizedTest(name = "[{0}]")
    @ValueSource(strings = {"", " ", "orders read", "orders\tread", "say\"hi", "back\\slash", "café"})
    @DisplayName("a scope outside the RFC 6749 §3.3 scope-token syntax is refused")
    void invalidScopesAreRefused(String scope) {
        assertThatThrownBy(() -> client(Set.of(scope), Set.of(), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("printable scope tokens such as orders:read or api/v1 are accepted")
    void validScopesAreAccepted() {
        assertThat(client(Set.of("orders:read", "api/v1", "a!#$%&'()*+,-./:;<=>?@[]^_`{|}~"), Set.of(), List.of())
                .allowedScopes()).hasSize(3);
    }

    @ParameterizedTest(name = "[{0}]")
    @ValueSource(strings = {"", " ", "two words", "tab\there"})
    @DisplayName("a blank audience or role, or one with whitespace, is refused")
    void blankOrSpacedAudiencesAndRolesAreRefused(String value) {
        assertThatThrownBy(() -> client(Set.of(), Set.of(value), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client(Set.of(), Set.of(), List.of(value)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("a null element is an IllegalArgumentException, not a NullPointerException")
    void nullElementsAreRefused() {
        Set<String> withNull = new LinkedHashSet<>(Arrays.asList("orders.read", null));
        assertThatThrownBy(() -> client(withNull, Set.of(), List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client(Set.of(), withNull, List.of())).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> client(Set.of(), Set.of(), Arrays.asList("ops", null)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
