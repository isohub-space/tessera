package dev.tessera.iam.domain.client.grant;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@DisplayName("GrantType — sealed exhaustiveness + RFC wire mapping")
class GrantTypeTest {

    /**
     * Exhaustive switch over the sealed {@link GrantType} hierarchy with
     * <strong>no {@code default} branch</strong>. This is the acceptance test: it
     * compiles only because the compiler can prove the three permitted members are
     * the whole hierarchy. Adding a (WON'T-list) member would break compilation
     * here — that broken build is the guarantee.
     */
    private static String rfcGrant(GrantType grant) {
        return switch (grant) {
            case AuthorizationCode ignored -> "authorization_code";
            case ClientCredentials ignored -> "client_credentials";
            case RefreshToken ignored -> "refresh_token";
        };
    }

    static List<GrantType> allGrants() {
        return List.of(new AuthorizationCode(), new ClientCredentials(), new RefreshToken());
    }

    @ParameterizedTest
    @MethodSource("allGrants")
    @DisplayName("exhaustive switch maps each grant to its RFC string")
    void exhaustiveSwitchMatchesWireValue(GrantType grant) {
        assertThat(rfcGrant(grant)).isEqualTo(grant.grantTypeValue());
    }

    @Test
    @DisplayName("the three permitted wire values are the modern, secure flows")
    void permittedWireValues() {
        assertThat(allGrants().stream().map(GrantType::grantTypeValue))
                .containsExactlyInAnyOrder(
                        "authorization_code", "client_credentials", "refresh_token");
    }
}
