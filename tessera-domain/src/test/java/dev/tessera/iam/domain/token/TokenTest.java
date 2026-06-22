package dev.tessera.iam.domain.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@DisplayName("Token — sealed exhaustiveness + ClaimSet/Confirmation invariants")
class TokenTest {

    /**
     * Exhaustive switch over the sealed {@link Token} hierarchy with no
     * {@code default} branch — a new token kind would break this build.
     */
    private static String typ(Token token) {
        return switch (token) {
            case AccessToken ignored -> "at+jwt";
            case IdToken ignored -> "id_token";
            case RefreshToken ignored -> "refresh_token";
        };
    }

    static List<Token> allTokens() {
        ClaimSet claims = new ClaimSet(Map.of("sub", "user-123"));
        return List.of(
                new AccessToken(claims, new Confirmation.DpopJkt("thumbprint")),
                new IdToken(claims),
                new RefreshToken(claims));
    }

    @ParameterizedTest
    @MethodSource("allTokens")
    @DisplayName("exhaustive switch covers every token kind")
    void exhaustiveSwitchCoversAllKinds(Token token) {
        assertThat(typ(token)).isNotBlank();
        assertThat(token.claims()).isNotNull();
    }

    @Test
    @DisplayName("Confirmation is sealed over the two sender-constraining methods")
    void confirmationExhaustiveSwitch() {
        List<Confirmation> cnfs =
                List.of(new Confirmation.DpopJkt("jkt"), new Confirmation.MtlsX5tS256("x5t"));
        for (Confirmation cnf : cnfs) {
            String method = switch (cnf) {
                case Confirmation.DpopJkt ignored -> "dpop";
                case Confirmation.MtlsX5tS256 ignored -> "mtls";
            };
            assertThat(method).isNotBlank();
        }
    }

    @Test
    @DisplayName("AccessToken requires a non-null cnf (sender-constrained)")
    void accessTokenRequiresCnf() {
        assertThatThrownBy(() -> new AccessToken(ClaimSet.empty(), null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("ClaimSet is defensively copied and unmodifiable")
    void claimSetDefensivelyCopiedAndUnmodifiable() {
        Map<String, Object> mutable = new HashMap<>();
        mutable.put("sub", "user-1");
        ClaimSet claims = new ClaimSet(mutable);

        // Mutating the source map after construction must not affect the claim set.
        mutable.put("admin", true);
        assertThat(claims.claims()).hasSize(1);
        assertThat(claims.claim("sub")).contains("user-1");
        assertThat(claims.claim("admin")).isEmpty();

        // And the exposed map is unmodifiable.
        assertThatThrownBy(() -> claims.claims().put("x", "y"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("ClaimSet and Confirmation reject null/blank values")
    void valueInvariants() {
        assertThatThrownBy(() -> new ClaimSet(null))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Confirmation.DpopJkt("  "))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new Confirmation.MtlsX5tS256(null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
