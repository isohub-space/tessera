package dev.tessera.iam.domain.authcode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Validates that an authorization request is unrepresentable without mandatory PKCE. */
@DisplayName("AuthorizationRequest — PKCE mandatory by construction")
class AuthorizationRequestTest {

    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    private static RealmKey realm() {
        return new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L)));
    }

    @Test
    @DisplayName("a complete request is accepted and openid is detected")
    void acceptsComplete() {
        AuthorizationRequest req = new AuthorizationRequest(
                realm(), "client-1", "https://app/cb",
                new LinkedHashSet<>(List.of("openid", "email")),
                "state-1", "nonce-1", CodeChallenge.s256(CHALLENGE));
        assertThat(req.isOpenIdRequest()).isTrue();
        // LinkedHashSet input → insertion order is preserved through the defensive copy.
        assertThat(req.scopes()).containsExactly("openid", "email");
    }

    @Test
    @DisplayName("a request with no code challenge cannot be constructed")
    void rejectsMissingPkce() {
        assertThatThrownBy(() -> new AuthorizationRequest(
                realm(), "client-1", "https://app/cb", Set.of("openid"),
                "state-1", "nonce-1", null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("PKCE");
    }

    @Test
    @DisplayName("a request with a blank state or nonce is rejected")
    void rejectsBlankStateOrNonce() {
        assertThatThrownBy(() -> new AuthorizationRequest(
                realm(), "client-1", "https://app/cb", Set.of("openid"),
                " ", "nonce-1", CodeChallenge.s256(CHALLENGE)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AuthorizationRequest(
                realm(), "client-1", "https://app/cb", Set.of("openid"),
                "state-1", " ", CodeChallenge.s256(CHALLENGE)))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
