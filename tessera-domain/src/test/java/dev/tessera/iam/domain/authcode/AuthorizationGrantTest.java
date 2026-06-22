package dev.tessera.iam.domain.authcode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Validates the single-use authorization-code payload and its token-endpoint bindings. */
@DisplayName("AuthorizationGrant — code-bound state and exact redirect-uri match")
class AuthorizationGrantTest {

    private static final String CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private static final Instant ISSUED = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant EXPIRES = ISSUED.plusSeconds(60);

    private static AuthorizationGrant grant(String redirectUri) {
        RealmKey realm = new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L)));
        return new AuthorizationGrant(
                realm,
                ClientId.generate(),
                "user-123",
                redirectUri,
                Set.of("openid", "profile"),
                "n-0S6_WzA2Mj",
                CodeChallenge.s256(CHALLENGE),
                ISSUED,
                EXPIRES);
    }

    @Test
    @DisplayName("redirect_uri match is exact — no prefix or substring matching")
    void exactRedirectUriMatch() {
        AuthorizationGrant g = grant("https://app.example/callback");
        assertThat(g.redirectUriMatches("https://app.example/callback")).isTrue();
        // A registered-prefix attack: a longer or shorter URI must not match.
        assertThat(g.redirectUriMatches("https://app.example/callback/evil")).isFalse();
        assertThat(g.redirectUriMatches("https://app.example/call")).isFalse();
        assertThat(g.redirectUriMatches("https://app.example/callback?x=1")).isFalse();
        assertThat(g.redirectUriMatches(null)).isFalse();
    }

    @Test
    @DisplayName("expiry is computed against the threaded-in clock")
    void expiry() {
        AuthorizationGrant g = grant("https://app.example/callback");
        assertThat(g.isExpired(ISSUED)).isFalse();
        assertThat(g.isExpired(EXPIRES.minusSeconds(1))).isFalse();
        assertThat(g.isExpired(EXPIRES)).isTrue();
        assertThat(g.isExpired(EXPIRES.plusSeconds(1))).isTrue();
    }

    @Test
    @DisplayName("rejects an expiry that is not after issuance")
    void rejectsBadExpiry() {
        RealmKey realm = new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L)));
        assertThatThrownBy(() -> new AuthorizationGrant(
                realm, ClientId.generate(), "u", "https://a/b", Set.of("openid"),
                "nonce", CodeChallenge.s256(CHALLENGE), ISSUED, ISSUED))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
