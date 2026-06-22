package dev.tessera.iam.domain.authcode;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.token.ClaimSet;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/** Validates the RFC 9068 access-token and OIDC ID-token claim assembly. */
@DisplayName("IssuedTokenClaims — RFC 9068 access token + OIDC ID token")
class IssuedTokenClaimsTest {

    private static final String ISSUER = "https://issuer.example";
    private static final Instant IAT = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant EXP = IAT.plusSeconds(300);

    @Test
    @DisplayName("access token carries the RFC 9068 required claims, scope space-delimited")
    void accessTokenRequiredClaims() {
        ClaimSet claims = IssuedTokenClaims.accessToken(
                ISSUER, "user-1", "client-abc", Set.of("https://api.example"),
                new java.util.LinkedHashSet<>(List.of("openid", "profile")), "jti-1", IAT, EXP);

        assertThat(claims.claim("iss")).contains(ISSUER);
        assertThat(claims.claim("sub")).contains("user-1");
        assertThat(claims.claim("client_id")).contains("client-abc");
        assertThat(claims.claim("aud")).contains("https://api.example");
        assertThat(claims.claim("iat")).contains(IAT.getEpochSecond());
        assertThat(claims.claim("exp")).contains(EXP.getEpochSecond());
        assertThat(claims.claim("jti")).contains("jti-1");
        assertThat(claims.claim("scope")).contains("openid profile");
    }

    @Test
    @DisplayName("multi-valued audience is rendered as a JSON array")
    void multiAudience() {
        ClaimSet claims = IssuedTokenClaims.accessToken(
                ISSUER, "user-1", "client-abc",
                new java.util.LinkedHashSet<>(List.of("aud-a", "aud-b")),
                Set.of("openid"), "jti-1", IAT, EXP);
        assertThat(claims.claim("aud")).contains(List.of("aud-a", "aud-b"));
    }

    @Test
    @DisplayName("ID token binds the nonce and required OIDC claims")
    void idTokenBindsNonce() {
        ClaimSet claims = IssuedTokenClaims.idToken(
                ISSUER, "user-1", "client-abc", "n-0S6_WzA2Mj", IAT, EXP);

        assertThat(claims.claim("iss")).contains(ISSUER);
        assertThat(claims.claim("sub")).contains("user-1");
        assertThat(claims.claim("aud")).contains("client-abc");
        assertThat(claims.claim("nonce")).contains("n-0S6_WzA2Mj");
        assertThat(claims.claim("iat")).contains(IAT.getEpochSecond());
        assertThat(claims.claim("exp")).contains(EXP.getEpochSecond());
    }

    @Test
    @DisplayName("rejects an empty audience and a blank nonce")
    void rejectsBadInput() {
        assertThatThrownBy(() -> IssuedTokenClaims.accessToken(
                ISSUER, "u", "c", Set.of(), Set.of("openid"), "jti", IAT, EXP))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> IssuedTokenClaims.idToken(ISSUER, "u", "c", " ", IAT, EXP))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
