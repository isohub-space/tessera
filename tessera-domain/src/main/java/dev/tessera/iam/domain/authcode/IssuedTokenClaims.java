package dev.tessera.iam.domain.authcode;

import dev.tessera.iam.domain.token.ClaimSet;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Pure assembler for the <em>unsigned</em> claim sets the Authorization Code flow mints:
 * an RFC 9068 JWT access token and an OIDC ID token. Building the claims is deterministic
 * domain logic; JWS serialisation, the {@code typ}/{@code alg}/{@code kid} header and the
 * signature are adapter effects in the shell (this code reads no clock, no randomness, no
 * key — every time-, identity- and id-input is threaded in).
 *
 * <p>The result is a {@link ClaimSet} (the domain's unsigned token payload). The shell
 * wraps it as a JWS: for the access token with {@code typ: at+jwt} (RFC 9068 §2.1), for
 * the ID token with {@code typ: JWT}.
 */
public final class IssuedTokenClaims {

    private IssuedTokenClaims() {
    }

    /**
     * Builds the claim set for an RFC 9068 JWT access token (§2.2 required claims:
     * {@code iss}, {@code exp}, {@code aud}, {@code sub}, {@code client_id}, {@code iat},
     * {@code jti}).
     *
     * @param issuer    the OIDC {@code iss} (never {@code null} or blank)
     * @param subjectId the {@code sub} (never {@code null} or blank)
     * @param clientId  the wire {@code client_id} of the authorized client (never {@code null} or blank)
     * @param audience  the {@code aud} — the protected resource(s) the token is for
     *                  (never {@code null} or empty)
     * @param scopes    the granted scopes, rendered space-delimited into {@code scope}
     *                  (never {@code null})
     * @param jti       a unique token identifier for {@code jti} (never {@code null} or blank)
     * @param issuedAt  the {@code iat} instant (never {@code null})
     * @param expiresAt the {@code exp} instant (never {@code null}; after {@code issuedAt})
     * @return the unsigned RFC 9068 access-token claim set
     */
    public static ClaimSet accessToken(
            String issuer,
            String subjectId,
            String clientId,
            Set<String> audience,
            Set<String> scopes,
            String jti,
            Instant issuedAt,
            Instant expiresAt) {
        requireText(issuer, "issuer");
        requireText(subjectId, "subjectId");
        requireText(clientId, "clientId");
        requireText(jti, "jti");
        if (audience == null || audience.isEmpty()) {
            throw new IllegalArgumentException("access-token audience must not be empty");
        }
        if (scopes == null) {
            throw new IllegalArgumentException("access-token scopes must not be null");
        }
        requireOrder(issuedAt, expiresAt);

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", subjectId);
        // RFC 9068 §3: aud is a single string when there is one audience, else an array.
        claims.put("aud", audience.size() == 1 ? audience.iterator().next() : audience.stream().toList());
        claims.put("client_id", clientId);
        claims.put("iat", issuedAt.getEpochSecond());
        claims.put("exp", expiresAt.getEpochSecond());
        claims.put("jti", jti);
        claims.put("scope", String.join(" ", scopes));
        return new ClaimSet(claims);
    }

    /**
     * Builds the claim set for an OIDC ID token (Core §2 required claims: {@code iss},
     * {@code sub}, {@code aud}, {@code exp}, {@code iat}; plus {@code nonce} echoed from
     * the authorization request, §3.1.3.6).
     *
     * @param issuer    the OIDC {@code iss} (never {@code null} or blank)
     * @param subjectId the {@code sub} (never {@code null} or blank)
     * @param clientId  the {@code aud} — the client the ID token is for (never {@code null} or blank)
     * @param nonce     the {@code nonce} to bind back (never {@code null} or blank)
     * @param issuedAt  the {@code iat} instant (never {@code null})
     * @param expiresAt the {@code exp} instant (never {@code null}; after {@code issuedAt})
     * @return the unsigned OIDC ID-token claim set
     */
    public static ClaimSet idToken(
            String issuer,
            String subjectId,
            String clientId,
            String nonce,
            Instant issuedAt,
            Instant expiresAt) {
        requireText(issuer, "issuer");
        requireText(subjectId, "subjectId");
        requireText(clientId, "clientId");
        requireText(nonce, "nonce");
        requireOrder(issuedAt, expiresAt);

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", subjectId);
        claims.put("aud", clientId);
        claims.put("iat", issuedAt.getEpochSecond());
        claims.put("exp", expiresAt.getEpochSecond());
        claims.put("nonce", nonce);
        return new ClaimSet(claims);
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be null or blank");
        }
    }

    private static void requireOrder(Instant issuedAt, Instant expiresAt) {
        if (issuedAt == null) {
            throw new IllegalArgumentException("issuedAt must not be null");
        }
        if (expiresAt == null) {
            throw new IllegalArgumentException("expiresAt must not be null");
        }
        if (!expiresAt.isAfter(issuedAt)) {
            throw new IllegalArgumentException("expiresAt must be after issuedAt");
        }
    }
}
