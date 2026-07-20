package dev.tessera.iam.adapter.rest.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * A successful token-endpoint response (RFC 6749 §5.1 / OIDC Core §3.1.3.3).
 *
 * <p>{@code token_type} is {@code DPoP} for a DPoP-bound token (RFC 9449) and {@code Bearer}
 * otherwise (an mTLS-bound token is a certificate-bound {@code Bearer}, its binding carried in
 * the token's {@code cnf} claim, not the type); {@code id_token} is present only for an
 * {@code openid} request. {@code expires_in} is the access-token lifetime in seconds.
 *
 * @param accessToken the signed RFC 9068 JWT access token
 * @param tokenType   the OAuth {@code token_type} — {@code DPoP} or {@code Bearer}
 * @param expiresIn   the access-token lifetime in seconds
 * @param scope       the granted scope, space-delimited
 * @param idToken     the signed OIDC ID token, or {@code null} for a non-OIDC request
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "TokenResponse", description = "A successful OAuth 2.0 / OIDC token response.")
public record TokenResponseDto(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn,
        @JsonProperty("scope") String scope,
        @JsonProperty("id_token") String idToken,
        @JsonProperty("refresh_token") String refreshToken) {

    /** The {@code Bearer} token type (an mTLS-bound token is a cert-bound Bearer). */
    public static final String BEARER = "Bearer";

    /** The {@code DPoP} token type (RFC 9449). */
    public static final String DPOP = "DPoP";
}
