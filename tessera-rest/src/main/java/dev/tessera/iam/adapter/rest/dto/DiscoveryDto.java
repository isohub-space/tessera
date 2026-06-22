package dev.tessera.iam.adapter.rest.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import dev.tessera.iam.domain.oidc.DiscoveryDocument;
import java.util.List;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * The OpenID Provider metadata document (OpenID Connect Discovery 1.0 / RFC 8414) as
 * served by the discovery endpoint. The JSON member names are the canonical snake_case
 * registered metadata names; the values are a faithful projection of the enforced
 * capability set, so the document advertises only what the server enforces.
 *
 * @param issuer                            the configured issuer identifier
 * @param authorizationEndpoint             the authorization endpoint URL
 * @param tokenEndpoint                     the token endpoint URL
 * @param userinfoEndpoint                  the UserInfo endpoint URL
 * @param jwksUri                           the JWK Set endpoint URL
 * @param responseTypesSupported            offered OAuth2 response types
 * @param grantTypesSupported               offered OAuth2 grant types
 * @param subjectTypesSupported             offered subject identifier types
 * @param idTokenSigningAlgValuesSupported  algorithms used to sign ID Tokens
 * @param codeChallengeMethodsSupported     offered PKCE code-challenge methods
 * @param tokenEndpointAuthMethodsSupported client authentication methods at the token
 *                                          endpoint
 * @param scopesSupported                   offered OAuth2 scopes
 * @param dpopSigningAlgValuesSupported     algorithms accepted for DPoP proofs
 * @param tlsClientCertificateBoundAccessTokens whether access tokens are certificate-bound
 */
@Schema(name = "DiscoveryDocument", description = "OpenID Provider metadata (OIDC Discovery 1.0).")
public record DiscoveryDto(
        @JsonProperty("issuer") String issuer,
        @JsonProperty("authorization_endpoint") String authorizationEndpoint,
        @JsonProperty("token_endpoint") String tokenEndpoint,
        @JsonProperty("userinfo_endpoint") String userinfoEndpoint,
        @JsonProperty("jwks_uri") String jwksUri,
        @JsonProperty("response_types_supported") List<String> responseTypesSupported,
        @JsonProperty("grant_types_supported") List<String> grantTypesSupported,
        @JsonProperty("subject_types_supported") List<String> subjectTypesSupported,
        @JsonProperty("id_token_signing_alg_values_supported")
                List<String> idTokenSigningAlgValuesSupported,
        @JsonProperty("code_challenge_methods_supported") List<String> codeChallengeMethodsSupported,
        @JsonProperty("token_endpoint_auth_methods_supported")
                List<String> tokenEndpointAuthMethodsSupported,
        @JsonProperty("scopes_supported") List<String> scopesSupported,
        @JsonProperty("dpop_signing_alg_values_supported") List<String> dpopSigningAlgValuesSupported,
        @JsonProperty("tls_client_certificate_bound_access_tokens")
                boolean tlsClientCertificateBoundAccessTokens) {

    /** Maps a pure {@link DiscoveryDocument} to its wire form. */
    public static DiscoveryDto from(DiscoveryDocument doc) {
        return new DiscoveryDto(
                doc.issuer(),
                doc.authorizationEndpoint(),
                doc.tokenEndpoint(),
                doc.userinfoEndpoint(),
                doc.jwksUri(),
                doc.responseTypesSupported(),
                doc.grantTypesSupported(),
                doc.subjectTypesSupported(),
                doc.idTokenSigningAlgValuesSupported(),
                doc.codeChallengeMethodsSupported(),
                doc.tokenEndpointAuthMethodsSupported(),
                doc.scopesSupported(),
                doc.dpopSigningAlgValuesSupported(),
                doc.tlsClientCertificateBoundAccessTokens());
    }
}
