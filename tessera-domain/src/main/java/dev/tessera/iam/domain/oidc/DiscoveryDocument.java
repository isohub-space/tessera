package dev.tessera.iam.domain.oidc;

import java.util.List;

/**
 * The OpenID Provider metadata document (OpenID Connect Discovery 1.0 / RFC 8414),
 * assembled as pure data. Every {@code *_supported} value is copied from an
 * {@link OidcCapabilities} declaration, and the endpoint URLs are derived from the
 * configured {@code issuer}, so the document is a faithful projection of what the server
 * enforces — it advertises nothing the server would not honour.
 *
 * <p>This is a framework-free value: the REST adapter maps it to the wire DTO with the
 * canonical snake_case member names.
 *
 * @param issuer                          the exact configured issuer identifier
 * @param authorizationEndpoint           the authorization endpoint URL
 * @param tokenEndpoint                   the token endpoint URL
 * @param userinfoEndpoint                the UserInfo endpoint URL
 * @param jwksUri                         the JWK Set endpoint URL
 * @param responseTypesSupported          offered OAuth2 response types
 * @param grantTypesSupported             offered OAuth2 grant types
 * @param subjectTypesSupported           offered subject identifier types
 * @param idTokenSigningAlgValuesSupported algorithms used to sign ID Tokens
 * @param codeChallengeMethodsSupported   offered PKCE code-challenge methods
 * @param tokenEndpointAuthMethodsSupported client authentication methods at the token
 *                                          endpoint
 * @param scopesSupported                 offered OAuth2 scopes
 * @param dpopSigningAlgValuesSupported   algorithms accepted for DPoP proofs
 * @param tlsClientCertificateBoundAccessTokens whether access tokens are certificate-bound
 */
public record DiscoveryDocument(
        String issuer,
        String authorizationEndpoint,
        String tokenEndpoint,
        String userinfoEndpoint,
        String jwksUri,
        List<String> responseTypesSupported,
        List<String> grantTypesSupported,
        List<String> subjectTypesSupported,
        List<String> idTokenSigningAlgValuesSupported,
        List<String> codeChallengeMethodsSupported,
        List<String> tokenEndpointAuthMethodsSupported,
        List<String> scopesSupported,
        List<String> dpopSigningAlgValuesSupported,
        boolean tlsClientCertificateBoundAccessTokens) {

    public DiscoveryDocument {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("DiscoveryDocument issuer must not be null or blank");
        }
        responseTypesSupported = List.copyOf(responseTypesSupported);
        grantTypesSupported = List.copyOf(grantTypesSupported);
        subjectTypesSupported = List.copyOf(subjectTypesSupported);
        idTokenSigningAlgValuesSupported = List.copyOf(idTokenSigningAlgValuesSupported);
        codeChallengeMethodsSupported = List.copyOf(codeChallengeMethodsSupported);
        tokenEndpointAuthMethodsSupported = List.copyOf(tokenEndpointAuthMethodsSupported);
        scopesSupported = List.copyOf(scopesSupported);
        dpopSigningAlgValuesSupported = List.copyOf(dpopSigningAlgValuesSupported);
    }

    /**
     * Assembles the discovery document for a configured {@code issuer} from an enforced
     * capability set. The endpoint URLs are the canonical issuer-relative paths
     * ({@code /authorize}, {@code /token}, {@code /userinfo}, {@code /jwks}); advertising
     * them is required by OIDC Discovery. The {@code *_supported} values are copied
     * verbatim from {@code caps}, so the document can advertise only what the server
     * enforces.
     *
     * @param issuer the exact configured issuer identifier (must not be blank)
     * @param caps   the enforced capability set
     * @return the assembled discovery document
     */
    public static DiscoveryDocument forIssuer(String issuer, OidcCapabilities caps) {
        if (issuer == null || issuer.isBlank()) {
            throw new IllegalArgumentException("issuer must not be null or blank");
        }
        String base = stripTrailingSlash(issuer);
        return new DiscoveryDocument(
                issuer,
                base + "/authorize",
                base + "/token",
                base + "/userinfo",
                base + "/jwks",
                caps.responseTypesSupported(),
                caps.grantTypesSupported(),
                caps.subjectTypesSupported(),
                caps.idTokenSigningAlgValuesSupported(),
                caps.codeChallengeMethodsSupported(),
                caps.tokenEndpointAuthMethodsSupported(),
                caps.scopesSupported(),
                caps.dpopSigningAlgValuesSupported(),
                caps.tlsClientCertificateBoundAccessTokens());
    }

    private static String stripTrailingSlash(String issuer) {
        return issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
    }
}
