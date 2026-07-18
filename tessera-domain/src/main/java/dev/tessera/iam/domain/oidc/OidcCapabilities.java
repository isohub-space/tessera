package dev.tessera.iam.domain.oidc;

import dev.tessera.iam.domain.signingkey.SigningAlgorithm;
import java.util.Arrays;
import java.util.List;

/**
 * The authoritative, immutable declaration of what the authorization server enforces:
 * every {@code *_supported} value the OIDC discovery document advertises is read from
 * this record, and the same record is the single source of truth that request-time
 * enforcement (the token, authorization and client-registration paths) consults. Because
 * both the advertised metadata and the runtime checks derive from one declaration, the
 * discovery document can never claim a capability the server would actually reject —
 * <em>discovery never lies</em>.
 *
 * <p>All members are unmodifiable lists of stable string tokens, in the exact form they
 * appear on the wire (RFC 8414 / OpenID Connect Discovery 1.0). This type is pure data:
 * it carries no framework dependency and no behaviour beyond construction.
 *
 * @param responseTypesSupported           the OAuth2 {@code response_type} values offered
 * @param grantTypesSupported              the OAuth2 {@code grant_type} values offered
 * @param codeChallengeMethodsSupported    the PKCE {@code code_challenge_method} values
 * @param tokenEndpointAuthMethodsSupported the client authentication methods offered at
 *                                          the token endpoint
 * @param subjectTypesSupported            the OIDC subject identifier types offered
 * @param idTokenSigningAlgValuesSupported the JWS algorithms used to sign ID Tokens
 * @param dpopSigningAlgValuesSupported    the JWS algorithms accepted for DPoP proofs
 * @param scopesSupported                  the OAuth2 scopes offered
 * @param tlsClientCertificateBoundAccessTokens whether the server issues certificate-bound
 *                                          (mTLS sender-constrained) access tokens
 */
public record OidcCapabilities(
        List<String> responseTypesSupported,
        List<String> grantTypesSupported,
        List<String> codeChallengeMethodsSupported,
        List<String> tokenEndpointAuthMethodsSupported,
        List<String> subjectTypesSupported,
        List<String> idTokenSigningAlgValuesSupported,
        List<String> dpopSigningAlgValuesSupported,
        List<String> scopesSupported,
        boolean tlsClientCertificateBoundAccessTokens) {

    public OidcCapabilities {
        responseTypesSupported = List.copyOf(responseTypesSupported);
        grantTypesSupported = List.copyOf(grantTypesSupported);
        codeChallengeMethodsSupported = List.copyOf(codeChallengeMethodsSupported);
        tokenEndpointAuthMethodsSupported = List.copyOf(tokenEndpointAuthMethodsSupported);
        subjectTypesSupported = List.copyOf(subjectTypesSupported);
        idTokenSigningAlgValuesSupported = List.copyOf(idTokenSigningAlgValuesSupported);
        dpopSigningAlgValuesSupported = List.copyOf(dpopSigningAlgValuesSupported);
        scopesSupported = List.copyOf(scopesSupported);
    }

    /**
     * The enforced capability set for the baseline ("Starter") tier. This is the exact,
     * deliberately narrow surface the server stands behind:
     *
     * <ul>
     *   <li>only the Authorization Code flow ({@code response_type=code}); the implicit
     *       and resource-owner-password flows are <strong>not</strong> offered;</li>
     *   <li>only {@code authorization_code} and {@code refresh_token} grants;</li>
     *   <li>PKCE is mandatory with {@code S256} only — the {@code plain} method is
     *       rejected;</li>
     *   <li>client authentication via {@code client_secret_basic},
     *       {@code private_key_jwt} or mutual-TLS ({@code tls_client_auth});</li>
     *   <li>token signing with asymmetric algorithms only (derived from the signing
     *       algorithm model — symmetric {@code HS*} MACs are unrepresentable and can
     *       never appear here);</li>
     *   <li>certificate-bound (mTLS sender-constrained) access tokens.</li>
     * </ul>
     *
     * @return the enforced Starter-tier capability set
     */
    public static OidcCapabilities enforced() {
        List<String> asymmetricSigningAlgs = asymmetricSigningAlgValues();
        return new OidcCapabilities(
                List.of("code"),
                List.of("authorization_code", "refresh_token"),
                List.of("S256"),
                List.of("client_secret_basic", "private_key_jwt", "tls_client_auth"),
                List.of("public"),
                asymmetricSigningAlgs,
                // DPoP proof algorithms accepted at the token endpoint. Narrower than the token
                // signing set on purpose: the bundled proof validator verifies ES256 (the de-facto
                // DPoP algorithm), so discovery advertises exactly that — accepting EdDSA proofs is
                // a follow-up. "Discovery never lies": this list equals what is enforced.
                List.of("ES256"),
                List.of("openid", "profile", "email"),
                true);
    }

    /**
     * The JWS {@code alg} identifiers offered for token signing, derived directly from
     * the signing-algorithm model. That model can only represent asymmetric algorithms
     * (symmetric {@code HS*} MACs are deliberately unrepresentable), so this list is
     * asymmetric by construction and an {@code HS*} value can never leak into discovery.
     */
    private static List<String> asymmetricSigningAlgValues() {
        return Arrays.stream(SigningAlgorithm.values())
                .map(SigningAlgorithm::algIdentifier)
                .toList();
    }
}
