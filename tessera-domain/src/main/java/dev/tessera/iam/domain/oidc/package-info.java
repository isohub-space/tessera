/**
 * The OIDC discovery domain: the enforced server capability set and the discovery
 * metadata document assembled from it.
 *
 * <p>Framework-free functional core. {@link dev.tessera.iam.domain.oidc.OidcCapabilities}
 * is the single, authoritative declaration of what the authorization server actually
 * enforces (response types, grant types, PKCE methods, client authentication methods,
 * signing algorithms, scopes). {@link dev.tessera.iam.domain.oidc.DiscoveryDocument} is
 * generated <em>from</em> that capability set, so the published discovery metadata can
 * never advertise a capability the server does not enforce — discovery never lies.
 */
package dev.tessera.iam.domain.oidc;
