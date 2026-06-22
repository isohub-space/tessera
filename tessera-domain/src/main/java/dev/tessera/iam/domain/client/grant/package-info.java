/**
 * OAuth2 grant types as a sealed, WON'T-list-excluding hierarchy
 *.
 *
 * <p>{@link dev.tessera.iam.domain.client.grant.GrantType} permits only the three
 * modern, secure flows the design accepts: Authorization Code (+PKCE), Client
 * Credentials, and Refresh Token. Implicit, ROPC, Device Code and Token Exchange
 * have <strong>no member type at all</strong> — compile-time exclusion is the
 * point.
 *
 * <p>This package is kept distinct from {@link dev.tessera.iam.domain.token} so the
 * grant {@code RefreshToken} and the issued-token {@code RefreshToken} can both
 * exist under their natural names.
 */
package dev.tessera.iam.domain.client.grant;
