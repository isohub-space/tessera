/**
 * Token model for the Tessera domain.
 *
 * <p>{@link dev.tessera.iam.domain.token.Token} is sealed over
 * {@link dev.tessera.iam.domain.token.AccessToken} (RFC 9068, sender-constrained via a
 * {@link dev.tessera.iam.domain.token.Confirmation}),
 * {@link dev.tessera.iam.domain.token.IdToken} and
 * {@link dev.tessera.iam.domain.token.RefreshToken}. Tokens are modelled as
 * <strong>unsigned</strong> {@link dev.tessera.iam.domain.token.ClaimSet}s — signing
 * and JWS serialisation are adapter effects, never domain concerns.
 *
 * <p>The token {@code RefreshToken} is deliberately a different type from the
 * grant {@link dev.tessera.iam.domain.client.grant.RefreshToken}; the package split
 * lets both keep their natural name.
 */
package dev.tessera.iam.domain.token;
