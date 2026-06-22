package dev.tessera.iam.domain.token;

/**
 * An issued refresh token as an unsigned claim set
 *.
 *
 * <p>In the design refresh tokens rotate and belong to a reuse-detection family;
 * those server-side bindings live in the persistence shell. The domain value here
 * is just the (unsigned) claim payload.
 *
 * <p><strong>Name-collision note.</strong> This is the issued <em>token</em>; the
 * {@code refresh_token} <em>grant</em> is
 * {@link dev.tessera.iam.domain.client.grant.RefreshToken}. Both names are kept,
 * separated by package, on purpose.
 *
 * @param claims the unsigned refresh-token claims (never {@code null})
 */
public record RefreshToken(ClaimSet claims) implements Token {

    public RefreshToken {
        if (claims == null) {
            throw new IllegalArgumentException("RefreshToken claims must not be null");
        }
    }
}
