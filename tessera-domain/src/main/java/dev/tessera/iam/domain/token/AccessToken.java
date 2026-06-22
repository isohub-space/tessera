package dev.tessera.iam.domain.token;

/**
 * A JWT access token (RFC 9068) as an unsigned claim set
 *.
 *
 * <p>Carries a {@link Confirmation} ({@code cnf}) because the design
 * sender-constrains access tokens: DPoP for public clients, mTLS for confidential
 * service clients. The binding is mandatory here, so {@code cnf} is a required
 * component — an unbound access token is not representable.
 *
 * @param claims the unsigned access-token claims (never {@code null})
 * @param cnf    the sender-constraining confirmation (never {@code null})
 */
public record AccessToken(ClaimSet claims, Confirmation cnf) implements Token {

    public AccessToken {
        if (claims == null) {
            throw new IllegalArgumentException("AccessToken claims must not be null");
        }
        if (cnf == null) {
            throw new IllegalArgumentException("AccessToken cnf must not be null — tokens are sender-constrained");
        }
    }
}
