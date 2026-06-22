package dev.tessera.iam.domain.token;

/**
 * An OIDC ID token as an unsigned claim set.
 *
 * <p>The ID token authenticates the end-user to the client; it is not
 * sender-constrained, so it carries no {@code cnf} — only its claims.
 *
 * @param claims the unsigned ID-token claims (never {@code null})
 */
public record IdToken(ClaimSet claims) implements Token {

    public IdToken {
        if (claims == null) {
            throw new IllegalArgumentException("IdToken claims must not be null");
        }
    }
}
