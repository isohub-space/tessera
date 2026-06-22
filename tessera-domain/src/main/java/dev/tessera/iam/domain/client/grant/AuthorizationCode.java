package dev.tessera.iam.domain.client.grant;

/**
 * The Authorization Code grant (RFC 6749 §4.1), PKCE S256-mandatory in this
 * design.
 *
 * <p>An empty marker record: the grant carries no state, only identity.
 */
public record AuthorizationCode() implements GrantType {

    @Override
    public String grantTypeValue() {
        return "authorization_code";
    }
}
