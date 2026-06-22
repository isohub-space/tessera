package dev.tessera.iam.domain.client.grant;

/**
 * The Client Credentials grant (RFC 6749 §4.4) for confidential service clients
 *.
 *
 * <p>An empty marker record: the grant carries no state, only identity.
 */
public record ClientCredentials() implements GrantType {

    @Override
    public String grantTypeValue() {
        return "client_credentials";
    }
}
