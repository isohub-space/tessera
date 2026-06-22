package dev.tessera.iam.domain.client.grant;

/**
 * The OAuth2 grant types Tessera is willing to honour
 *.
 *
 * <p>This is the design's most important type-level statement: the
 * <em>WON'T-list</em> grants are <strong>not sealed in</strong>. There is no
 * {@code ImplicitGrant}, {@code ResourceOwnerPassword} (ROPC), {@code DeviceCode}
 * or {@code TokenExchange} member — refusing them is a <em>compile-time</em>
 * guarantee, not a runtime check. Any code that exhaustively switches over a
 * {@code GrantType} is therefore provably unable to handle an insecure-by-modern-
 * standard flow, and adding such a flow would break compilation everywhere it
 * matters.
 *
 * <p>Permitted members are empty marker records: a {@code GrantType} carries no
 * state of its own; its identity is its type.
 */
public sealed interface GrantType
        permits AuthorizationCode, ClientCredentials, RefreshToken {

    /**
     * The RFC grant identifier carried in the token-endpoint {@code grant_type}
     * parameter for this grant.
     *
     * @return the wire {@code grant_type} string
     */
    String grantTypeValue();
}
