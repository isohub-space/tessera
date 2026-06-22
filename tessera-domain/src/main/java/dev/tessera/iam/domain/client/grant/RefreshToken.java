package dev.tessera.iam.domain.client.grant;

/**
 * The Refresh Token grant (RFC 6749 §6) — rotation + family reuse-detection in
 * this design.
 *
 * <p>An empty marker record: the grant carries no state, only identity.
 *
 * <p><strong>Name-collision note.</strong> "RefreshToken" names two distinct
 * domain concepts: this <em>grant</em> ({@code grant_type=refresh_token}) and the
 * issued <em>token</em> ({@link dev.tessera.iam.domain.token.RefreshToken}). They
 * live in distinct sub-packages on purpose so both can coexist without an alias;
 * do not collapse them.
 */
public record RefreshToken() implements GrantType {

    @Override
    public String grantTypeValue() {
        return "refresh_token";
    }
}
