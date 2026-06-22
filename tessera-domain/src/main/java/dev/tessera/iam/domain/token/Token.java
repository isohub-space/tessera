package dev.tessera.iam.domain.token;

/**
 * An issued OIDC/OAuth2 token, modelled as an <strong>unsigned</strong> claim set
 *.
 *
 * <p>Sealed over the three token kinds the design mints. Crucially the domain
 * holds only the <em>claims</em>; signing (EdDSA/ES256), JWS serialisation and key
 * selection are adapter effects in the shell — there is no crypto in iam-domain.
 *
 * <p><strong>Name-collision note.</strong> {@link RefreshToken} here is the issued
 * <em>token</em>; the {@code RefreshToken} <em>grant</em> lives in
 * {@link dev.tessera.iam.domain.client.grant}. The two are intentionally separate
 * types in separate packages.
 */
public sealed interface Token permits AccessToken, IdToken, RefreshToken {

    /** The (unsigned) claims carried by this token. */
    ClaimSet claims();
}
