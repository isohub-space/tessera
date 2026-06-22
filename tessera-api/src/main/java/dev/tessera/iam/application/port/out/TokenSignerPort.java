package dev.tessera.iam.application.port.out;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.token.ClaimSet;

/**
 * Outbound port that serialises an unsigned {@link ClaimSet} into a signed compact JWS
 * (a JWT string), using the realm's current signing key.
 *
 * <p>The domain produces only unsigned claims; turning them into a verifiable JWT — the
 * JOSE header ({@code alg}, {@code kid}, {@code typ}), canonical serialisation and the
 * asymmetric signature — is an adapter effect. The private key never crosses this port;
 * signing happens inside the implementation (which delegates to {@link KeyProviderPort}).
 * Signing is a CPU-bound asymmetric operation, so the adapter <strong>must</strong> run
 * it off the reactive event loop; the port returns a {@link Uni}.
 */
public interface TokenSignerPort {

    /**
     * Signs a claim set into a compact JWS (JWT), stamping the given {@code typ} header.
     *
     * @param realm  the realm whose current signing key signs (RLS-scoped key lookup)
     * @param typ    the JOSE {@code typ} header value — {@code "at+jwt"} for an RFC 9068
     *               access token, {@code "JWT"} for an ID token (never {@code null} or blank)
     * @param claims the unsigned claim set to sign (never {@code null})
     * @return a {@link Uni} emitting the compact-serialised, signed JWT string
     */
    Uni<String> sign(RealmKey realm, String typ, ClaimSet claims);
}
