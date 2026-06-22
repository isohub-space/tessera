package dev.tessera.iam.adapter.rest.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.tessera.iam.domain.signingkey.PublicJwk;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * A single public JWK as served in the JWKS document (RFC 7517 / RFC 8037).
 *
 * <p>Only public members are present: there is no field that could carry private key
 * material, so no private material can ever be serialised onto the wire.
 *
 * @param kty key type (e.g. {@code OKP})
 * @param crv curve (e.g. {@code Ed25519})
 * @param x   base64url public coordinate
 * @param y   base64url Y coordinate (EC keys only; {@code null} for OKP)
 * @param kid key id
 * @param alg algorithm (e.g. {@code EdDSA})
 * @param use public key use (e.g. {@code sig})
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(name = "Jwk", description = "A public JSON Web Key (RFC 7517 / RFC 8037).")
public record JwkDto(
        String kty, String crv, String x, String y, String kid, String alg, String use) {

    /** Maps a domain {@link PublicJwk} to its wire form. */
    public static JwkDto from(PublicJwk jwk) {
        return new JwkDto(
                jwk.keyType(),
                jwk.curve(),
                jwk.x(),
                jwk.y(),
                jwk.keyId().value(),
                jwk.algorithm().algIdentifier(),
                jwk.use().jwkValue());
    }
}
