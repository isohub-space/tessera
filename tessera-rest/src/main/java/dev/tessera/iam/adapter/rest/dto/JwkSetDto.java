package dev.tessera.iam.adapter.rest.dto;

import dev.tessera.iam.domain.signingkey.PublicJwk;
import java.util.List;
import org.eclipse.microprofile.openapi.annotations.media.Schema;

/**
 * A JWK Set document ({@code {"keys":[...]}}, RFC 7517 §5) — the body of the JWKS
 * endpoint. Carries the realm's published (ACTIVE + RETIRING) public verification keys.
 *
 * @param keys the published public JWKs
 */
@Schema(name = "JwkSet", description = "A JWK Set: the published public verification keys.")
public record JwkSetDto(List<JwkDto> keys) {

    /** Maps a list of domain {@link PublicJwk}s to a JWK Set wire document. */
    public static JwkSetDto from(List<PublicJwk> jwks) {
        return new JwkSetDto(jwks.stream().map(JwkDto::from).toList());
    }
}
