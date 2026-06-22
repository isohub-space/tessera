package dev.tessera.iam.adapter.persistence.crypto;

import dev.tessera.iam.domain.signingkey.PublicJwk;
import java.util.List;
import java.util.StringJoiner;

/**
 * Hand-rolled, minimal JWK / JWK Set JSON serialisation (RFC 7517 / RFC 8037).
 *
 * <p>The public JWK members are a small, fixed set of strings ({@code kty}, {@code crv},
 * {@code x}, optionally {@code y}, {@code kid}, {@code alg}, {@code use}), so rendering
 * them by hand avoids pulling a JOSE library into the adapter while still producing a
 * spec-shaped document. Only public members are ever emitted — there is no code path
 * that can serialise a private key.
 */
public final class JwkJson {

    private JwkJson() {
    }

    /** Serialises a single public JWK to its JSON object form. */
    public static String toJwk(PublicJwk jwk) {
        StringBuilder out = new StringBuilder("{");
        StringJoiner members = new StringJoiner(",");
        members.add(member("kty", jwk.keyType()));
        members.add(member("crv", jwk.curve()));
        members.add(member("x", jwk.x()));
        if (jwk.y() != null) {
            members.add(member("y", jwk.y()));
        }
        members.add(member("kid", jwk.keyId().value()));
        members.add(member("alg", jwk.algorithm().algIdentifier()));
        members.add(member("use", jwk.use().jwkValue()));
        out.append(members);
        out.append("}");
        return out.toString();
    }

    /** Serialises a list of public JWKs to a JWK Set document ({@code {"keys":[...]}}). */
    public static String toJwkSet(List<PublicJwk> jwks) {
        StringJoiner keys = new StringJoiner(",", "{\"keys\":[", "]}");
        for (PublicJwk jwk : jwks) {
            keys.add(toJwk(jwk));
        }
        return keys.toString();
    }

    private static String member(String name, String value) {
        return "\"" + name + "\":\"" + escape(value) + "\"";
    }

    private static String escape(String value) {
        StringBuilder sb = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
