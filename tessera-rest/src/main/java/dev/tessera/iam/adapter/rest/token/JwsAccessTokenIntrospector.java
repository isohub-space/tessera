package dev.tessera.iam.adapter.rest.token;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.tessera.iam.application.port.out.AccessTokenIntrospectorPort;
import dev.tessera.iam.application.port.out.KeyProviderPort;
import dev.tessera.iam.domain.signingkey.PublicJwk;
import dev.tessera.iam.domain.signingkey.SigningAlgorithm;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Verifies RFC 9068 EdDSA JWT access tokens against a realm's <em>published</em> keys, implementing
 * {@link AccessTokenIntrospectorPort} for the introspection endpoint.
 *
 * <p>All cryptography is plain JDK {@code java.security} — no JOSE library. The verifier mirrors the
 * signer ({@code JwsTokenSignerAdapter}) in reverse: split the compact JWS, read the JOSE header,
 * require {@code alg=EdDSA} and {@code typ=at+jwt}, select the published key by {@code kid},
 * reconstruct its {@link PublicKey} from the OKP JWK {@code x} coordinate, and verify the Ed25519
 * signature over {@code header.payload}. Only keys returned by {@link KeyProviderPort#publishedJwks}
 * for {@code realm} are trusted — a token signed by another tenant's key is not published here and so
 * does not verify, which is the cryptographic tenant boundary. Any malformedness, unknown {@code kid},
 * or bad signature yields {@link Optional#empty()} (never an exception); expiry is left to the caller.
 *
 * <p>{@code alg=none} and any non-EdDSA algorithm are rejected before key lookup, so an unsigned or
 * downgraded token can never be accepted. EdDSA verification is a fast CPU operation, safe to run on
 * the reactive thread; the only I/O is the (reactive) key lookup.
 */
@ApplicationScoped
public class JwsAccessTokenIntrospector implements AccessTokenIntrospectorPort {

    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();
    private static final String ED25519 = "Ed25519";
    private static final String ALG_EDDSA = "EdDSA";
    private static final String TYP_ACCESS_TOKEN = "at+jwt";
    private static final int ED25519_PUBLIC_KEY_BYTES = 32;

    @Inject
    KeyProviderPort keyProvider;

    @Inject
    ObjectMapper mapper;

    @Override
    public Uni<Optional<VerifiedAccessToken>> verify(RealmKey realm, String token) {
        Jws jws = split(token);
        if (jws == null) {
            return empty();
        }
        Header header = header(jws.headerB64());
        if (header == null
                || !ALG_EDDSA.equals(header.alg())
                || !TYP_ACCESS_TOKEN.equals(header.typ())
                || header.kid() == null) {
            return empty();
        }
        return keyProvider.publishedJwks(realm).map(jwks -> {
            PublicJwk match = selectKey(jwks, header.kid());
            if (match == null) {
                return Optional.empty();
            }
            PublicKey publicKey = edPublicKey(match.x());
            if (publicKey == null || !verifySignature(publicKey, jws)) {
                return Optional.empty();
            }
            return claims(jws.payloadB64());
        });
    }

    /** Splits a compact JWS into its three parts; {@code null} unless there are exactly two dots. */
    private static Jws split(String token) {
        if (token == null) {
            return null;
        }
        int d1 = token.indexOf('.');
        if (d1 <= 0) {
            return null;
        }
        int d2 = token.indexOf('.', d1 + 1);
        if (d2 <= d1 + 1 || d2 >= token.length() - 1) {
            return null;
        }
        if (token.indexOf('.', d2 + 1) >= 0) {
            return null; // more than two dots — not a compact JWS
        }
        byte[] signingInput = token.substring(0, d2).getBytes(StandardCharsets.US_ASCII);
        return new Jws(token.substring(0, d1), token.substring(d1 + 1, d2), token.substring(d2 + 1),
                signingInput);
    }

    private Header header(String headerB64) {
        try {
            JsonNode h = mapper.readTree(B64URL.decode(headerB64));
            return new Header(text(h, "alg"), text(h, "typ"), text(h, "kid"));
        } catch (IOException | RuntimeException notJson) {
            return null;
        }
    }

    private static PublicJwk selectKey(List<PublicJwk> jwks, String kid) {
        for (PublicJwk jwk : jwks) {
            if (jwk.algorithm() == SigningAlgorithm.EdDSA && kid.equals(jwk.keyId().value())) {
                return jwk;
            }
        }
        return null;
    }

    /**
     * Reconstructs an Ed25519 {@link PublicKey} from the OKP JWK {@code x} — the exact inverse of the
     * signer's encoding (RFC 8032 §3.1): {@code x} is the 32-byte little-endian Y coordinate with the
     * sign of X folded into the most-significant bit of the last byte.
     */
    private static PublicKey edPublicKey(String x) {
        try {
            byte[] le = B64URL.decode(x);
            if (le.length != ED25519_PUBLIC_KEY_BYTES) {
                return null;
            }
            boolean xOdd = (le[ED25519_PUBLIC_KEY_BYTES - 1] & 0x80) != 0;
            byte[] yBigEndian = new byte[ED25519_PUBLIC_KEY_BYTES];
            for (int i = 0; i < ED25519_PUBLIC_KEY_BYTES; i++) {
                // Strip the sign bit from the top byte (last, little-endian) then reverse to big-endian.
                int b = le[i] & 0xff;
                if (i == ED25519_PUBLIC_KEY_BYTES - 1) {
                    b &= 0x7f;
                }
                yBigEndian[ED25519_PUBLIC_KEY_BYTES - 1 - i] = (byte) b;
            }
            BigInteger y = new BigInteger(1, yBigEndian);
            EdECPoint point = new EdECPoint(xOdd, y);
            return KeyFactory.getInstance(ED25519)
                    .generatePublic(new EdECPublicKeySpec(NamedParameterSpec.ED25519, point));
        } catch (RuntimeException | java.security.GeneralSecurityException badKey) {
            return null;
        }
    }

    private static boolean verifySignature(PublicKey publicKey, Jws jws) {
        try {
            Signature verifier = Signature.getInstance(ED25519);
            verifier.initVerify(publicKey);
            verifier.update(jws.signingInput());
            return verifier.verify(B64URL.decode(jws.signatureB64()));
        } catch (RuntimeException | java.security.GeneralSecurityException badSignature) {
            return false;
        }
    }

    private Optional<VerifiedAccessToken> claims(String payloadB64) {
        try {
            JsonNode c = mapper.readTree(B64URL.decode(payloadB64));
            return Optional.of(new VerifiedAccessToken(
                    text(c, "sub"),
                    text(c, "client_id"),
                    text(c, "scope"),
                    text(c, "jti"),
                    number(c, "iat"),
                    number(c, "exp")));
        } catch (IOException | RuntimeException notJson) {
            return Optional.empty();
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }

    private static Long number(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isNumber() ? value.asLong() : null;
    }

    private static Uni<Optional<VerifiedAccessToken>> empty() {
        return Uni.createFrom().item(Optional.empty());
    }

    /** The three base64url segments of a compact JWS, plus the pre-computed signing input. */
    private record Jws(String headerB64, String payloadB64, String signatureB64, byte[] signingInput) {
    }

    /** The JOSE header members this verifier reads. */
    private record Header(String alg, String typ, String kid) {
    }
}
