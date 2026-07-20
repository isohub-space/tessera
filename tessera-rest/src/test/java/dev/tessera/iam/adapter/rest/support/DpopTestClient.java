package dev.tessera.iam.adapter.rest.support;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * A test DPoP client (RFC 9449): holds one ES256 (P-256) key pair and mints proof JWTs bound
 * to a request. Backed by the same JOSE library the server's validator uses, so a proof it
 * produces is exactly what a real public client would send.
 */
public final class DpopTestClient {

    private final ECKey key;

    public DpopTestClient() {
        try {
            this.key = new ECKeyGenerator(Curve.P_256).generate();
        } catch (Exception e) {
            throw new IllegalStateException("failed to generate test EC key", e);
        }
    }

    /** The base64url SHA-256 JWK thumbprint this client's tokens are bound to (cnf.jkt). */
    public String jkt() {
        try {
            return key.toPublicJWK().computeThumbprint().toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A fresh, valid proof for {@code POST htu} (unique jti, current iat). */
    public String proof(String htu) {
        return proof("POST", htu, Instant.now(), UUID.randomUUID().toString());
    }

    /** A proof with fully controlled binding/time/jti — for exercising validation edges. */
    public String proof(String htm, String htu, Instant iat, String jti) {
        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(key.toPublicJWK())
                    .build();
            SignedJWT jwt = new SignedJWT(header, boundClaims(htm, htu, iat, jti));
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("failed to mint DPoP proof", e);
        }
    }

    /**
     * A proof signed with a non-ES256 algorithm (ES384, on a fresh P-384 key) — the validator
     * accepts only ES256 and must reject it.
     */
    public String proofWithUnsupportedAlg(String htu) {
        try {
            ECKey es384Key = new ECKeyGenerator(Curve.P_384).generate();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES384)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(es384Key.toPublicJWK())
                    .build();
            SignedJWT jwt = new SignedJWT(header,
                    boundClaims("POST", htu, Instant.now(), UUID.randomUUID().toString()));
            jwt.sign(new ECDSASigner(es384Key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A proof whose embedded {@code jwk} is this client's genuine public key, but whose
     * signature was produced by a <em>different</em> key pair entirely — a proof cannot be
     * forged by presenting someone else's public key without their private key.
     */
    public String proofSignedByWrongKey(String htu) {
        try {
            ECKey impostorKey = new ECKeyGenerator(Curve.P_256).generate();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("dpop+jwt"))
                    .jwk(key.toPublicJWK())
                    .build();
            SignedJWT jwt = new SignedJWT(header,
                    boundClaims("POST", htu, Instant.now(), UUID.randomUUID().toString()));
            jwt.sign(new ECDSASigner(impostorKey));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * A hand-assembled, unsigned ({@code alg=none}) proof — bypasses the JOSE library's own
     * signer/builder entirely (which refuse to produce this) to prove the validator itself
     * rejects the classic "none" alg-confusion attack, however the rejection is reached.
     */
    public String proofWithNoneAlg(String htu) {
        String header = "{\"typ\":\"dpop+jwt\",\"alg\":\"none\"}";
        String payload = String.format(
                "{\"htm\":\"POST\",\"htu\":\"%s\",\"iat\":%d,\"jti\":\"%s\"}",
                htu, Instant.now().getEpochSecond(), UUID.randomUUID());
        return Base64URL.encode(header) + "." + Base64URL.encode(payload) + ".";
    }

    private static JWTClaimsSet boundClaims(String htm, String htu, Instant iat, String jti) {
        return new JWTClaimsSet.Builder()
                .jwtID(jti)
                .claim("htm", htm)
                .claim("htu", htu)
                .issueTime(Date.from(iat))
                .build();
    }
}
