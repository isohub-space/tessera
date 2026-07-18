package dev.tessera.iam.adapter.rest.support;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
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
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .jwtID(jti)
                    .claim("htm", htm)
                    .claim("htu", htu)
                    .issueTime(Date.from(iat))
                    .build();
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("failed to mint DPoP proof", e);
        }
    }
}
