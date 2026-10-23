// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.support;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;
import java.util.function.UnaryOperator;

/**
 * A {@code private_key_jwt} client for tests: one ES256 key pair, its public JWK Set as a client
 * would register it, and JWT client assertions (RFC 7523) signed with it.
 */
public final class AssertionTestClient {

    public static final String KID = "client-key-1";

    private final ECKey key;

    public AssertionTestClient() {
        this(KID);
    }

    /** A client whose key carries {@code kid}, as after a key rotation. */
    public AssertionTestClient(String kid) {
        try {
            this.key = new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException("failed to generate test EC key", e);
        }
    }

    /** The public JWK Set to register for the client. */
    public String jwks() {
        return new JWKSet(key.toPublicJWK()).toString();
    }

    /** Valid claims for {@code clientId} at {@code audience}: one-minute lifetime, fresh jti. */
    public static JWTClaimsSet.Builder claims(String clientId, String audience, Instant now) {
        return new JWTClaimsSet.Builder()
                .issuer(clientId)
                .subject(clientId)
                .audience(audience)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(Duration.ofMinutes(1))))
                .jwtID(UUID.randomUUID().toString());
    }

    /** An assertion with the given claims, signed ES256 under {@link #KID}. */
    public String sign(JWTClaimsSet claims) {
        return sign(claims, header -> header);
    }

    /** An assertion signed ES256, with the header adjusted by {@code header}. */
    public String sign(JWTClaimsSet claims, UnaryOperator<JWSHeader.Builder> header) {
        try {
            SignedJWT jwt = new SignedJWT(header.apply(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID())).build(),
                    claims);
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("failed to sign the client assertion", e);
        }
    }
}
