package dev.tessera.iam.adapter.persistence.crypto;

import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.signingkey.KeyUse;
import dev.tessera.iam.domain.signingkey.PublicJwk;
import dev.tessera.iam.domain.signingkey.SigningAlgorithm;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * Ed25519 (EdDSA, RFC 8037) key generation, JWK encoding and signing.
 *
 * <p>All cryptography for the EdDSA signing path lives here, in the adapter shell —
 * the domain only owns the published JWK shape. Key generation uses the JDK provider
 * ({@code KeyPairGenerator.getInstance("Ed25519")}); the public key is encoded as an
 * OKP JWK ({@code kty=OKP, crv=Ed25519, x=base64url(public)}), and signing produces a
 * raw Ed25519 signature.
 */
public final class Ed25519Keys {

    private static final String ED25519 = "Ed25519";
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private Ed25519Keys() {
    }

    /** Generates a fresh Ed25519 key pair. */
    public static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance(ED25519).generateKeyPair();
        } catch (Exception e) {
            throw new EnvelopeCipher.GeneralSecurityFailure(
                    "Failed to generate Ed25519 key pair", e);
        }
    }

    /**
     * Builds the OKP public JWK for an Ed25519 public key.
     *
     * @param keyId the {@code kid} to stamp on the JWK
     * @param use   the JWK {@code use}
     * @param publicKey the Ed25519 public key
     * @return the public JWK domain value
     */
    public static PublicJwk toPublicJwk(KeyId keyId, KeyUse use, PublicKey publicKey) {
        String x = B64URL.encodeToString(rawPublicKey(publicKey));
        return new PublicJwk(keyId, SigningAlgorithm.EdDSA, use, x, null);
    }

    /** PKCS#8 encoding of the private key, for envelope-encryption storage. */
    public static byte[] encodePrivate(PrivateKey privateKey) {
        return privateKey.getEncoded();
    }

    /** Restores a private key from its PKCS#8 encoding (after envelope-decryption). */
    public static PrivateKey decodePrivate(byte[] pkcs8) {
        try {
            return KeyFactory.getInstance(ED25519)
                    .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        } catch (Exception e) {
            throw new EnvelopeCipher.GeneralSecurityFailure(
                    "Failed to decode Ed25519 private key", e);
        }
    }

    /** Produces a raw Ed25519 signature over {@code signingInput}. */
    public static byte[] sign(PrivateKey privateKey, byte[] signingInput) {
        try {
            Signature signature = Signature.getInstance(ED25519);
            signature.initSign(privateKey);
            signature.update(signingInput);
            return signature.sign();
        } catch (Exception e) {
            throw new EnvelopeCipher.GeneralSecurityFailure("Failed to sign with Ed25519 key", e);
        }
    }

    /** Verifies a raw Ed25519 signature — used by the round-trip integration tests. */
    public static boolean verify(PublicKey publicKey, byte[] signingInput, byte[] signature) {
        try {
            Signature verifier = Signature.getInstance(ED25519);
            verifier.initVerify(publicKey);
            verifier.update(signingInput);
            return verifier.verify(signature);
        } catch (Exception e) {
            throw new EnvelopeCipher.GeneralSecurityFailure("Failed to verify Ed25519 signature", e);
        }
    }

    /**
     * Extracts the 32-byte little-endian public key from an {@link EdECPublicKey}, per
     * RFC 8032 §3.1: the point is the Y coordinate with the sign of X folded into its
     * most-significant bit.
     */
    private static byte[] rawPublicKey(PublicKey publicKey) {
        if (!(publicKey instanceof EdECPublicKey edKey)) {
            throw new IllegalArgumentException("Not an Ed25519 public key: " + publicKey);
        }
        byte[] yLittleEndian = toLittleEndian(edKey.getPoint().getY(), 32);
        if (edKey.getPoint().isXOdd()) {
            yLittleEndian[31] |= (byte) 0x80;
        }
        return yLittleEndian;
    }

    private static byte[] toLittleEndian(java.math.BigInteger value, int length) {
        byte[] big = value.toByteArray();
        byte[] little = new byte[length];
        // big is big-endian, possibly with a leading sign byte; reverse into `length`.
        for (int i = 0; i < big.length && i < length; i++) {
            little[i] = big[big.length - 1 - i];
        }
        return little;
    }
}
