package dev.tessera.observability.audit;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HexFormat;
import java.util.Objects;

/**
 * An {@link CheckpointSigner} backed by an in-process Ed25519 (EdDSA, RFC 8032)
 * key pair generated from the JDK provider.
 *
 * <p>Self-contained: holds its own key pair so the checkpoint mechanism works out
 * of the box and in tests without external key custody. A deployment that requires
 * an externally-managed key supplies a different {@link CheckpointSigner}; the
 * chain, checkpoint and verification code are agnostic to the implementation.
 * Ed25519 keys and the {@code Signature} API are supported under GraalVM native
 * image, so this signer works in both JVM and native builds.</p>
 *
 * <p>Thread-safe: a fresh {@link Signature} instance is created per call rather than
 * shared (a {@code Signature} is stateful and not safe for concurrent use).</p>
 */
public final class Ed25519CheckpointSigner implements CheckpointSigner {

    private static final String ED25519 = "Ed25519";
    private static final HexFormat HEX = HexFormat.of();

    private final String keyId;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;

    private Ed25519CheckpointSigner(String keyId, KeyPair keyPair) {
        this.keyId = Objects.requireNonNull(keyId, "keyId must not be null");
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    /**
     * Generates a fresh Ed25519 key pair and wraps it in a signer.
     *
     * @param keyId a stable identifier for the generated key
     * @return the signer
     */
    public static Ed25519CheckpointSigner generate(String keyId) {
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalArgumentException("keyId must not be null or blank");
        }
        try {
            KeyPair pair = KeyPairGenerator.getInstance(ED25519).generateKeyPair();
            return new Ed25519CheckpointSigner(keyId, pair);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is required but unavailable", e);
        }
    }

    /** @return the public key, so a verifier can be constructed independently. */
    public PublicKey publicKey() {
        return publicKey;
    }

    @Override
    public String keyId() {
        return keyId;
    }

    @Override
    public String sign(String signingInput) {
        Objects.requireNonNull(signingInput, "signingInput must not be null");
        try {
            Signature signature = Signature.getInstance(ED25519);
            signature.initSign(privateKey);
            signature.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return HEX.formatHex(signature.sign());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to sign audit checkpoint", e);
        }
    }

    @Override
    public boolean verify(String signingInput, String hexSignature) {
        Objects.requireNonNull(signingInput, "signingInput must not be null");
        Objects.requireNonNull(hexSignature, "hexSignature must not be null");
        final byte[] raw;
        try {
            raw = HEX.parseHex(hexSignature);
        } catch (IllegalArgumentException malformedHex) {
            // A non-hex / odd-length signature is simply invalid, not an error.
            return false;
        }
        try {
            Signature verifier = Signature.getInstance(ED25519);
            verifier.initVerify(publicKey);
            verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(raw);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to verify audit checkpoint signature", e);
        }
    }
}
