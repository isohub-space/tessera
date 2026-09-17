package dev.tessera.observability.audit;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
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
 *
 * <p><strong>The key id is derived from the key, never declared beside it.</strong>
 * {@link #generate()} takes no identifier: the id is a thumbprint of the public key
 * ({@link #keyIdFor}), so fresh material always gets a fresh name and it is impossible to
 * mint a new key wearing an old key's identity. The previous API accepted a configured id
 * and generated a new key pair every boot under it, which meant each restart silently
 * reused one identity for unrelated key material — checkpoints from before the restart
 * named a key that no longer existed while a different key claimed the same name, so they
 * could neither be verified nor honestly reported as unverifiable.</p>
 *
 * <p>Note what this does and does not fix. Deriving the id removes the false identity; it
 * does not make the key itself durable. This signer's key still lives only as long as the
 * process, so checkpoints from earlier boots resolve to
 * {@link CheckpointVerification.UnknownKey} — an explicit "cannot judge", which is the
 * truthful answer. Making them verify instead requires durable key custody and a
 * {@link CheckpointKeyResolver} backed by it.</p>
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
     * Generates a fresh Ed25519 key pair and wraps it in a signer whose {@code keyId} is
     * derived from the generated public key.
     *
     * <p>There is deliberately no overload taking an identifier. Naming freshly generated
     * material is exactly the defect this replaces, and an API that still allowed it would
     * leave the hole open for the next caller.
     *
     * @return the signer
     */
    public static Ed25519CheckpointSigner generate() {
        try {
            KeyPair pair = KeyPairGenerator.getInstance(ED25519).generateKeyPair();
            return new Ed25519CheckpointSigner(keyIdFor(pair.getPublic()), pair);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Ed25519 is required but unavailable", e);
        }
    }

    /**
     * Wraps an already-held key pair, deriving the {@code keyId} the same way. This is the
     * entry point for durable custody: a deployment that stores the key pair reloads it
     * here and gets back the identical {@code keyId}, so checkpoints signed by that key in
     * an earlier process still resolve.
     *
     * @param keyPair the Ed25519 key pair to use; never {@code null}
     * @return the signer
     */
    public static Ed25519CheckpointSigner of(KeyPair keyPair) {
        Objects.requireNonNull(keyPair, "keyPair must not be null");
        return new Ed25519CheckpointSigner(keyIdFor(keyPair.getPublic()), keyPair);
    }

    /**
     * Derives a key's identifier from the key itself: {@code ed25519-} followed by the
     * first 128 bits of the SHA-256 digest of the encoded public key (X.509
     * SubjectPublicKeyInfo), in lowercase hex.
     *
     * <p>Being a function of the public key is the whole point — the same key always
     * yields the same id, and different key material can never collide onto one id by
     * configuration. 128 bits is far beyond what a collision would need here, and the
     * value is a public thumbprint, not a secret: it is already published on every
     * checkpoint.
     *
     * @param publicKey the public half of the signing key; never {@code null}
     * @return the derived identifier
     */
    public static String keyIdFor(PublicKey publicKey) {
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded());
            return "ed25519-" + HEX.formatHex(java.util.Arrays.copyOf(digest, 16));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
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
