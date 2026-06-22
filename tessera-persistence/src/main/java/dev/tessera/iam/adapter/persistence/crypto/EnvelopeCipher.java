package dev.tessera.iam.adapter.persistence.crypto;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Envelope encryption for private signing-key material, using AES-256-GCM.
 *
 * <p>The scheme is the standard two-tier "envelope": each private key is encrypted
 * under a fresh per-key <em>data encryption key</em> (DEK); the DEK is then itself
 * wrapped (encrypted) under a single <em>master key</em>. Only the wrapped DEK, the
 * ciphertext and the nonces are persisted — never the master key and never cleartext
 * key bytes.
 *
 * <p>In this development implementation the master key is a 256-bit key supplied via
 * configuration. In production the wrapping step is delegated to a KMS/HSM behind the
 * signing-key provider port; this class is the seam where that substitution happens —
 * replace {@link #wrapDek}/{@link #unwrapDek} with KMS {@code Encrypt}/{@code Decrypt}
 * calls and the persisted column shape stays identical.
 */
public final class EnvelopeCipher {

    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_NONCE_BYTES = 12;
    private static final int DEK_BITS = 256;

    private final SecretKey masterKey;
    private final SecureRandom random = new SecureRandom();

    /**
     * @param masterKeyBytes the 32-byte (256-bit) master key used to wrap each DEK
     */
    public EnvelopeCipher(byte[] masterKeyBytes) {
        if (masterKeyBytes == null || masterKeyBytes.length != 32) {
            throw new IllegalArgumentException(
                    "Master key must be exactly 32 bytes (256 bits); got "
                            + (masterKeyBytes == null ? "null" : masterKeyBytes.length));
        }
        this.masterKey = new SecretKeySpec(masterKeyBytes.clone(), AES);
    }

    /**
     * Envelope-encrypts {@code plaintext} (the private key bytes).
     *
     * @param plaintext the private key material to protect
     * @return the sealed envelope: ciphertext, nonce and wrapped DEK
     */
    public Envelope seal(byte[] plaintext) {
        try {
            SecretKey dek = newDek();
            byte[] nonce = randomNonce();
            byte[] ciphertext = gcm(Cipher.ENCRYPT_MODE, dek, nonce, plaintext);
            byte[] wrappedDek = wrapDek(dek);
            return new Envelope(ciphertext, nonce, wrappedDek);
        } catch (GeneralSecurityFailure e) {
            throw e;
        } catch (Exception e) {
            throw new GeneralSecurityFailure("Failed to seal private key material", e);
        }
    }

    /**
     * Recovers the plaintext private key from a sealed envelope.
     *
     * @param envelope the sealed envelope as persisted
     * @return the cleartext private key bytes (the caller must not persist these)
     */
    public byte[] open(Envelope envelope) {
        try {
            SecretKey dek = unwrapDek(envelope.wrappedDek());
            return gcm(Cipher.DECRYPT_MODE, dek, envelope.nonce(), envelope.ciphertext());
        } catch (Exception e) {
            throw new GeneralSecurityFailure("Failed to open private key material", e);
        }
    }

    // --- KMS seam: in production these two become KMS Encrypt/Decrypt of the DEK. ---

    private byte[] wrapDek(SecretKey dek) throws Exception {
        byte[] nonce = randomNonce();
        byte[] wrapped = gcm(Cipher.ENCRYPT_MODE, masterKey, nonce, dek.getEncoded());
        // Prefix the wrap nonce so unwrap is self-contained.
        byte[] out = new byte[GCM_NONCE_BYTES + wrapped.length];
        System.arraycopy(nonce, 0, out, 0, GCM_NONCE_BYTES);
        System.arraycopy(wrapped, 0, out, GCM_NONCE_BYTES, wrapped.length);
        return out;
    }

    private SecretKey unwrapDek(byte[] wrappedWithNonce) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        byte[] wrapped = new byte[wrappedWithNonce.length - GCM_NONCE_BYTES];
        System.arraycopy(wrappedWithNonce, 0, nonce, 0, GCM_NONCE_BYTES);
        System.arraycopy(wrappedWithNonce, GCM_NONCE_BYTES, wrapped, 0, wrapped.length);
        byte[] raw = gcm(Cipher.DECRYPT_MODE, masterKey, nonce, wrapped);
        return new SecretKeySpec(raw, AES);
    }

    private static byte[] gcm(int mode, SecretKey key, byte[] nonce, byte[] input)
            throws Exception {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(mode, key, new GCMParameterSpec(GCM_TAG_BITS, nonce));
        return cipher.doFinal(input);
    }

    private SecretKey newDek() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance(AES);
        generator.init(DEK_BITS, random);
        return generator.generateKey();
    }

    private byte[] randomNonce() {
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        random.nextBytes(nonce);
        return nonce;
    }

    /** A sealed envelope: AES-GCM ciphertext, its nonce, and the wrapped DEK. */
    public record Envelope(byte[] ciphertext, byte[] nonce, byte[] wrappedDek) {

        public Envelope {
            ciphertext = ciphertext.clone();
            nonce = nonce.clone();
            wrappedDek = wrappedDek.clone();
        }

        @Override
        public byte[] ciphertext() {
            return ciphertext.clone();
        }

        @Override
        public byte[] nonce() {
            return nonce.clone();
        }

        @Override
        public byte[] wrappedDek() {
            return wrappedDek.clone();
        }
    }

    /** Unchecked wrapper for the checked cryptography exceptions. */
    public static final class GeneralSecurityFailure extends RuntimeException {
        private static final long serialVersionUID = 1L;

        GeneralSecurityFailure(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
