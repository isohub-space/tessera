package dev.tessera.observability.audit;

/**
 * Signs and verifies {@link AuditCheckpoint} content.
 *
 * <p>Abstracted from any particular key custody so the checkpoint mechanism does
 * not assume where the signing key lives: the bundled {@link Ed25519CheckpointSigner}
 * holds an in-process Ed25519 key for self-contained operation and tests, while a
 * deployment may supply an implementation backed by an external KMS/HSM without
 * touching the chain or checkpoint code.</p>
 */
public interface CheckpointSigner {

    /**
     * @return a stable identifier of the signing key, surfaced as
     *         {@link AuditCheckpoint#keyId()} so a verifier can select the matching
     *         public key. A multi-key deployment (rotation, KMS migration) must resolve
     *         {@code keyId} to the corresponding public key before verifying — this
     *         label is the selector, not itself a cryptographic binding.
     */
    String keyId();

    /**
     * Produces a detached signature over {@code signingInput}.
     *
     * @param signingInput the canonical checkpoint bytes (see
     *                     {@link AuditCheckpoint#signingInput()})
     * @return the lowercase-hex signature
     */
    String sign(String signingInput);

    /**
     * Verifies a detached signature against {@code signingInput}.
     *
     * @param signingInput the canonical checkpoint bytes
     * @param hexSignature the lowercase-hex signature to check
     * @return {@code true} iff the signature is valid for this signer's key
     */
    boolean verify(String signingInput, String hexSignature);
}
