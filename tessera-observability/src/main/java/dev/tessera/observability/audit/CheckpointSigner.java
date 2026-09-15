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
public interface CheckpointSigner extends CheckpointVerifier {

    /**
     * @return a stable identifier of the signing key, surfaced as
     *         {@link AuditCheckpoint#keyId()} so a verifier can select the matching
     *         public key. This label is the selector, not itself a cryptographic binding,
     *         so verification resolves it through {@link CheckpointKeyResolver} rather
     *         than assuming the current signer produced the checkpoint in hand.
     *
     *         <p><strong>An implementation must never reuse an identifier across
     *         different key material.</strong> Doing so makes the label a lie: every
     *         checkpoint carrying it names a key identity that now points at something
     *         else, and no verifier can tell which one it meant. Derive the identifier
     *         from the key (see {@link Ed25519CheckpointSigner#keyIdFor}) or take it from
     *         durable custody alongside the key itself — never declare it beside freshly
     *         generated material.
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
     * Verifies a detached signature against this signer's own key. Inherited from
     * {@link CheckpointVerifier}: a signer can always verify what it signed, but it is
     * only ever the right verifier for checkpoints carrying <em>its</em>
     * {@link #keyId()}.
     */
    @Override
    boolean verify(String signingInput, String hexSignature);
}
