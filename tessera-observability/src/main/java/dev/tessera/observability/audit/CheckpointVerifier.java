package dev.tessera.observability.audit;

/**
 * Verifies a detached checkpoint signature against one specific key.
 *
 * <p>Split out from {@link CheckpointSigner} because verifying and signing have different
 * lifetimes. A checkpoint must stay verifiable for as long as the audit trail is retained
 * — across restarts, across rotations, long after the key that produced it stopped
 * signing — whereas only one key signs at a time. Resolving which verifier a given
 * checkpoint needs is {@link CheckpointKeyResolver}'s job; this is the verification
 * itself, over the key already selected.
 */
@FunctionalInterface
public interface CheckpointVerifier {

    /**
     * Verifies a detached signature against {@code signingInput}.
     *
     * @param signingInput the canonical checkpoint bytes (see
     *                     {@link AuditCheckpoint#signingInput()})
     * @param hexSignature the lowercase-hex signature to check
     * @return {@code true} iff the signature is valid for this verifier's key
     */
    boolean verify(String signingInput, String hexSignature);
}
