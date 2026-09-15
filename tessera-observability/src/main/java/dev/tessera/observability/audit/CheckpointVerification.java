package dev.tessera.observability.audit;

import java.util.Objects;

/**
 * The outcome of verifying an {@link AuditCheckpoint}.
 *
 * <p>Deliberately not a boolean. "Has the audit log been altered?" has more than two
 * honest answers, and collapsing them is what made the checkpoint mechanism misleading:
 * a checkpoint signed by a key that no longer exists used to fail exactly like a forged
 * one, so an operator could not distinguish a rewritten log from a restarted server.
 * Tamper-evidence that cannot tell those apart is worse than none, because it is trusted.
 *
 * <p>The variants separate the three questions in the order verification asks them: is the
 * key known, is the signature genuine, and does the anchored prefix still match.
 */
public sealed interface CheckpointVerification {

    /** @return {@code true} only for {@link Valid} — every other outcome is not a pass. */
    default boolean isValid() {
        return this instanceof Valid;
    }

    /**
     * The signature is genuine under the named key and the anchored prefix of the chain
     * still hashes to what was signed.
     */
    record Valid(String keyId) implements CheckpointVerification {
        public Valid {
            Objects.requireNonNull(keyId, "keyId must not be null");
        }
    }

    /**
     * The checkpoint names a key this deployment cannot resolve, so it can be neither
     * confirmed nor refuted.
     *
     * <p>This is <strong>not</strong> a tampering signal and must never be reported as
     * one. It is the expected outcome for a checkpoint written before a restart when the
     * signing key was ephemeral, and the honest answer is "unknown": the evidence needed
     * to judge this checkpoint is absent. Resolving it requires durable key custody, not
     * a change to this verification path.
     */
    record UnknownKey(String keyId) implements CheckpointVerification {
        public UnknownKey {
            Objects.requireNonNull(keyId, "keyId must not be null");
        }
    }

    /**
     * The named key is known, but the signature does not verify under it — the checkpoint
     * was forged or altered after signing.
     */
    record SignatureInvalid(String keyId) implements CheckpointVerification {
        public SignatureInvalid {
            Objects.requireNonNull(keyId, "keyId must not be null");
        }
    }

    /**
     * The signature is genuine, but the chain no longer matches what was signed: the entry
     * now at the anchored sequence does not hash to the anchored head hash, so the covered
     * prefix has been truncated or rewritten. This is the positive tampering signal.
     */
    record ChainMismatch(String keyId, long headSequence) implements CheckpointVerification {
        public ChainMismatch {
            Objects.requireNonNull(keyId, "keyId must not be null");
        }
    }

    /**
     * The checkpoint anchors a different tenant than the one it was presented for. A
     * caller-side mistake rather than evidence about the chain, kept distinct so it is
     * never read as tampering.
     */
    record TenantMismatch(String expectedTenant, String checkpointTenant)
            implements CheckpointVerification {
        public TenantMismatch {
            Objects.requireNonNull(expectedTenant, "expectedTenant must not be null");
            Objects.requireNonNull(checkpointTenant, "checkpointTenant must not be null");
        }
    }
}
