package dev.tessera.observability.audit;

import java.time.Instant;
import java.util.Objects;

/**
 * A signed checkpoint over a tenant's audit chain at a point in time.
 *
 * <p>Periodically the server signs the current head of each tenant's chain,
 * producing a checkpoint that anchors everything written so far. Because the head
 * hash transitively covers every prior entry, a single signature over it attests
 * the whole chain up to {@code headSequence}: a verifier that trusts the signing
 * public key can confirm the chain has not been truncated or rewritten behind the
 * checkpoint without re-signing — which it cannot do without the private key.</p>
 *
 * @param tenant        the tenant whose chain this checkpoint anchors; never null/blank
 * @param headSequence  the sequence number of the chain head at checkpoint time, or
 *                      {@code -1} for an empty chain
 * @param headHash      the lowercase-hex hash of the chain head (or
 *                      {@link AuditEntry#GENESIS_HASH} for an empty chain); never null
 * @param createdAt     when the checkpoint was produced; never null
 * @param keyId         identifier of the key that produced {@code signature}; never null/blank
 * @param signature     lowercase-hex detached signature over the canonical checkpoint
 *                      content; never null/blank
 */
public record AuditCheckpoint(
        String tenant,
        long headSequence,
        String headHash,
        Instant createdAt,
        String keyId,
        String signature) {

    public AuditCheckpoint {
        requireText(tenant, "tenant");
        if (headSequence < -1) {
            throw new IllegalArgumentException("headSequence must be >= -1");
        }
        Objects.requireNonNull(headHash, "headHash must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        requireText(keyId, "keyId");
        requireText(signature, "signature");
    }

    /**
     * The canonical, length-prefixed content that the signature is computed over.
     * Kept identical between signing and verification so the bytes match exactly.
     *
     * @return the signing input
     */
    public String signingInput() {
        return signingInput(tenant, headSequence, headHash, createdAt, keyId);
    }

    static String signingInput(
            String tenant, long headSequence, String headHash, Instant createdAt, String keyId) {
        StringBuilder sb = new StringBuilder(96);
        sb.append("checkpoint-v1\n");
        field(sb, "tenant", tenant);
        field(sb, "headSeq", Long.toString(headSequence));
        field(sb, "headHash", headHash);
        field(sb, "createdAt", createdAt.toString());
        field(sb, "keyId", keyId);
        return sb.toString();
    }

    private static void field(StringBuilder sb, String key, String value) {
        byte[] vb = value.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        sb.append(key).append('=').append(vb.length).append(':').append(value).append('\n');
    }

    private static void requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be null or blank");
        }
    }
}
