package dev.tessera.observability.audit;

import java.util.List;
import java.util.Objects;

/**
 * Pure verification of a tamper-evident audit hash chain.
 *
 * <p>A chain is a list of {@link AuditEntry} ordered by ascending sequence, each
 * hashing over its predecessor's hash. Verification re-derives every entry's hash
 * from its content and checks four invariants:</p>
 * <ol>
 *   <li>the first entry's {@code previousHash} is {@link AuditEntry#GENESIS_HASH};</li>
 *   <li>sequence numbers are contiguous and start at {@code 0} (no gaps/reorder);</li>
 *   <li>each entry's {@code previousHash} equals the prior entry's stored hash;</li>
 *   <li>each entry's stored {@code hash} equals the hash recomputed from its content.</li>
 * </ol>
 *
 * <p>Mutating, inserting, deleting or reordering any entry violates at least one
 * invariant, so {@link #verify(List)} returns a failure pinpointing the first
 * broken link. Stateless and side-effect-free.</p>
 */
public final class AuditChain {

    private AuditChain() {
    }

    /**
     * The outcome of verifying a chain.
     *
     * @param valid        whether every invariant held
     * @param brokenAt     index of the first entry that failed, or {@code -1} when valid
     * @param reason       human-readable description of the failure, or {@code null} when valid
     */
    public record Verification(boolean valid, int brokenAt, String reason) {

        static Verification ok() {
            return new Verification(true, -1, null);
        }

        static Verification broken(int index, String reason) {
            return new Verification(false, index, reason);
        }
    }

    /**
     * Verifies a per-tenant chain.
     *
     * @param entries the chain ordered by ascending sequence; never null. An empty
     *                chain is trivially valid.
     * @return the verification outcome
     */
    public static Verification verify(List<AuditEntry> entries) {
        Objects.requireNonNull(entries, "entries must not be null");
        if (entries.isEmpty()) {
            return Verification.ok();
        }

        String expectedTenant = entries.get(0).tenant();
        String previousHash = AuditEntry.GENESIS_HASH;

        for (int i = 0; i < entries.size(); i++) {
            AuditEntry entry = entries.get(i);

            if (!expectedTenant.equals(entry.tenant())) {
                return Verification.broken(i, "tenant changed within chain: expected "
                        + expectedTenant + " but entry " + i + " is " + entry.tenant());
            }
            if (entry.sequence() != i) {
                return Verification.broken(i, "sequence gap or reorder: expected " + i
                        + " but entry carries " + entry.sequence());
            }
            if (!previousHash.equals(entry.previousHash())) {
                return Verification.broken(i, "broken link: entry " + i
                        + " previousHash does not match the prior entry's hash");
            }
            String recomputed = entry.recomputeHash();
            if (!recomputed.equals(entry.hash())) {
                return Verification.broken(i, "tampered content: entry " + i
                        + " stored hash does not match its recomputed hash");
            }
            previousHash = entry.hash();
        }
        return Verification.ok();
    }

    /**
     * @param entries a chain (possibly empty), ordered by ascending sequence
     * @return the hash of the last entry, or {@link AuditEntry#GENESIS_HASH} for an
     *         empty chain — i.e. the value the next appended entry chains over and the
     *         value a checkpoint should sign
     */
    public static String headHash(List<AuditEntry> entries) {
        Objects.requireNonNull(entries, "entries must not be null");
        return entries.isEmpty() ? AuditEntry.GENESIS_HASH : entries.get(entries.size() - 1).hash();
    }
}
