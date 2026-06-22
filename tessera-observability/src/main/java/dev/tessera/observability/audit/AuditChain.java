package dev.tessera.observability.audit;

import java.util.List;
import java.util.Objects;

/**
 * Pure verification of a tamper-evident audit hash chain.
 *
 * <p>A chain is a sequence of {@link AuditEntry} ordered by ascending sequence, each
 * hashing over its predecessor's hash. Verification re-derives every entry's hash
 * from its content and checks four invariants:</p>
 * <ol>
 *   <li>the first entry's {@code previousHash} is {@link AuditEntry#GENESIS_HASH};</li>
 *   <li>sequence numbers are contiguous and start at {@code 0} (no gaps/reorder);</li>
 *   <li>each entry's {@code previousHash} equals the prior entry's stored hash;</li>
 *   <li>each entry's stored {@code hash} equals the hash recomputed from its content.</li>
 * </ol>
 *
 * <p>The core is a <strong>pure, per-entry fold step</strong>,
 * {@link #verifyNext(State, AuditEntry)}, mirroring the project's other pure reducers
 * (e.g. the auth-flow reducer): it takes the running {@link State} and one entry and
 * returns the next {@link State}, performing no I/O and holding no chain in memory. A
 * caller folds the entries through it one at a time, so verification runs in
 * <strong>O(1) working memory</strong> regardless of chain length — the whole
 * (unbounded) per-tenant log never needs to be materialized. {@link #verify(List)} is
 * the convenience fold over an already-materialized list; a streaming source folds the
 * same step over a reactive stream (see {@code StreamingAuditVerifier}).</p>
 *
 * <p>Mutating, inserting, deleting or reordering any entry violates at least one
 * invariant, so the fold reports a failure pinpointing the first broken link. Stateless
 * and side-effect-free.</p>
 */
public final class AuditChain {

    private AuditChain() {
    }

    /**
     * @return a fresh initial fold state — a supplier-friendly alias for
     *         {@link State#initial()}, used as the seed when folding the per-entry step
     *         over a stream
     */
    public static State initialState() {
        return State.initial();
    }

    /**
     * The outcome of verifying a chain.
     *
     * @param valid    whether every invariant held
     * @param brokenAt index of the first entry that failed, or {@code -1} when valid
     * @param reason   human-readable description of the failure, or {@code null} when valid
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
     * The running state threaded through the per-entry fold. Immutable and tiny — it
     * holds only what the next step needs (the expected next sequence, the previous
     * entry's hash, the pinned tenant) plus the terminal verdict — never the entries
     * themselves, which is what keeps verification O(1) in memory.
     *
     * @param expectedSequence the sequence the next entry must carry ({@code 0}-based)
     * @param previousHash     the hash the next entry must chain over
     * @param tenant           the tenant pinned by the first entry, or {@code null} before it
     * @param result           the verdict so far: {@link Verification#valid()} while the
     *                          fold may still continue, or a failure once a step breaks
     */
    public record State(long expectedSequence, String previousHash, String tenant, Verification result) {

        public State {
            Objects.requireNonNull(previousHash, "previousHash must not be null");
            Objects.requireNonNull(result, "result must not be null");
        }

        /**
         * @return the initial state for an empty fold — expecting sequence {@code 0}
         *         chaining over {@link AuditEntry#GENESIS_HASH}, with no tenant pinned and
         *         a (trivially) valid verdict
         */
        public static State initial() {
            return new State(0L, AuditEntry.GENESIS_HASH, null, Verification.ok());
        }

        /** @return whether the fold may still continue (no broken link seen yet). */
        public boolean ongoing() {
            return result.valid();
        }
    }

    /**
     * Folds one entry into the running {@link State} — the pure verification step.
     *
     * <p>Re-derives the entry's hash and checks the four chain invariants against the
     * running state. On success it returns the advanced state (next expected sequence,
     * this entry's hash as the new previous-hash, tenant pinned). On the first violation
     * it returns a state carrying the failure {@link Verification}; subsequent calls are
     * a no-op pass-through, so a caller may stop early or keep folding harmlessly.</p>
     *
     * @param state the running state (never null); use {@link State#initial()} to start
     * @param entry the next entry in ascending-sequence order (never null)
     * @return the next state
     */
    public static State verifyNext(State state, AuditEntry entry) {
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(entry, "entry must not be null");

        // Once broken, stay broken: the verdict pins the first failing index.
        if (!state.ongoing()) {
            return state;
        }

        int index = (int) state.expectedSequence();
        String expectedTenant = state.tenant() == null ? entry.tenant() : state.tenant();

        if (!expectedTenant.equals(entry.tenant())) {
            return broken(state, index, "tenant changed within chain: expected "
                    + expectedTenant + " but entry " + index + " is " + entry.tenant());
        }
        if (entry.sequence() != state.expectedSequence()) {
            return broken(state, index, "sequence gap or reorder: expected " + state.expectedSequence()
                    + " but entry carries " + entry.sequence());
        }
        if (!state.previousHash().equals(entry.previousHash())) {
            return broken(state, index, "broken link: entry " + index
                    + " previousHash does not match the prior entry's hash");
        }
        if (!entry.recomputeHash().equals(entry.hash())) {
            return broken(state, index, "tampered content: entry " + index
                    + " stored hash does not match its recomputed hash");
        }
        return new State(state.expectedSequence() + 1, entry.hash(), expectedTenant, Verification.ok());
    }

    private static State broken(State state, int index, String reason) {
        return new State(state.expectedSequence(), state.previousHash(), state.tenant(),
                Verification.broken(index, reason));
    }

    /**
     * Verifies a per-tenant chain held as a list, by folding {@link #verifyNext} over it.
     * Convenience for callers that already hold the entries; a streaming source should
     * fold {@link #verifyNext} over its stream instead to keep memory O(1).
     *
     * @param entries the chain ordered by ascending sequence; never null. An empty chain
     *                is trivially valid.
     * @return the verification outcome
     */
    public static Verification verify(List<AuditEntry> entries) {
        Objects.requireNonNull(entries, "entries must not be null");
        State state = State.initial();
        for (AuditEntry entry : entries) {
            state = verifyNext(state, entry);
            if (!state.ongoing()) {
                break;
            }
        }
        return state.result();
    }

    /**
     * @param entries a chain (possibly empty), ordered by ascending sequence
     * @return the hash of the last entry, or {@link AuditEntry#GENESIS_HASH} for an empty
     *         chain — i.e. the value the next appended entry chains over and the value a
     *         checkpoint should sign
     */
    public static String headHash(List<AuditEntry> entries) {
        Objects.requireNonNull(entries, "entries must not be null");
        return entries.isEmpty() ? AuditEntry.GENESIS_HASH : entries.get(entries.size() - 1).hash();
    }
}
