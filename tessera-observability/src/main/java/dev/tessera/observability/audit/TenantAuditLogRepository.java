package dev.tessera.observability.audit;

import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import java.util.Set;

/**
 * Outbound port for the durable, append-only storage behind a tenant's audit chain.
 *
 * <p>Verification and checkpointing must work over an <em>unbounded</em> per-tenant log
 * without holding it in memory, so reads are exposed as a {@link Multi} that streams the
 * entries <strong>in ascending chain-sequence order</strong>. {@link TenantAuditLog}
 * folds that stream through the pure {@link AuditChain#verifyNext(AuditChain.State, AuditEntry)}
 * step, giving O(1)-memory verification regardless of chain length. The port deliberately
 * never returns a {@code List} of entries.</p>
 *
 * <p>The contract is reactive at this boundary; the chain math itself stays pure and
 * framework-free in {@link AuditChain}. An adapter implements this port — the bundled
 * in-memory {@link InMemoryTenantAuditLogRepository} for self-contained operation and
 * tests, or a deployment-supplied store (e.g. a reactive Postgres adapter streaming
 * {@code ORDER BY sequence}) for durability.</p>
 */
public interface TenantAuditLogRepository {

    /**
     * Appends an already-formed, self-hashed entry to its tenant's chain. The caller
     * (the audit log) has assigned the sequence and links; the adapter persists it.
     *
     * @param entry the entry to append (never null); {@link AuditEntry#tenant()} selects
     *              the chain and {@link AuditEntry#sequence()} its position
     * @return a {@link Uni} completing when the entry is durably appended
     */
    Uni<Void> append(AuditEntry entry);

    /**
     * Streams a tenant's chain in ascending sequence order, one entry at a time.
     *
     * @param tenant the tenant whose chain to stream; not null/blank
     * @return a {@link Multi} emitting the tenant's entries ordered by sequence (empty if
     *         the tenant has no chain)
     */
    Multi<AuditEntry> stream(String tenant);

    /**
     * Resolves the current head of a tenant's chain — the hash and sequence the next
     * appended entry chains over, and that a checkpoint signs — without materializing the
     * whole chain.
     *
     * @param tenant the tenant; not null/blank
     * @return a {@link Uni} emitting the head; {@link Head#empty()} for an unknown/empty chain
     */
    Uni<Head> head(String tenant);

    /**
     * @return a {@link Uni} emitting the set of tenants that currently have a chain — the
     *         set the periodic checkpoint trigger iterates over
     */
    Uni<Set<String>> tenants();

    /**
     * The head of a tenant's chain: the last entry's sequence and hash, or the
     * empty-chain anchor.
     *
     * @param sequence the head entry's sequence, or {@code -1} for an empty chain
     * @param hash     the head entry's hash, or {@link AuditEntry#GENESIS_HASH} for an
     *                 empty chain
     */
    record Head(long sequence, String hash) {

        /** @return the head of an empty chain: sequence {@code -1}, genesis hash. */
        public static Head empty() {
            return new Head(-1L, AuditEntry.GENESIS_HASH);
        }

        /** @return whether this head denotes an empty chain. */
        public boolean isEmpty() {
            return sequence < 0;
        }
    }
}
