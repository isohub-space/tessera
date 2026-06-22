package dev.tessera.observability.audit;

import io.quarkus.arc.DefaultBean;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-memory {@link TenantAuditLogRepository} — the bundled, self-contained default so the
 * audit subsystem works out of the box and in tests without an external store.
 *
 * <p>Each tenant's chain is an append-only {@link ArrayList} guarded by its own monitor;
 * appends for one tenant are serialized while different tenants proceed concurrently, and
 * reads take a consistent snapshot under the same monitor. {@link #stream(String)} emits
 * that snapshot lazily as a {@link Multi} so the verification fold consumes it one entry
 * at a time. Marked {@link DefaultBean} so a deployment-supplied (e.g. Postgres-backed,
 * streaming {@code ORDER BY sequence}) {@link TenantAuditLogRepository} takes precedence
 * without any change to the audit core.</p>
 */
@ApplicationScoped
@DefaultBean
public class InMemoryTenantAuditLogRepository implements TenantAuditLogRepository {

    private final ConcurrentMap<String, List<AuditEntry>> chains = new ConcurrentHashMap<>();

    @Override
    public Uni<Void> append(AuditEntry entry) {
        Objects.requireNonNull(entry, "entry must not be null");
        List<AuditEntry> chain = chains.computeIfAbsent(entry.tenant(), t -> new ArrayList<>());
        synchronized (chain) {
            chain.add(entry);
        }
        return Uni.createFrom().voidItem();
    }

    @Override
    public Multi<AuditEntry> stream(String tenant) {
        requireText(tenant, "tenant");
        // Snapshot under the monitor, then emit lazily — the consumer (the verification
        // fold) pulls one entry at a time and never holds the whole chain.
        List<AuditEntry> chain = chains.get(tenant);
        if (chain == null) {
            return Multi.createFrom().empty();
        }
        final List<AuditEntry> snapshot;
        synchronized (chain) {
            snapshot = List.copyOf(chain);
        }
        return Multi.createFrom().iterable(snapshot);
    }

    @Override
    public Uni<Head> head(String tenant) {
        requireText(tenant, "tenant");
        List<AuditEntry> chain = chains.get(tenant);
        if (chain == null) {
            return Uni.createFrom().item(Head.empty());
        }
        final Head head;
        synchronized (chain) {
            head = chain.isEmpty()
                    ? Head.empty()
                    : new Head(chain.get(chain.size() - 1).sequence(), chain.get(chain.size() - 1).hash());
        }
        return Uni.createFrom().item(head);
    }

    @Override
    public Uni<Set<String>> tenants() {
        return Uni.createFrom().item(Set.copyOf(chains.keySet()));
    }

    private static void requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be null or blank");
        }
    }
}
