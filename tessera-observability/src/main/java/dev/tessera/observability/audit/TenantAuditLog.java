package dev.tessera.observability.audit;

import dev.tessera.observability.metrics.IamMetrics;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;
import org.jboss.logging.Logger;

/**
 * Application-scoped, tenant-scoped tamper-evident audit log.
 *
 * <p>Each tenant has its own independent hash chain (see {@link AuditEntry}); a tenant's
 * entries never share a chain with another tenant's, so tampering or truncation is
 * detected per tenant and one tenant cannot affect another's verifiability.</p>
 *
 * <p>Storage is an outbound concern behind the {@link TenantAuditLogRepository} port — the
 * bundled in-memory adapter, or a durable streaming store. Crucially, verification and
 * checkpointing read the chain as a {@link Multi} streamed in sequence order and fold the
 * pure {@link AuditChain#verifyNext} step over it, so an <strong>unbounded</strong>
 * per-tenant log is verified in <strong>O(1) memory</strong> — the whole chain is never
 * materialized. {@link #record(String, String, Map)} appends an entry, increments the
 * {@code iam.audit.entry} metric and fires an {@link AuditEvent.EntryRecorded};
 * {@link #checkpoint(String)} signs the current head, increments
 * {@code iam.audit.checkpoint} and fires {@link AuditEvent.CheckpointSigned}.</p>
 *
 * <p>Appends for a given tenant are serialized on a per-tenant lock so the read-head /
 * assign-sequence / append step is atomic and sequence numbers and links are assigned
 * without races; different tenants proceed concurrently.</p>
 */
@ApplicationScoped
public class TenantAuditLog {

    private static final Logger LOG = Logger.getLogger(TenantAuditLog.class);

    /** Metric subsystem segment for every audit meter. */
    static final String SUBSYSTEM = "audit";

    /** Per-tenant append serialization (sequence assignment must be atomic per chain). */
    private final ConcurrentMap<String, ReentrantLock> appendLocks = new ConcurrentHashMap<>();

    private final IamMetrics metrics;
    private final CheckpointSigner signer;
    private final Event<AuditEvent> events;
    private final TenantAuditLogRepository repository;
    private final Clock clock;

    @Inject
    public TenantAuditLog(IamMetrics metrics, CheckpointSigner signer, Event<AuditEvent> events,
            TenantAuditLogRepository repository) {
        this(metrics, signer, events, repository, Clock.systemUTC());
    }

    /** Package-visible constructor for unit tests with a fixed clock. */
    TenantAuditLog(IamMetrics metrics, CheckpointSigner signer, Event<AuditEvent> events,
            TenantAuditLogRepository repository, Clock clock) {
        this.metrics = Objects.requireNonNull(metrics, "metrics must not be null");
        this.signer = Objects.requireNonNull(signer, "signer must not be null");
        this.events = Objects.requireNonNull(events, "events must not be null");
        this.repository = Objects.requireNonNull(repository, "repository must not be null");
        this.clock = Objects.requireNonNull(clock, "clock must not be null");
    }

    @PostConstruct
    void started() {
        LOG.infof("Tenant audit log ready (checkpoint signer keyId=%s)", signer.keyId());
    }

    /**
     * Appends an entry to {@code tenant}'s chain.
     *
     * <p>The caller is responsible for ensuring {@code attributes} carry no secrets or
     * PII: values are hashed into the entry, fired verbatim on the {@code iam.audit.*}
     * channel, and forwarded to whatever durable sink observes those events. Do not put
     * tokens, authorization codes, client secrets, PKCE verifiers or passwords here.</p>
     *
     * @param tenant     the tenant whose chain to append to; not null/blank
     * @param eventType  a stable event-type name (e.g. {@code "token.issued"}); not null/blank
     * @param attributes free-form, non-secret attributes; not null (may be empty)
     * @return a {@link Uni} emitting the appended, self-hashed entry
     */
    public Uni<AuditEntry> record(String tenant, String eventType, Map<String, String> attributes) {
        requireText(tenant, "tenant");
        Instant now = clock.instant();
        ReentrantLock lock = appendLocks.computeIfAbsent(tenant, t -> new ReentrantLock());
        // Serialize the read-head/assign-sequence/append per tenant so concurrent records
        // can't assign the same sequence or chain over a stale head.
        lock.lock();
        try {
            TenantAuditLogRepository.Head head = repository.head(tenant).await().indefinitely();
            AuditEntry appended = head.isEmpty()
                    ? AuditEntry.genesis(tenant, eventType, now, attributes)
                    : AuditEntry.appendAfter(head.sequence(), tenant, head.hash(), eventType, now, attributes);
            repository.append(appended).await().indefinitely();
            metrics.increment(SUBSYSTEM, "entry", "tenant", tenant, "event", eventType);
            events.fire(new AuditEvent.EntryRecorded(appended));
            return Uni.createFrom().item(appended);
        } finally {
            lock.unlock();
        }
    }

    /**
     * Signs the current head of {@code tenant}'s chain, producing a checkpoint that
     * anchors every entry written so far.
     *
     * @param tenant the tenant whose chain to checkpoint; not null/blank
     * @return a {@link Uni} emitting the signed checkpoint
     */
    public Uni<AuditCheckpoint> checkpoint(String tenant) {
        requireText(tenant, "tenant");
        return repository.head(tenant).map(head -> {
            Instant now = clock.instant();
            String signingInput =
                    AuditCheckpoint.signingInput(tenant, head.sequence(), head.hash(), now, signer.keyId());
            String signature = signer.sign(signingInput);
            AuditCheckpoint checkpoint =
                    new AuditCheckpoint(tenant, head.sequence(), head.hash(), now, signer.keyId(), signature);
            metrics.increment(SUBSYSTEM, "checkpoint", "tenant", tenant);
            events.fire(new AuditEvent.CheckpointSigned(checkpoint));
            return checkpoint;
        });
    }

    /**
     * Verifies the integrity of {@code tenant}'s chain by streaming it through the pure
     * per-entry chain step — O(1) memory, no materialization.
     *
     * @param tenant the tenant to verify; not null/blank
     * @return a {@link Uni} emitting the verification outcome (trivially valid for an
     *         unknown/empty tenant)
     */
    public Uni<AuditChain.Verification> verify(String tenant) {
        requireText(tenant, "tenant");
        return StreamingAuditVerifier.verify(repository.stream(tenant));
    }

    /**
     * Verifies that {@code checkpoint}'s signature is authentic and that it still anchors
     * a genuine prefix of {@code tenant}'s chain.
     *
     * <p>A checkpoint attests the chain up to its {@code headSequence}, not necessarily
     * the live tail: the chain legitimately grows after a checkpoint is signed, so a
     * historical checkpoint must remain verifiable. Verification therefore streams the
     * chain to the entry now occupying {@code headSequence} (without collecting it) and
     * checks that it still hashes to the signed {@code headHash} — i.e. the covered prefix
     * has not been truncated or rewritten. A signed checkpoint over the empty chain
     * (sequence {@code -1}, genesis hash) holds while the chain remains empty there.</p>
     *
     * @param tenant     the tenant the checkpoint should anchor
     * @param checkpoint the checkpoint to verify
     * @return a {@link Uni} emitting {@code true} iff the signature is valid and the
     *         checkpoint still anchors an untampered prefix of the tenant's chain
     */
    public Uni<Boolean> verifyCheckpoint(String tenant, AuditCheckpoint checkpoint) {
        requireText(tenant, "tenant");
        Objects.requireNonNull(checkpoint, "checkpoint must not be null");
        if (!tenant.equals(checkpoint.tenant())
                || !signer.verify(checkpoint.signingInput(), checkpoint.signature())) {
            return Uni.createFrom().item(false);
        }
        long seq = checkpoint.headSequence();
        if (seq < 0) {
            // Anchored the empty chain: still holds iff nothing occupies sequence 0.
            return repository.stream(tenant).toUni()
                    .map(first -> first == null && AuditEntry.GENESIS_HASH.equals(checkpoint.headHash()));
        }
        // Stream to the entry at the anchored sequence and compare its hash, without
        // collecting the chain.
        return repository.stream(tenant)
                .filter(e -> e.sequence() == seq)
                .toUni()
                .map(anchored -> anchored != null && anchored.hash().equals(checkpoint.headHash()));
    }

    /**
     * @return a {@link Uni} emitting the tenants that currently have a chain — the set the
     *         periodic checkpoint trigger iterates over
     */
    public Uni<Set<String>> tenants() {
        return repository.tenants();
    }

    /**
     * Streams a tenant's chain in ascending sequence order (delegates to the repository).
     * Exposed for callers that need the raw entries; verification should prefer
     * {@link #verify(String)} which never materializes them.
     *
     * @param tenant a tenant; not null/blank
     * @return a {@link Multi} of the tenant's entries ordered by sequence
     */
    public Multi<AuditEntry> stream(String tenant) {
        requireText(tenant, "tenant");
        return repository.stream(tenant);
    }

    private static void requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be null or blank");
        }
    }
}
