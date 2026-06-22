package dev.tessera.observability.audit;

import dev.tessera.observability.metrics.IamMetrics;
import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Event;
import jakarta.inject.Inject;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import org.jboss.logging.Logger;

/**
 * Application-scoped, tenant-scoped tamper-evident audit log.
 *
 * <p>Each tenant has its own independent hash chain (see {@link AuditEntry}); a
 * tenant's entries never share a chain with another tenant's, so tampering or
 * truncation is detected per tenant and one tenant cannot affect another's
 * verifiability. {@link #record(String, String, Map)} appends an entry, increments
 * the {@code iam.audit.entry} metric and fires an {@link AuditEvent.EntryRecorded}
 * on the in-process {@code iam.audit.*} event channel.
 * {@link #checkpoint(String)} signs the current head of a tenant's chain, increments
 * {@code iam.audit.checkpoint} and fires {@link AuditEvent.CheckpointSigned}.</p>
 *
 * <p>This bean keeps each tenant's chain in memory as the reference, self-contained
 * implementation: it is the source for {@link #verify(String)} and for the periodic
 * checkpoint. Durable, append-only persistence is a deployment concern fulfilled by
 * observing {@link AuditEvent} and writing to an external sink — the chain and
 * checkpoint logic here do not depend on any particular store. Appends per tenant
 * are serialized so sequence numbers and links are assigned without races; different
 * tenants proceed concurrently.</p>
 */
@ApplicationScoped
public class TenantAuditLog {

    private static final Logger LOG = Logger.getLogger(TenantAuditLog.class);

    /** Metric subsystem segment for every audit meter. */
    static final String SUBSYSTEM = "audit";

    private final ConcurrentMap<String, List<AuditEntry>> chains = new ConcurrentHashMap<>();

    private final IamMetrics metrics;
    private final CheckpointSigner signer;
    private final Event<AuditEvent> events;
    private final Clock clock;

    @Inject
    public TenantAuditLog(IamMetrics metrics, CheckpointSigner signer, Event<AuditEvent> events) {
        this(metrics, signer, events, Clock.systemUTC());
    }

    /** Package-visible constructor for unit tests with a fixed clock. */
    TenantAuditLog(IamMetrics metrics, CheckpointSigner signer, Event<AuditEvent> events, Clock clock) {
        this.metrics = Objects.requireNonNull(metrics, "metrics must not be null");
        this.signer = Objects.requireNonNull(signer, "signer must not be null");
        this.events = Objects.requireNonNull(events, "events must not be null");
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
     * @return the appended, self-hashed entry
     */
    public AuditEntry record(String tenant, String eventType, Map<String, String> attributes) {
        requireText(tenant, "tenant");
        Instant now = clock.instant();
        // Per-tenant serialization: the whole append is atomic w.r.t. this tenant's chain.
        List<AuditEntry> chain = chains.computeIfAbsent(tenant, t -> new ArrayList<>());
        final AuditEntry appended;
        synchronized (chain) {
            appended = chain.isEmpty()
                    ? AuditEntry.genesis(tenant, eventType, now, attributes)
                    : AuditEntry.append(chain.get(chain.size() - 1), eventType, now, attributes);
            chain.add(appended);
        }
        metrics.increment(SUBSYSTEM, "entry", "tenant", tenant, "event", eventType);
        events.fire(new AuditEvent.EntryRecorded(appended));
        return appended;
    }

    /**
     * Signs the current head of {@code tenant}'s chain, producing a checkpoint that
     * anchors every entry written so far.
     *
     * @param tenant the tenant whose chain to checkpoint; not null/blank
     * @return the signed checkpoint
     */
    public AuditCheckpoint checkpoint(String tenant) {
        requireText(tenant, "tenant");
        List<AuditEntry> chain = chains.computeIfAbsent(tenant, t -> new ArrayList<>());
        final String headHash;
        final long headSequence;
        synchronized (chain) {
            headHash = AuditChain.headHash(chain);
            headSequence = chain.isEmpty() ? -1L : chain.get(chain.size() - 1).sequence();
        }
        Instant now = clock.instant();
        String signingInput =
                AuditCheckpoint.signingInput(tenant, headSequence, headHash, now, signer.keyId());
        String signature = signer.sign(signingInput);
        AuditCheckpoint checkpoint =
                new AuditCheckpoint(tenant, headSequence, headHash, now, signer.keyId(), signature);

        metrics.increment(SUBSYSTEM, "checkpoint", "tenant", tenant);
        events.fire(new AuditEvent.CheckpointSigned(checkpoint));
        return checkpoint;
    }

    /**
     * Verifies the integrity of {@code tenant}'s chain as currently held.
     *
     * @param tenant the tenant to verify; not null/blank
     * @return the verification outcome (trivially valid for an unknown/empty tenant)
     */
    public AuditChain.Verification verify(String tenant) {
        requireText(tenant, "tenant");
        return AuditChain.verify(snapshot(tenant));
    }

    /**
     * Verifies that {@code checkpoint}'s signature is authentic and that it still
     * anchors a genuine prefix of {@code tenant}'s chain.
     *
     * <p>A checkpoint attests the chain up to its {@code headSequence}, not necessarily
     * the live tail: the chain legitimately grows after a checkpoint is signed, so a
     * historical checkpoint must remain verifiable. Verification therefore checks that
     * the entry now occupying {@code headSequence} still hashes to the signed
     * {@code headHash} — i.e. the prefix the checkpoint covers has not been truncated or
     * rewritten. (A signed checkpoint over the {@link AuditEntry#GENESIS_HASH} at
     * sequence {@code -1} anchors the empty chain.) Any tampering with that prefix moves
     * the entry's hash and fails the check; a forged signature fails first.</p>
     *
     * @param tenant     the tenant the checkpoint should anchor
     * @param checkpoint the checkpoint to verify
     * @return {@code true} iff the signature is valid and the checkpoint still anchors an
     *         untampered prefix of the tenant's chain
     */
    public boolean verifyCheckpoint(String tenant, AuditCheckpoint checkpoint) {
        requireText(tenant, "tenant");
        Objects.requireNonNull(checkpoint, "checkpoint must not be null");
        if (!tenant.equals(checkpoint.tenant())) {
            return false;
        }
        if (!signer.verify(checkpoint.signingInput(), checkpoint.signature())) {
            return false;
        }
        List<AuditEntry> chain = snapshot(tenant);
        long seq = checkpoint.headSequence();
        if (seq == -1L) {
            // The checkpoint anchored an empty chain; it still holds iff nothing was
            // appended at sequence 0 since (the genesis-hash anchor cannot be tampered).
            return checkpoint.headHash().equals(AuditEntry.GENESIS_HASH);
        }
        // The signed prefix must still be present and intact: the entry that was the head
        // at checkpoint time must still occupy that sequence and hash to headHash.
        if (seq < 0 || seq >= chain.size()) {
            return false;
        }
        AuditEntry anchored = chain.get((int) seq);
        return anchored.sequence() == seq && anchored.hash().equals(checkpoint.headHash());
    }

    /**
     * @return an immutable snapshot of the tenants that currently have a chain — the
     *         set the periodic checkpoint trigger iterates over
     */
    public java.util.Set<String> tenants() {
        return java.util.Set.copyOf(chains.keySet());
    }

    /**
     * @param tenant a tenant
     * @return an immutable snapshot of the tenant's chain (empty if unknown), ordered
     *         by ascending sequence
     */
    public List<AuditEntry> snapshot(String tenant) {
        requireText(tenant, "tenant");
        List<AuditEntry> chain = chains.get(tenant);
        if (chain == null) {
            return List.of();
        }
        synchronized (chain) {
            return List.copyOf(chain);
        }
    }

    private static void requireText(String value, String label) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(label + " must not be null or blank");
        }
    }
}
