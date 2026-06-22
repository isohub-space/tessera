package dev.tessera.observability.audit;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.observability.metrics.IamMetrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the audit log keeps per-tenant chains continuous, isolates tenants,
 * emits the {@code iam.audit.*} metrics, fires events, and produces checkpoints
 * that bind to (and historically anchor) the chain head — over the streaming
 * repository port, with O(1) verification.
 */
@DisplayName("TenantAuditLog — per-tenant chains, metrics, events & checkpoints")
class TenantAuditLogTest {

    private static final Duration AWAIT = Duration.ofSeconds(5);

    private SimpleMeterRegistry registry;
    private IamMetrics metrics;
    private Ed25519CheckpointSigner signer;
    private RecordingEvent events;
    private InMemoryTenantAuditLogRepository repository;
    private TenantAuditLog log;

    @BeforeEach
    void setUp() {
        registry = new SimpleMeterRegistry();
        metrics = new IamMetrics(registry);
        signer = Ed25519CheckpointSigner.generate("test-key");
        events = new RecordingEvent();
        repository = new InMemoryTenantAuditLogRepository();
        Clock fixed = Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"), ZoneOffset.UTC);
        log = new TenantAuditLog(metrics, signer, events, repository, fixed);
    }

    // ─── helpers ────────────────────────────────────────────────────────────────

    private AuditEntry record(String tenant, String eventType, Map<String, String> attrs) {
        return log.record(tenant, eventType, attrs).await().atMost(AWAIT);
    }

    private List<AuditEntry> chain(String tenant) {
        return log.stream(tenant).collect().asList().await().atMost(AWAIT);
    }

    private AuditCheckpoint checkpoint(String tenant) {
        return log.checkpoint(tenant).await().atMost(AWAIT);
    }

    private boolean verify(String tenant) {
        return log.verify(tenant).await().atMost(AWAIT).valid();
    }

    private boolean verifyCheckpoint(String tenant, AuditCheckpoint cp) {
        return log.verifyCheckpoint(tenant, cp).await().atMost(AWAIT);
    }

    // ─── tests ──────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("recording appends a verifiable, continuous chain")
    void recordsContinuousChain() {
        record("t1", "token.issued", Map.of("sub", "alice"));
        record("t1", "token.refreshed", Map.of("sub", "alice"));
        record("t1", "authorize.granted", Map.of("client", "c1"));

        List<AuditEntry> chain = chain("t1");
        assertThat(chain).hasSize(3);
        assertThat(chain.get(0).previousHash()).isEqualTo(AuditEntry.GENESIS_HASH);
        assertThat(verify("t1")).isTrue();
    }

    @Test
    @DisplayName("each tenant has an independent chain")
    void tenantsAreIsolated() {
        record("t1", "token.issued", Map.of());
        record("t2", "token.issued", Map.of());
        record("t1", "token.issued", Map.of());

        assertThat(chain("t1")).hasSize(2);
        assertThat(chain("t2")).hasSize(1);
        // t2's lone entry is a genesis on its own chain, independent of t1.
        assertThat(chain("t2").get(0).sequence()).isZero();
        assertThat(chain("t2").get(0).previousHash()).isEqualTo(AuditEntry.GENESIS_HASH);
        assertThat(verify("t1")).isTrue();
        assertThat(verify("t2")).isTrue();
    }

    @Test
    @DisplayName("recording increments iam.audit.entry and fires an EntryRecorded event")
    void recordEmitsMetricAndEvent() {
        record("t1", "token.issued", Map.of("sub", "alice"));

        double count = registry.get("iam.audit.entry")
                .tags("tenant", "t1", "event", "token.issued")
                .counter().count();
        assertThat(count).isEqualTo(1.0);
        assertThat(events.fired).hasSize(1);
        assertThat(events.fired.get(0)).isInstanceOf(AuditEvent.EntryRecorded.class);
        assertThat(events.fired.get(0).kind()).isEqualTo(AuditEvent.Kind.ENTRY);
    }

    @Test
    @DisplayName("a checkpoint binds to the chain head and verifies; it increments iam.audit.checkpoint")
    void checkpointBindsToHead() {
        record("t1", "token.issued", Map.of("sub", "alice"));
        record("t1", "token.issued", Map.of("sub", "bob"));

        AuditCheckpoint cp = checkpoint("t1");
        assertThat(cp.headSequence()).isEqualTo(1L);
        assertThat(cp.headHash()).isEqualTo(chain("t1").get(1).hash());
        assertThat(cp.keyId()).isEqualTo("test-key");
        assertThat(verifyCheckpoint("t1", cp)).isTrue();

        assertThat(registry.get("iam.audit.checkpoint").tags("tenant", "t1").counter().count())
                .isEqualTo(1.0);
        assertThat(events.fired).anyMatch(e -> e instanceof AuditEvent.CheckpointSigned);
    }

    @Test
    @DisplayName("a checkpoint over an empty chain anchors the genesis hash at sequence -1")
    void checkpointOverEmptyChain() {
        AuditCheckpoint cp = checkpoint("never-used");
        assertThat(cp.headSequence()).isEqualTo(-1L);
        assertThat(cp.headHash()).isEqualTo(AuditEntry.GENESIS_HASH);
        assertThat(verifyCheckpoint("never-used", cp)).isTrue();
    }

    @Test
    @DisplayName("a historical checkpoint still verifies after the chain legitimately advances")
    void historicalCheckpointStillVerifies() {
        record("t1", "token.issued", Map.of("sub", "alice"));
        AuditCheckpoint cp = checkpoint("t1");
        assertThat(verifyCheckpoint("t1", cp)).isTrue();

        // The chain legitimately grows; the checkpoint anchors a genuine prefix, so it
        // must remain verifiable — that is the whole point of retaining checkpoints.
        record("t1", "token.issued", Map.of("sub", "bob"));
        record("t1", "token.issued", Map.of("sub", "carol"));
        assertThat(verifyCheckpoint("t1", cp)).isTrue();

        // A fresh checkpoint over the new head also verifies.
        assertThat(verifyCheckpoint("t1", checkpoint("t1"))).isTrue();
    }

    @Test
    @DisplayName("a validly-signed checkpoint whose anchored prefix has been rewritten is rejected")
    void rewrittenPrefixRejected() {
        record("t1", "token.issued", Map.of("sub", "alice"));
        record("t1", "token.issued", Map.of("sub", "bob"));
        AuditEntry head = chain("t1").get(1);

        // A checkpoint that points at the real head sequence but anchors a DIFFERENT
        // hash than the entry there — genuinely signed, so the signature check passes,
        // but the prefix no longer matches, so verification must fail.
        Instant now = Instant.parse("2026-01-01T00:00:00Z");
        String wrongHash = "ff".repeat(32);
        String input = AuditCheckpoint.signingInput(
                "t1", head.sequence(), wrongHash, now, signer.keyId());
        AuditCheckpoint divergent = new AuditCheckpoint(
                "t1", head.sequence(), wrongHash, now, signer.keyId(), signer.sign(input));

        assertThat(signer.verify(divergent.signingInput(), divergent.signature())).isTrue();
        assertThat(verifyCheckpoint("t1", divergent)).isFalse();
    }

    @Test
    @DisplayName("a checkpoint with a forged signature is rejected")
    void forgedCheckpointRejected() {
        record("t1", "token.issued", Map.of("sub", "alice"));
        AuditCheckpoint genuine = checkpoint("t1");
        AuditCheckpoint forged = new AuditCheckpoint(
                genuine.tenant(), genuine.headSequence(), genuine.headHash(),
                genuine.createdAt(), genuine.keyId(),
                // flip the signature to a syntactically valid but wrong hex value
                "00".repeat(64));
        assertThat(verifyCheckpoint("t1", forged)).isFalse();
    }

    @Test
    @DisplayName("known tenants are reported for the periodic checkpoint trigger")
    void tenantsReported() {
        record("t1", "e", Map.of());
        record("t2", "e", Map.of());
        assertThat(log.tenants().await().atMost(AWAIT)).containsExactlyInAnyOrder("t1", "t2");
    }
}
