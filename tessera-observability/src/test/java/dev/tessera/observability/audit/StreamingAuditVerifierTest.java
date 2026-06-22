package dev.tessera.observability.audit;

import static org.assertj.core.api.Assertions.assertThat;

import io.smallrye.mutiny.Multi;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the streaming, O(1)-memory verification folds the pure per-entry step over a
 * reactive stream and reaches the same verdict as the list-based fold — including the
 * tamper cases — without ever collecting the chain.
 */
@DisplayName("StreamingAuditVerifier — O(1) streaming chain verification")
class StreamingAuditVerifierTest {

    private static final Duration AWAIT = Duration.ofSeconds(5);
    private static final String TENANT = "tenant-a";
    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

    private static List<AuditEntry> buildChain(int n) {
        List<AuditEntry> chain = new ArrayList<>();
        AuditEntry e = AuditEntry.genesis(TENANT, "token.issued", T0, Map.of("sub", "alice"));
        chain.add(e);
        for (int i = 1; i < n; i++) {
            e = AuditEntry.append(e, "token.issued", T0.plusSeconds(i), Map.of("sub", "user-" + i));
            chain.add(e);
        }
        return chain;
    }

    private static AuditChain.Verification verifyStream(List<AuditEntry> entries) {
        return StreamingAuditVerifier.verify(Multi.createFrom().iterable(entries)).await().atMost(AWAIT);
    }

    @Test
    @DisplayName("an empty stream is trivially valid")
    void emptyStreamValid() {
        assertThat(verifyStream(List.of()).valid()).isTrue();
    }

    @Test
    @DisplayName("a well-formed streamed chain verifies")
    void wellFormedStreamVerifies() {
        AuditChain.Verification v = verifyStream(buildChain(50));
        assertThat(v.valid()).isTrue();
        assertThat(v.brokenAt()).isEqualTo(-1);
    }

    @Test
    @DisplayName("streaming and list verification agree on a tampered chain, pinpointing the break")
    void streamMatchesListOnTamper() {
        List<AuditEntry> chain = buildChain(6);
        AuditEntry victim = chain.get(3);
        AuditEntry forged = new AuditEntry(
                victim.sequence(), victim.tenant(), victim.eventType(), victim.timestamp(),
                Map.of("sub", "mallory"), victim.previousHash(), victim.hash());
        chain.set(3, forged);

        AuditChain.Verification streamed = verifyStream(chain);
        AuditChain.Verification listed = AuditChain.verify(chain);
        assertThat(streamed.valid()).isFalse();
        assertThat(streamed.brokenAt()).isEqualTo(3);
        assertThat(streamed.reason()).contains("tampered content");
        // The streaming fold reaches exactly the list-based verdict.
        assertThat(streamed).isEqualTo(listed);
    }

    @Test
    @DisplayName("a deletion (sequence gap) is detected at the gap")
    void deletionDetected() {
        List<AuditEntry> chain = buildChain(6);
        chain.remove(2); // sequences now 0,1,3,4,5 — gap at index 2
        AuditChain.Verification v = verifyStream(chain);
        assertThat(v.valid()).isFalse();
        assertThat(v.brokenAt()).isEqualTo(2);
        assertThat(v.reason()).contains("sequence");
    }

    @Test
    @DisplayName("the pure verifyNext step short-circuits: once broken it passes through")
    void verifyNextShortCircuits() {
        // Drive the pure step directly: a broken state ignores further entries.
        AuditChain.State broken = AuditChain.verifyNext(
                AuditChain.State.initial(),
                // an entry claiming sequence 5 when 0 is expected → broken
                AuditEntry.appendAfter(4, TENANT, "ab".repeat(32), "e", T0, Map.of()));
        assertThat(broken.ongoing()).isFalse();
        AuditChain.State afterMore = AuditChain.verifyNext(broken,
                AuditEntry.genesis(TENANT, "e", T0, Map.of()));
        // Verdict unchanged — still the first failure.
        assertThat(afterMore.result()).isEqualTo(broken.result());
    }
}
