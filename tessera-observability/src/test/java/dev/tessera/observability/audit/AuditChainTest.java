package dev.tessera.observability.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Proves the hash-chain invariants: a well-formed chain verifies, and every form
 * of tampering (content edit, reorder, deletion, insertion, link splice) breaks
 * verification at the offending entry.
 */
@DisplayName("AuditChain — continuity & tamper detection")
class AuditChainTest {

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

    @Test
    @DisplayName("an empty chain is trivially valid")
    void emptyChainValid() {
        assertThat(AuditChain.verify(List.of()).valid()).isTrue();
    }

    @Test
    @DisplayName("a freshly built chain verifies and its links are continuous")
    void wellFormedChainVerifies() {
        AuditChain.Verification v = AuditChain.verify(buildChain(5));
        assertThat(v.valid()).isTrue();
        assertThat(v.brokenAt()).isEqualTo(-1);
    }

    @Test
    @DisplayName("genesis previousHash is the all-zero digest and each link chains over the prior hash")
    void linksChainOverPriorHash() {
        List<AuditEntry> chain = buildChain(4);
        assertThat(chain.get(0).previousHash()).isEqualTo(AuditEntry.GENESIS_HASH);
        for (int i = 1; i < chain.size(); i++) {
            assertThat(chain.get(i).previousHash()).isEqualTo(chain.get(i - 1).hash());
        }
    }

    @Nested
    @DisplayName("tampering breaks verification")
    class Tampering {

        @Test
        @DisplayName("editing an entry's attribute breaks it at that entry")
        void contentEditDetected() {
            List<AuditEntry> chain = buildChain(5);
            AuditEntry victim = chain.get(2);
            // Forge an entry with mutated content but the original (now stale) stored hash.
            AuditEntry forged = new AuditEntry(
                    victim.sequence(), victim.tenant(), victim.eventType(), victim.timestamp(),
                    Map.of("sub", "mallory"), victim.previousHash(), victim.hash());
            chain.set(2, forged);

            AuditChain.Verification v = AuditChain.verify(chain);
            assertThat(v.valid()).isFalse();
            assertThat(v.brokenAt()).isEqualTo(2);
            assertThat(v.reason()).contains("tampered content");
        }

        @Test
        @DisplayName("deleting an entry breaks the link at the gap")
        void deletionDetected() {
            List<AuditEntry> chain = buildChain(5);
            chain.remove(2); // sequences now 0,1,3,4 — gap at index 2

            AuditChain.Verification v = AuditChain.verify(chain);
            assertThat(v.valid()).isFalse();
            assertThat(v.brokenAt()).isEqualTo(2);
            assertThat(v.reason()).contains("sequence");
        }

        @Test
        @DisplayName("reordering two entries breaks verification")
        void reorderDetected() {
            List<AuditEntry> chain = buildChain(5);
            AuditEntry a = chain.get(1);
            AuditEntry b = chain.get(2);
            chain.set(1, b);
            chain.set(2, a);

            assertThat(AuditChain.verify(chain).valid()).isFalse();
        }

        @Test
        @DisplayName("inserting a foreign entry breaks the chain")
        void insertionDetected() {
            List<AuditEntry> chain = buildChain(4);
            AuditEntry injected = AuditEntry.genesis(TENANT, "token.forged", T0, Map.of("x", "y"));
            chain.add(2, injected);

            AuditChain.Verification v = AuditChain.verify(chain);
            assertThat(v.valid()).isFalse();
            assertThat(v.brokenAt()).isEqualTo(2);
        }

        @Test
        @DisplayName("splicing a mismatched previousHash breaks the link")
        void brokenLinkDetected() {
            List<AuditEntry> chain = buildChain(4);
            AuditEntry victim = chain.get(2);
            AuditEntry forged = new AuditEntry(
                    victim.sequence(), victim.tenant(), victim.eventType(), victim.timestamp(),
                    victim.attributes(), AuditEntry.GENESIS_HASH, victim.hash());
            chain.set(2, forged);

            AuditChain.Verification v = AuditChain.verify(chain);
            assertThat(v.valid()).isFalse();
            assertThat(v.brokenAt()).isEqualTo(2);
        }
    }

    @Test
    @DisplayName("headHash returns genesis for empty and the last hash otherwise")
    void headHash() {
        assertThat(AuditChain.headHash(List.of())).isEqualTo(AuditEntry.GENESIS_HASH);
        List<AuditEntry> chain = buildChain(3);
        assertThat(AuditChain.headHash(chain)).isEqualTo(chain.get(2).hash());
    }

    @Test
    @DisplayName("the same content always hashes the same, regardless of attribute insertion order")
    void hashIsDeterministicAndOrderIndependent() {
        var ordered = new java.util.LinkedHashMap<String, String>();
        ordered.put("a", "1");
        ordered.put("b", "2");
        var reversed = new java.util.LinkedHashMap<String, String>();
        reversed.put("b", "2");
        reversed.put("a", "1");

        AuditEntry e1 = AuditEntry.genesis(TENANT, "evt", T0, ordered);
        AuditEntry e2 = AuditEntry.genesis(TENANT, "evt", T0, reversed);
        assertThat(e1.hash()).isEqualTo(e2.hash());
    }
}
