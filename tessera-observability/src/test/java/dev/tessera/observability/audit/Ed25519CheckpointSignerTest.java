package dev.tessera.observability.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Proves the checkpoint signature round-trips and that any change to the signed
 * content — or use of a different key — fails verification.
 */
@DisplayName("Ed25519CheckpointSigner — sign/verify round-trip")
class Ed25519CheckpointSignerTest {

    @Test
    @DisplayName("a signature produced by a signer verifies with the same signer")
    void roundTrip() {
        Ed25519CheckpointSigner signer = Ed25519CheckpointSigner.generate("k1");
        String input = AuditCheckpoint.signingInput(
                "tenant-a", 7, "deadbeef", Instant.parse("2026-01-01T00:00:00Z"), "k1");

        String sig = signer.sign(input);
        assertThat(signer.verify(input, sig)).isTrue();
    }

    @Test
    @DisplayName("a tampered signing input fails verification")
    void tamperedInputRejected() {
        Ed25519CheckpointSigner signer = Ed25519CheckpointSigner.generate("k1");
        String input = AuditCheckpoint.signingInput(
                "tenant-a", 7, "deadbeef", Instant.parse("2026-01-01T00:00:00Z"), "k1");
        String sig = signer.sign(input);

        String tampered = AuditCheckpoint.signingInput(
                "tenant-a", 8, "deadbeef", Instant.parse("2026-01-01T00:00:00Z"), "k1");
        assertThat(signer.verify(tampered, sig)).isFalse();
    }

    @Test
    @DisplayName("a signature from a different key does not verify")
    void wrongKeyRejected() {
        Ed25519CheckpointSigner a = Ed25519CheckpointSigner.generate("k1");
        Ed25519CheckpointSigner b = Ed25519CheckpointSigner.generate("k2");
        String input = AuditCheckpoint.signingInput(
                "tenant-a", 1, "abc", Instant.parse("2026-01-01T00:00:00Z"), "k1");

        String sig = a.sign(input);
        assertThat(b.verify(input, sig)).isFalse();
    }

    @Test
    @DisplayName("a malformed (non-hex) signature is rejected rather than throwing")
    void malformedSignatureRejected() {
        Ed25519CheckpointSigner signer = Ed25519CheckpointSigner.generate("k1");
        String input = AuditCheckpoint.signingInput(
                "tenant-a", 0, AuditEntry.GENESIS_HASH, Instant.parse("2026-01-01T00:00:00Z"), "k1");
        assertThat(signer.verify(input, "not-hex!!")).isFalse();
        assertThat(signer.verify(input, "abc")).isFalse(); // odd length
    }
}
