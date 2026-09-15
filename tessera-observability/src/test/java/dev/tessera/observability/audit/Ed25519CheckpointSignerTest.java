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
        Ed25519CheckpointSigner signer = Ed25519CheckpointSigner.generate();
        String input = AuditCheckpoint.signingInput(
                "tenant-a", 7, "deadbeef", Instant.parse("2026-01-01T00:00:00Z"), "k1");

        String sig = signer.sign(input);
        assertThat(signer.verify(input, sig)).isTrue();
    }

    @Test
    @DisplayName("a tampered signing input fails verification")
    void tamperedInputRejected() {
        Ed25519CheckpointSigner signer = Ed25519CheckpointSigner.generate();
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
        Ed25519CheckpointSigner a = Ed25519CheckpointSigner.generate();
        Ed25519CheckpointSigner b = Ed25519CheckpointSigner.generate();
        String input = AuditCheckpoint.signingInput(
                "tenant-a", 1, "abc", Instant.parse("2026-01-01T00:00:00Z"), "k1");

        String sig = a.sign(input);
        assertThat(b.verify(input, sig)).isFalse();
    }

    @Test
    @DisplayName("the key id is derived from the key, so fresh material never reuses an id")
    void keyIdIsDerivedFromKeyMaterial() {
        // The core of the defect: a boot used to generate a new key pair and stamp a
        // CONFIGURED id on it, so one identity named different material after every
        // restart. Deriving the id makes that unrepresentable.
        Ed25519CheckpointSigner a = Ed25519CheckpointSigner.generate();
        Ed25519CheckpointSigner b = Ed25519CheckpointSigner.generate();

        assertThat(a.keyId()).isNotEqualTo(b.keyId());
        assertThat(a.keyId()).startsWith("ed25519-");
        assertThat(a.keyId()).isEqualTo(Ed25519CheckpointSigner.keyIdFor(a.publicKey()));
    }

    @Test
    @DisplayName("reloading the same key pair yields the same key id — the durable-custody path")
    void sameKeyPairYieldsSameKeyId() {
        // What a deployment with durable custody relies on: store the key pair, reload it
        // in the next process, and checkpoints signed by it still resolve to this id.
        // The signer never hands out its private key, so the "reload" is modelled the way
        // durable custody would actually do it: the key pair comes from storage, and two
        // signers built from it agree on the id and on each other's signatures.
        java.security.KeyPair pair;
        try {
            pair = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new AssertionError("Ed25519 must be available", e);
        }
        Ed25519CheckpointSigner original = Ed25519CheckpointSigner.of(pair);
        Ed25519CheckpointSigner reloaded = Ed25519CheckpointSigner.of(pair);

        assertThat(reloaded.keyId()).isEqualTo(original.keyId());

        String input = AuditCheckpoint.signingInput(
                "tenant-a", 3, "abc", Instant.parse("2026-01-01T00:00:00Z"), original.keyId());
        assertThat(reloaded.verify(input, original.sign(input))).isTrue();
    }

    @Test
    @DisplayName("a malformed (non-hex) signature is rejected rather than throwing")
    void malformedSignatureRejected() {
        Ed25519CheckpointSigner signer = Ed25519CheckpointSigner.generate();
        String input = AuditCheckpoint.signingInput(
                "tenant-a", 0, AuditEntry.GENESIS_HASH, Instant.parse("2026-01-01T00:00:00Z"), "k1");
        assertThat(signer.verify(input, "not-hex!!")).isFalse();
        assertThat(signer.verify(input, "abc")).isFalse(); // odd length
    }
}
