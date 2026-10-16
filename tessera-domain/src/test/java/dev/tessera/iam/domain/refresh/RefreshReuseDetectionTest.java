package dev.tessera.iam.domain.refresh;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RefreshReuseDetection — rotate / replay / unknown / expired classification (pure)")
class RefreshReuseDetectionTest {

    private static final Instant CREATED = Instant.parse("2026-01-01T00:00:00Z");
    private static final Instant NOW = Instant.parse("2026-01-01T00:10:00Z");
    private static final RealmKey REALM =
            new RealmKey(TenantId.generate(), BaselineId.generate());

    private RefreshTokenFamily family(
            String current, String previous, int generation, boolean reused, Instant expiresAt) {
        return new RefreshTokenFamily(
                new FamilyId(java.util.UUID.randomUUID()),
                REALM,
                "user-1",
                ClientId.generate(),
                current,
                previous,
                generation,
                reused,
                CREATED,
                expiresAt);
    }

    @Test
    @DisplayName("the current-token hash rotates the family forward")
    void currentHashRotates() {
        RefreshTokenFamily fam = family("cur", "prev", 3, false, null);
        RefreshDecision d = RefreshReuseDetection.classify(fam, "cur", NOW);
        assertThat(d).isInstanceOf(RefreshDecision.Rotate.class);
        assertThat(((RefreshDecision.Rotate) d).id()).isEqualTo(fam.id());
    }

    @Test
    @DisplayName("the previous-token hash is a replay → whole family revoked")
    void previousHashIsReplay() {
        RefreshTokenFamily fam = family("cur", "prev", 3, false, null);
        assertThat(RefreshReuseDetection.classify(fam, "prev", NOW))
                .isInstanceOf(RefreshDecision.Replay.class);
    }

    @Test
    @DisplayName("an already-reused (revoked) family classifies every presentation as replay")
    void reusedFamilyIsAlwaysReplay() {
        RefreshTokenFamily fam = family("cur", "prev", 3, true, null);
        // Even presenting the 'current' hash on a burned family is a replay.
        assertThat(RefreshReuseDetection.classify(fam, "cur", NOW))
                .isInstanceOf(RefreshDecision.Replay.class);
    }

    @Test
    @DisplayName("an expired family is Expired (checked before hash matching, but after the reuse burn)")
    void expiredFamily() {
        RefreshTokenFamily fam = family("cur", "prev", 3, false, CREATED.plusSeconds(60));
        assertThat(RefreshReuseDetection.classify(fam, "cur", NOW))
                .isInstanceOf(RefreshDecision.Expired.class);
    }

    @Test
    @DisplayName("a hash matching no generation is Unknown (no side effect)")
    void unknownHash() {
        RefreshTokenFamily fam = family("cur", "prev", 3, false, null);
        assertThat(RefreshReuseDetection.classify(fam, "stranger", NOW))
                .isInstanceOf(RefreshDecision.Unknown.class);
    }

    @Test
    @DisplayName("at generation 0 (no previous hash) a non-current hash is Unknown, not a replay")
    void generationZeroHasNoPrevious() {
        RefreshTokenFamily fam = family("cur", null, 0, false, null);
        assertThat(RefreshReuseDetection.classify(fam, "anything-else", NOW))
                .isInstanceOf(RefreshDecision.Unknown.class);
        assertThat(RefreshReuseDetection.classify(fam, "cur", NOW))
                .isInstanceOf(RefreshDecision.Rotate.class);
    }

    @Test
    @DisplayName("rejects null/blank arguments")
    void rejectsBadArgs() {
        RefreshTokenFamily fam = family("cur", "prev", 1, false, null);
        assertThatThrownBy(() -> RefreshReuseDetection.classify(null, "cur", NOW))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RefreshReuseDetection.classify(fam, " ", NOW))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> RefreshReuseDetection.classify(fam, "cur", null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private RefreshTokenFamily rotatedAt(Instant rotatedAt, boolean reused) {
        return new RefreshTokenFamily(
                new FamilyId(java.util.UUID.randomUUID()), REALM, "user-1", ClientId.generate(),
                "cur", "prev", 1, reused, CREATED, null, rotatedAt, "salt", java.util.Set.of());
    }

    @Test
    @DisplayName("the previous hash inside the reuse grace of the last rotation is a reissue")
    void previousHashWithinGraceIsReissue() {
        RefreshTokenFamily fam = rotatedAt(NOW.minusSeconds(2), false);
        assertThat(RefreshReuseDetection.classify(fam, "prev", NOW, Duration.ofSeconds(5)))
                .isInstanceOf(RefreshDecision.Reissue.class);
    }

    @Test
    @DisplayName("the previous hash after the grace, or with no grace, is still a replay")
    void previousHashOutsideGraceIsReplay() {
        RefreshTokenFamily fam = rotatedAt(NOW.minusSeconds(6), false);
        assertThat(RefreshReuseDetection.classify(fam, "prev", NOW, Duration.ofSeconds(5)))
                .isInstanceOf(RefreshDecision.Replay.class);
        RefreshTokenFamily recent = rotatedAt(NOW.minusSeconds(1), false);
        assertThat(RefreshReuseDetection.classify(recent, "prev", NOW, Duration.ZERO))
                .isInstanceOf(RefreshDecision.Replay.class);
        assertThat(RefreshReuseDetection.classify(recent, "prev", NOW))
                .as("the three-argument form has no grace").isInstanceOf(RefreshDecision.Replay.class);
    }

    @Test
    @DisplayName("a replay says whether it revokes the family or finds it already revoked")
    void replayReportsWhetherItBurns() {
        RefreshDecision first = RefreshReuseDetection.classify(
                rotatedAt(NOW.minusSeconds(60), false), "prev", NOW, Duration.ofSeconds(5));
        RefreshDecision again = RefreshReuseDetection.classify(
                rotatedAt(NOW.minusSeconds(60), true), "prev", NOW, Duration.ofSeconds(5));
        assertThat(first).isEqualTo(new RefreshDecision.Replay(((RefreshDecision.Replay) first).id(), true));
        assertThat(((RefreshDecision.Replay) again).burns()).isFalse();
    }

    @Test
    @DisplayName("the grace never revives a burned family, and needs a known rotation instant")
    void graceDoesNotReviveOrGuess() {
        assertThat(RefreshReuseDetection.classify(
                rotatedAt(NOW.minusSeconds(1), true), "prev", NOW, Duration.ofSeconds(5)))
                .isInstanceOf(RefreshDecision.Replay.class);
        assertThat(RefreshReuseDetection.classify(
                rotatedAt(null, false), "prev", NOW, Duration.ofSeconds(5)))
                .isInstanceOf(RefreshDecision.Replay.class);
        assertThatThrownBy(() -> RefreshReuseDetection.classify(
                rotatedAt(null, false), "prev", NOW, null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
