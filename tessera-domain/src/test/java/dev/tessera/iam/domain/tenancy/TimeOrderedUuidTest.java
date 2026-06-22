package dev.tessera.iam.domain.tenancy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("TimeOrderedUuid — RFC 9562 version 7 invariants")
class TimeOrderedUuidTest {

    @Test
    @DisplayName("stamps version 7 and the RFC variant")
    void carriesVersionAndVariant() {
        UUID uuid = TimeOrderedUuid.generate();
        assertThat(uuid.version()).isEqualTo(7);
        assertThat(uuid.variant()).isEqualTo(2); // IETF variant 0b10
    }

    @Test
    @DisplayName("is unique across many calls")
    void isUniqueAcrossManyCalls() {
        int count = 10_000;
        Set<UUID> seen = new HashSet<>(count * 2);
        for (int i = 0; i < count; i++) {
            seen.add(TimeOrderedUuid.generate());
        }
        assertThat(seen).hasSize(count);
    }

    @Test
    @DisplayName("embedded timestamps are non-decreasing across successive calls")
    void timestampsAreNonDecreasing() {
        long previous = Long.MIN_VALUE;
        for (int i = 0; i < 1_000; i++) {
            UUID uuid = TimeOrderedUuid.generate();
            long millis = uuid.getMostSignificantBits() >>> 16; // top 48 bits
            assertThat(millis).isGreaterThanOrEqualTo(previous);
            previous = millis;
        }
    }
}
