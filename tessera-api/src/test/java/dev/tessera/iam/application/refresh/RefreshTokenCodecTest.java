package dev.tessera.iam.application.refresh;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.domain.refresh.FamilyId;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RefreshTokenCodec — wire format round-trip, malformed rejection, stable hash")
class RefreshTokenCodecTest {

    @Test
    @DisplayName("assemble then parse round-trips the family id and secret")
    void roundTrip() {
        FamilyId id = new FamilyId(UUID.randomUUID());
        String wire = RefreshTokenCodec.assemble(id, "sekret-value");
        Optional<RefreshTokenCodec.Parsed> parsed = RefreshTokenCodec.parse(wire);
        assertThat(parsed).isPresent();
        assertThat(parsed.get().id()).isEqualTo(id);
        assertThat(parsed.get().secret()).isEqualTo("sekret-value");
    }

    @Test
    @DisplayName("malformed tokens parse to empty, never throw")
    void malformedIsEmpty() {
        assertThat(RefreshTokenCodec.parse(null)).isEmpty();
        assertThat(RefreshTokenCodec.parse("")).isEmpty();
        assertThat(RefreshTokenCodec.parse("no-dot-here")).isEmpty();
        assertThat(RefreshTokenCodec.parse(".secretonly")).isEmpty();
        assertThat(RefreshTokenCodec.parse("familyonly.")).isEmpty();
        assertThat(RefreshTokenCodec.parse("not!base64.secret")).isEmpty();
        // A valid base64url prefix that is not 16 bytes is rejected.
        assertThat(RefreshTokenCodec.parse("dG9vLXNob3J0.secret")).isEmpty();
    }

    @Test
    @DisplayName("sha256 is deterministic and secret-sensitive; only the secret is hashed")
    void hashIsStable() {
        assertThat(RefreshTokenCodec.sha256("abc")).isEqualTo(RefreshTokenCodec.sha256("abc"));
        assertThat(RefreshTokenCodec.sha256("abc")).isNotEqualTo(RefreshTokenCodec.sha256("abd"));
        // The family id is not part of the hash: two tokens with the same secret hash equally.
        FamilyId a = new FamilyId(UUID.randomUUID());
        FamilyId b = new FamilyId(UUID.randomUUID());
        String secret = "shared-secret";
        assertThat(RefreshTokenCodec.parse(RefreshTokenCodec.assemble(a, secret)).get().secret())
                .isEqualTo(RefreshTokenCodec.parse(RefreshTokenCodec.assemble(b, secret)).get().secret());
    }
}
