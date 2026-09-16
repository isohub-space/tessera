package dev.tessera.iam.launcher.health;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.adapter.persistence.DevTenant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The readiness tenant resolution order, tested without a container: explicit readiness
 * tenant, else the deployment's fixed tenant, else the development tenant.
 */
@DisplayName("SigningKeyReadinessCheck — which tenant the probe binds")
class SigningKeyReadinessTenantTest {

    private static final UUID EXPLICIT = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID FIXED = UUID.fromString("22222222-2222-4222-8222-222222222222");

    @Test
    @DisplayName("falls back to the development tenant when nothing is configured")
    void defaultsToDevTenant() {
        assertThat(SigningKeyReadinessCheck.readinessTenant(Optional.empty(), Optional.empty()))
                .isEqualTo(DevTenant.ID);
        assertThat(SigningKeyReadinessCheck.readinessTenant(Optional.of("  "), Optional.of("")))
                .isEqualTo(DevTenant.ID);
    }

    @Test
    @DisplayName("a single-tenant deployment probes its fixed tenant")
    void usesFixedTenant() {
        assertThat(SigningKeyReadinessCheck.readinessTenant(
                Optional.empty(), Optional.of(FIXED.toString()))).isEqualTo(FIXED);
    }

    @Test
    @DisplayName("an explicit readiness tenant wins over the fixed tenant")
    void explicitWins() {
        assertThat(SigningKeyReadinessCheck.readinessTenant(
                Optional.of(" " + EXPLICIT + " "), Optional.of(FIXED.toString()))).isEqualTo(EXPLICIT);
    }

    @Test
    @DisplayName("a non-UUID tenant fails fast instead of probing the wrong tenant")
    void rejectsMalformed() {
        assertThatThrownBy(() -> SigningKeyReadinessCheck.readinessTenant(
                Optional.of("not-a-uuid"), Optional.empty()))
                .isInstanceOf(IllegalStateException.class);
    }
}
