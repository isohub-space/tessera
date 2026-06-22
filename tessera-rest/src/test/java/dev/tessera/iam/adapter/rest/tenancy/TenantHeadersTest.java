package dev.tessera.iam.adapter.rest.tenancy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.adapter.rest.tenancy.TenantHeaders.MalformedTenantException;
import dev.tessera.iam.adapter.rest.tenancy.TenantHeaders.MissingTenantException;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The fail-closed tenant-header resolution rule, tested without a container.
 */
@DisplayName("TenantHeaders — fail-closed resolution of the ingress tenant headers")
class TenantHeadersTest {

    private static final UUID TENANT = UUID.fromString("11111111-1111-4111-8111-111111111111");
    private static final UUID BASELINE = UUID.fromString("22222222-2222-4222-8222-222222222222");
    private static final UUID ZERO = new UUID(0L, 0L);

    @Test
    @DisplayName("resolves tenant + baseline when both headers are present")
    void resolvesBoth() {
        RealmKey realm = TenantHeaders.resolve(TENANT.toString(), BASELINE.toString());
        assertThat(realm.tenant().value()).isEqualTo(TENANT);
        assertThat(realm.baseline().value()).isEqualTo(BASELINE);
    }

    @Test
    @DisplayName("defaults to the zero baseline when the baseline header is absent")
    void defaultsBaselineWhenAbsent() {
        RealmKey realm = TenantHeaders.resolve(TENANT.toString(), null);
        assertThat(realm.tenant().value()).isEqualTo(TENANT);
        assertThat(realm.baseline().value()).isEqualTo(ZERO);
    }

    @Test
    @DisplayName("defaults to the zero baseline when the baseline header is blank")
    void defaultsBaselineWhenBlank() {
        RealmKey realm = TenantHeaders.resolve(TENANT.toString(), "   ");
        assertThat(realm.baseline().value()).isEqualTo(ZERO);
    }

    @Test
    @DisplayName("trims surrounding whitespace before parsing")
    void trimsWhitespace() {
        RealmKey realm = TenantHeaders.resolve("  " + TENANT + "  ", null);
        assertThat(realm.tenant().value()).isEqualTo(TENANT);
    }

    @Test
    @DisplayName("fails closed when the tenant header is null")
    void failsClosedWhenTenantNull() {
        assertThatThrownBy(() -> TenantHeaders.resolve(null, null))
                .isInstanceOf(MissingTenantException.class);
    }

    @Test
    @DisplayName("fails closed when the tenant header is blank")
    void failsClosedWhenTenantBlank() {
        assertThatThrownBy(() -> TenantHeaders.resolve("  ", null))
                .isInstanceOf(MissingTenantException.class);
    }

    @Test
    @DisplayName("rejects a tenant header that is not a UUID")
    void rejectsMalformedTenant() {
        assertThatThrownBy(() -> TenantHeaders.resolve("not-a-uuid", null))
                .isInstanceOf(MalformedTenantException.class);
    }

    @Test
    @DisplayName("rejects a baseline header that is not a UUID")
    void rejectsMalformedBaseline() {
        assertThatThrownBy(() -> TenantHeaders.resolve(TENANT.toString(), "not-a-uuid"))
                .isInstanceOf(MalformedTenantException.class);
    }
}
