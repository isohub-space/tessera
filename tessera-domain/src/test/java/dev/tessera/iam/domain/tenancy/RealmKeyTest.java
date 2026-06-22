package dev.tessera.iam.domain.tenancy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("RealmKey & tenancy ids — value invariants")
class RealmKeyTest {

    @Test
    @DisplayName("RealmKey rejects null tenant or baseline")
    void rejectsNullComponents() {
        assertThatThrownBy(() -> new RealmKey(null, BaselineId.generate()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RealmKey(TenantId.generate(), null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("TenantId / BaselineId reject null and are value-equal")
    void idsRejectNullAndAreValueEqual() {
        assertThatThrownBy(() -> new TenantId(null)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new BaselineId(null)).isInstanceOf(IllegalArgumentException.class);

        TenantId t = TenantId.generate();
        assertThat(new TenantId(t.value())).isEqualTo(t);
    }

    @Test
    @DisplayName("fromString round-trips the canonical UUID form")
    void fromStringRoundTrips() {
        TenantId t = TenantId.generate();
        assertThat(TenantId.fromString(t.value().toString())).isEqualTo(t);
    }
}
