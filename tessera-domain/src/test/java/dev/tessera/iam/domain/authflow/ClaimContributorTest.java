package dev.tessera.iam.domain.authflow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import dev.tessera.iam.domain.token.ClaimSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ClaimContributor — pure claim assembly over already-fetched data")
class ClaimContributorTest {

    private final ClaimContributor contributor = new ClaimContributor();
    private final RealmKey realm = new RealmKey(TenantId.generate(), BaselineId.generate());
    private final Subject subject = new Subject("sub-77", realm);

    @Test
    @DisplayName("stamps sub and roles from the context")
    void stampsSubAndRoles() {
        ClaimContext context = new ClaimContext(
                subject, realm, List.of("operator", "viewer"), Set.of());
        ClaimSet result = contributor.contribute(ClaimSet.empty(), context);

        assertThat(result.claim("sub")).contains("sub-77");
        assertThat(result.claim("roles")).contains(List.of("operator", "viewer"));
    }

    @Test
    @DisplayName("emits realm correlation claims only when 'profile' scope is granted")
    void realmClaimsScopeGated() {
        ClaimContext without = new ClaimContext(subject, realm, List.of(), Set.of("openid"));
        assertThat(contributor.contribute(ClaimSet.empty(), without).claim("realm_tenant")).isEmpty();

        ClaimContext with = new ClaimContext(subject, realm, List.of(), Set.of("openid", "profile"));
        ClaimSet result = contributor.contribute(ClaimSet.empty(), with);
        assertThat(result.claim("realm_tenant")).contains(realm.tenant().value().toString());
        assertThat(result.claim("realm_baseline")).contains(realm.baseline().value().toString());
    }

    @Test
    @DisplayName("merges onto pre-seeded claims without losing them")
    void mergesOntoExisting() {
        ClaimSet seeded = new ClaimSet(java.util.Map.of("iss", "https://auth.example.com"));
        ClaimContext context = new ClaimContext(subject, realm, List.of("a"), Set.of());
        ClaimSet result = contributor.contribute(seeded, context);

        assertThat(result.claim("iss")).contains("https://auth.example.com");
        assertThat(result.claim("sub")).contains("sub-77");
    }

    @Test
    @DisplayName("is deterministic — same inputs yield equal claim sets")
    void deterministic() {
        ClaimContext context = new ClaimContext(subject, realm, List.of("r1"), Set.of("profile"));
        ClaimSet a = contributor.contribute(ClaimSet.empty(), context);
        ClaimSet b = contributor.contribute(ClaimSet.empty(), context);
        assertThat(a).isEqualTo(b);
    }

    @Test
    @DisplayName("the resulting ClaimSet is immutable")
    void resultIsImmutable() {
        ClaimContext context = new ClaimContext(subject, realm, List.of("r1"), Set.of());
        ClaimSet result = contributor.contribute(ClaimSet.empty(), context);
        assertThatThrownBy(() -> result.claims().put("evil", "value"))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    @DisplayName("does not mutate the input claim set")
    void doesNotMutateInput() {
        ClaimSet seeded = ClaimSet.empty();
        ClaimContext context = new ClaimContext(subject, realm, List.of("r1"), Set.of());
        contributor.contribute(seeded, context);
        assertThat(seeded.claims()).isEmpty();
    }
}
