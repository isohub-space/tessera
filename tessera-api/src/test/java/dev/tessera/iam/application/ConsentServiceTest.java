package dev.tessera.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.out.ConsentStorePort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("ConsentService — records and checks per-(subject, client) consent")
class ConsentServiceTest {

    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());
    private static final ClientId CLIENT = ClientId.generate();

    private static final class InMemoryConsent implements ConsentStorePort {
        private final Map<String, Set<String>> granted = new HashMap<>();

        @Override
        public Uni<Boolean> hasConsent(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
            Set<String> existing = granted.get(key(subjectId, clientId));
            boolean covers = existing != null && existing.containsAll(scopes);
            return Uni.createFrom().item(covers);
        }

        @Override
        public Uni<Void> grant(RealmKey realm, String subjectId, ClientId clientId, Set<String> scopes) {
            granted.put(key(subjectId, clientId), Set.copyOf(scopes));
            return Uni.createFrom().voidItem();
        }

        private static String key(String subjectId, ClientId clientId) {
            return subjectId + "|" + clientId;
        }
    }

    @Test
    @DisplayName("no prior consent means hasConsented is false")
    void noPriorConsent() {
        ConsentService service = new ConsentService(new InMemoryConsent());

        boolean result = service.hasConsented(REALM, "sub-1", CLIENT, Set.of("openid"))
                .await().indefinitely();

        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("recording consent for a scope set makes hasConsented true for that set")
    void recordedConsentIsVisible() {
        ConsentService service = new ConsentService(new InMemoryConsent());

        service.recordConsent(REALM, "sub-1", CLIENT, Set.of("openid", "profile")).await().indefinitely();

        assertThat(service.hasConsented(REALM, "sub-1", CLIENT, Set.of("openid")).await().indefinitely())
                .isTrue();
    }

    @Test
    @DisplayName("a request for a scope beyond what was consented is not covered")
    void widerScopeNotCovered() {
        ConsentService service = new ConsentService(new InMemoryConsent());
        service.recordConsent(REALM, "sub-1", CLIENT, Set.of("openid")).await().indefinitely();

        boolean result = service.hasConsented(REALM, "sub-1", CLIENT, Set.of("openid", "email"))
                .await().indefinitely();

        assertThat(result).isFalse();
    }
}
