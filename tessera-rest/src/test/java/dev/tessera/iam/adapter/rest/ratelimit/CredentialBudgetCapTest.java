package dev.tessera.iam.adapter.rest.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.smallrye.mutiny.Uni;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The credential throttle's budget table is bounded by {@code max-tracked-keys}. At the cap a new
 * key is verified without a budget, the same for a real client and an unknown id, and the event is
 * counted: memory stays bounded, the CPU cost stays bounded by Argon2 admission control, and
 * nothing tells a real client from an unknown one.
 */
@DisplayName("Credential throttle — a bounded budget table, the same at the cap for every id")
class CredentialBudgetCapTest {

    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());

    private final AtomicInteger delegateCalls = new AtomicInteger();
    private final AtomicInteger tableFull = new AtomicInteger();

    private ThrottlingClientSecretVerifier throttle(int maxTrackedKeys) {
        ThrottlingClientSecretVerifier throttle = new ThrottlingClientSecretVerifier();
        throttle.delegate = (realm, id, secret) -> {
            delegateCalls.incrementAndGet();
            return Uni.createFrom().item(Boolean.FALSE);
        };
        throttle.config = config(maxTrackedKeys);
        throttle.metrics = new NoOpRateLimitMetrics() {
            @Override
            public void credentialTableFull() {
                tableFull.incrementAndGet();
            }
        };
        return throttle;
    }

    /** Verifier calls made by each of {@code n} wrong-secret attempts for {@code id}. */
    private List<Integer> attempts(ThrottlingClientSecretVerifier throttle, ClientId id, int n) {
        List<Integer> calls = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            int before = delegateCalls.get();
            throttle.verifySecret(REALM, id, "wrong").await().indefinitely();
            calls.add(delegateCalls.get() - before);
        }
        return calls;
    }

    @Test
    @DisplayName("below the cap every id is budgeted: 1 1 1 then answered without the verifier")
    void belowTheCapEveryIdIsBudgeted() {
        ThrottlingClientSecretVerifier throttle = throttle(100);
        assertThat(attempts(throttle, new ClientId(UUID.randomUUID()), 5)).containsExactly(1, 1, 1, 0, 0);
        assertThat(tableFull.get()).isZero();
    }

    @Test
    @DisplayName("at the cap a new real or unknown id is verified unbudgeted and counted; tracked ids keep their budgets")
    void atTheCapNewIdsAreVerifiedUnbudgeted() {
        ThrottlingClientSecretVerifier throttle = throttle(2);
        ClientId first = new ClientId(UUID.randomUUID());
        ClientId second = new ClientId(UUID.randomUUID());
        // Two partly spent budgets fill the table; a sweep cannot drop them, as they are not full.
        attempts(throttle, first, 1);
        attempts(throttle, second, 1);

        ClientId realClient = new ClientId(UUID.randomUUID());
        ClientId unknownId = ClientSecretVerifierPort.unknownClient("no-such-client");
        assertThat(attempts(throttle, realClient, 5)).containsExactly(1, 1, 1, 1, 1);
        assertThat(attempts(throttle, unknownId, 5)).containsExactly(1, 1, 1, 1, 1);
        assertThat(tableFull.get()).isEqualTo(10);

        // The tracked ids are still throttled as before.
        assertThat(attempts(throttle, first, 3)).containsExactly(1, 1, 0);
    }

    private static RateLimitConfig config(int maxTrackedKeys) {
        return new RateLimitConfig() {
            @Override
            public boolean enabled() {
                return true;
            }

            @Override
            public int maxTrackedKeys() {
                return maxTrackedKeys;
            }

            @Override
            public int tokenCapacity() {
                return 100;
            }

            @Override
            public int tokenRefillPerMinute() {
                return 100;
            }

            @Override
            public int authorizeCapacity() {
                return 100;
            }

            @Override
            public int authorizeRefillPerMinute() {
                return 100;
            }

            @Override
            public int credentialFailureBurst() {
                return 3;
            }

            @Override
            public int credentialRefillPerMinute() {
                return 1;
            }
        };
    }
}
