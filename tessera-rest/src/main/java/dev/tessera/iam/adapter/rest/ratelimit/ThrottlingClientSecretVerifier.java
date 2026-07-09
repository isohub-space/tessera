package dev.tessera.iam.adapter.rest.ratelimit;

import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.annotation.Priority;
import jakarta.decorator.Decorator;
import jakarta.decorator.Delegate;
import jakarta.inject.Inject;
import jakarta.interceptor.Interceptor;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A CDI {@link Decorator} that wraps whichever {@link ClientSecretVerifierPort} is active (the
 * Argon2id verifier in production, a fake in flow tests) with a per-{@code (tenant, client_id)}
 * <strong>failure-budget throttle</strong> on credential verification.
 *
 * <p><strong>Why a decorator, and why here.</strong> {@code verifySecret} already receives
 * {@code (realm, clientId)} — exactly the throttle key — so no new plumbing is needed, and wrapping
 * the port leaves the real verifier untouched. Each key owns a token bucket that models its
 * remaining <em>failure</em> allowance: a wrong secret spends one token, a correct secret spends
 * none. When the budget is exhausted the decorator short-circuits to {@code Uni(false)} <em>without
 * calling the delegate</em> — and because the delegate is the CPU/memory-hard Argon2 pass, that is
 * what caps the hashing rate for a client under an invalid-credential flood.
 *
 * <p><strong>Throttle, not lockout — deliberately.</strong> A fixed hard lockout keyed on the
 * public {@code client_id} would let anyone who can reach the credential path deny a legitimate
 * client (its correct secret included) for the whole lockout window — the account-lockout self-DoS
 * RFC 9700 warns against. A throttle instead: a correct secret never spends budget, and the budget
 * refills continuously, so denial of a valid credential is transient (bounded by the refill rate)
 * and self-heals rather than lasting a fixed window. <em>Residual risk:</em> because the key is a
 * public identifier and is not scoped to source, a caller who can repeatedly reach this path for a
 * given client (which requires an authenticated subject to mint each authorization code, and is
 * itself bounded by the ingress {@code /token} limiter) can keep that client's budget low and cause
 * transient throttling of it. This is inherent to any client-keyed credential control and is
 * accepted for the single-node tier.
 *
 * <p><strong>Not a 429.</strong> A {@code TokenService} collapses a {@code false} here to
 * {@code invalid_client} (401), and this decorator preserves that: it never emits 429. A 429 on the
 * credential path would itself be an oracle ("this {@code client_id} exists and is under attack");
 * returning the same {@code invalid_client} as a wrong secret leaks nothing.
 *
 * <p>Enabled globally by its {@link Priority} (Quarkus/ArC honours {@code @Priority} on decorators —
 * no {@code beans.xml} needed). A no-op when {@code iam.ratelimit.enabled=false}.
 */
@Decorator
@Priority(Interceptor.Priority.APPLICATION)
public class ThrottlingClientSecretVerifier implements ClientSecretVerifierPort {

    /** Run the idle-eviction sweep once per this many verify calls. */
    private static final int SWEEP_INTERVAL = 1024;

    @Inject
    @Delegate
    ClientSecretVerifierPort delegate;

    @Inject
    RateLimitConfig config;

    @Inject
    RateLimitMetrics metrics;

    private final ConcurrentMap<CredentialKey, TokenBucket> budgets = new ConcurrentHashMap<>();
    private final AtomicLong callsSinceSweep = new AtomicLong();

    @Override
    public Uni<Boolean> verifySecret(RealmKey realm, ClientId clientId, String presentedSecret) {
        if (!config.enabled() || realm == null || clientId == null) {
            return delegate.verifySecret(realm, clientId, presentedSecret);
        }

        CredentialKey key = new CredentialKey(realm.tenant().value(), clientId.value());
        TokenBucket budget = budgetFor(key);
        if (!budget.hasToken()) {
            // Failure allowance exhausted: short-circuit without running Argon2. Collapses to
            // invalid_client downstream, same as a wrong secret — no 429, no client-existence oracle.
            metrics.credentialThrottled(realm.tenant().value());
            return Uni.createFrom().item(Boolean.FALSE);
        }

        return delegate.verifySecret(realm, clientId, presentedSecret)
                .invoke(ok -> {
                    if (!Boolean.TRUE.equals(ok)) {
                        // A wrong secret spends one unit of the failure budget; a correct secret
                        // spends none, so legitimate traffic never throttles itself.
                        budget.tryAcquire();
                    }
                });
    }

    private TokenBucket budgetFor(CredentialKey key) {
        maybeSweep();
        return budgets.computeIfAbsent(key, k -> new TokenBucket(
                config.credentialFailureBurst(),
                config.credentialRefillPerMinute() / 60.0,
                System::nanoTime));
    }

    private void maybeSweep() {
        if (callsSinceSweep.incrementAndGet() >= SWEEP_INTERVAL) {
            callsSinceSweep.set(0L);
            // Drop full budgets — a full bucket has spent nothing and is recreated full on next use.
            budgets.values().removeIf(TokenBucket::isFull);
        }
    }

    /** Composite key: a failure budget is scoped to one client within one tenant. */
    private record CredentialKey(UUID tenant, UUID clientId) {
    }
}
