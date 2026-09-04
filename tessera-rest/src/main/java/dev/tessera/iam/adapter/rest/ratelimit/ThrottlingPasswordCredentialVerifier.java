package dev.tessera.iam.adapter.rest.ratelimit;

import dev.tessera.iam.application.port.out.PasswordCredentialVerifierPort;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.annotation.Priority;
import jakarta.decorator.Decorator;
import jakarta.decorator.Delegate;
import jakarta.inject.Inject;
import jakarta.interceptor.Interceptor;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * A CDI {@link Decorator} that wraps whichever {@link PasswordCredentialVerifierPort} is active
 * with a per-{@code (tenant, username)} failure-budget throttle — the login-path counterpart of
 * {@link ThrottlingClientSecretVerifier}, reusing the exact same mechanism (a {@link TokenBucket}
 * failure budget, {@link RateLimitConfig#credentialFailureBurst()} /
 * {@link RateLimitConfig#credentialRefillPerMinute()}, and {@link RateLimitMetrics#credentialThrottled})
 * rather than inventing a second one for IAM-49 AC7.
 *
 * <p>See {@link ThrottlingClientSecretVerifier}'s javadoc for the full rationale (throttle, not
 * lockout; uniform-cost short-circuit; residual risk of a client/username-keyed control) — it
 * applies here verbatim with "username" standing in for "client_id". A correct password never
 * spends budget; a wrong one does, and once a username's budget is spent, verification
 * short-circuits to {@code Uni(Optional.empty())} without running Argon2 — collapsing to the
 * same {@code invalid_credentials} outcome as a plain wrong password (no oracle, no 429).
 */
@Decorator
@Priority(Interceptor.Priority.APPLICATION)
public class ThrottlingPasswordCredentialVerifier implements PasswordCredentialVerifierPort {

    /** Run the idle-eviction sweep once per this many verify calls. */
    private static final int SWEEP_INTERVAL = 1024;

    @Inject
    @Delegate
    PasswordCredentialVerifierPort delegate;

    @Inject
    RateLimitConfig config;

    @Inject
    RateLimitMetrics metrics;

    private final ConcurrentMap<CredentialKey, TokenBucket> budgets = new ConcurrentHashMap<>();
    private final AtomicLong callsSinceSweep = new AtomicLong();

    @Override
    public Uni<Optional<String>> verify(RealmKey realm, String username, String password) {
        if (!config.enabled() || realm == null || username == null) {
            return delegate.verify(realm, username, password);
        }

        CredentialKey key = new CredentialKey(realm.tenant().value(), username);
        TokenBucket budget = budgetFor(key);
        if (!budget.hasToken()) {
            metrics.credentialThrottled(realm.tenant().value());
            return Uni.createFrom().item(Optional.empty());
        }

        return delegate.verify(realm, username, password)
                .invoke(result -> {
                    if (result.isEmpty()) {
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
            budgets.values().removeIf(TokenBucket::isFull);
        }
    }

    /** Composite key: a failure budget is scoped to one username within one tenant. */
    private record CredentialKey(UUID tenant, String username) {
    }
}
