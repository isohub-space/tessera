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

/**
 * A CDI {@link Decorator} that wraps whichever {@link PasswordCredentialVerifierPort} is active
 * with a per-{@code (tenant, username)} failure-budget throttle — the login-path counterpart of
 * {@link ThrottlingClientSecretVerifier}, reusing the exact same mechanism (a {@link TokenBucket}
 * failure budget, {@link RateLimitConfig#credentialFailureBurst()} /
 * {@link RateLimitConfig#credentialRefillPerMinute()}, and {@link RateLimitMetrics#credentialThrottled})
 * rather than inventing a second one.
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

    @Inject
    @Delegate
    PasswordCredentialVerifierPort delegate;

    @Inject
    RateLimitConfig config;

    @Inject
    RateLimitMetrics metrics;

    private final CredentialBudgets<CredentialKey> budgets = new CredentialBudgets<>();

    @Override
    public Uni<Optional<String>> verify(RealmKey realm, String username, String password) {
        if (!config.enabled() || realm == null || username == null) {
            return delegate.verify(realm, username, password);
        }

        CredentialKey key = new CredentialKey(realm.tenant().value(), username);
        TokenBucket budget = budgets.budgetFor(key, config);
        if (budget == null) {
            // The budget table is full: verify without a budget, as for any new username at the cap.
            metrics.credentialTableFull();
            return delegate.verify(realm, username, password);
        }
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

    /** Composite key: a failure budget is scoped to one username within one tenant. */
    private record CredentialKey(UUID tenant, String username) {
    }
}
