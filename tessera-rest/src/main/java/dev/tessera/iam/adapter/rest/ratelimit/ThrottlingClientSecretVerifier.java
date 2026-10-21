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
 * <p><strong>Unknown ids are budgeted like real ones.</strong> A request that names no
 * confidential client is verified against {@link ClientSecretVerifierPort#unknownClient}, one
 * sentinel per presented {@code client_id}, so it gets its own budget here exactly as a real client
 * does. Known and unknown ids therefore run dry after the same number of failures and answer the
 * same way afterwards: neither the timing nor the throttle tells whether a {@code client_id}
 * exists.
 *
 * <p><strong>A bounded table.</strong> The budgets live in a {@link CredentialBudgets} table capped
 * at {@code max-tracked-keys}; at the cap a new key is verified without a budget and counted
 * ({@link RateLimitMetrics#credentialTableFull()}), the same for a real and an unknown id.
 *
 * <p><strong>Throttle, not lockout — deliberately.</strong> A fixed hard lockout keyed on the
 * public {@code client_id} would let anyone who can reach the credential path deny a legitimate
 * client (its correct secret included) for the whole lockout window — the account-lockout self-DoS
 * RFC 9700 warns against. A throttle instead: a correct secret never spends budget, and the budget
 * refills continuously, so denial of a valid credential is transient (bounded by the refill rate)
 * and self-heals rather than lasting a fixed window. <em>Residual risk:</em> the key is a public
 * identifier and is not scoped to the caller, so anyone who knows a client's {@code client_id} can
 * keep its budget empty with a steady trickle of wrong secrets. No authenticated subject is needed:
 * the {@code client_credentials} grant, {@code /introspect} and {@code /revoke} take a client
 * credential directly. While the budget is empty even the client's correct secret is refused, so a
 * machine client can be kept out for as long as the attacker keeps sending. This is inherent to a
 * shared secret checked by a client-keyed control; the durable answer for machine clients is
 * keyless client authentication ({@code private_key_jwt} or {@code tls_client_auth}), where no
 * guessable secret exists to spend the budget on.
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

    @Inject
    @Delegate
    ClientSecretVerifierPort delegate;

    @Inject
    RateLimitConfig config;

    @Inject
    RateLimitMetrics metrics;

    private final CredentialBudgets<CredentialKey> budgets = new CredentialBudgets<>();

    @Override
    public Uni<Boolean> verifySecret(RealmKey realm, ClientId clientId, String presentedSecret) {
        if (!config.enabled() || realm == null || clientId == null) {
            return delegate.verifySecret(realm, clientId, presentedSecret);
        }

        CredentialKey key = new CredentialKey(realm.tenant().value(), clientId.value());
        TokenBucket budget = budgets.budgetFor(key, config);
        if (budget == null) {
            // The budget table is full: verify without a budget, as for any new key at the cap.
            metrics.credentialTableFull();
            return delegate.verifySecret(realm, clientId, presentedSecret);
        }
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

    /** Composite key: a failure budget is scoped to one client within one tenant. */
    private record CredentialKey(UUID tenant, UUID clientId) {
    }
}
