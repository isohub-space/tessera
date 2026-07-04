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
 * brute-force lockout.
 *
 * <p><strong>Why a decorator, and why here.</strong> {@code verifySecret} already receives
 * {@code (realm, clientId)} — exactly the lockout key — so no new plumbing is needed, and wrapping
 * the port leaves the real verifier untouched. After {@code credential.max-failures} consecutive
 * wrong secrets the decorator short-circuits to {@code Uni(false)} <em>without calling the
 * delegate</em>; because the delegate is the CPU/memory-hard Argon2 pass, this is what relieves the
 * hashing pool under an invalid-credential flood (the batch-1 concurrency review's
 * DoS-amplification finding).
 *
 * <p><strong>Deliberate asymmetry: a lockout is not a 429.</strong> A {@code TokenService} collapses
 * a {@code false} here to {@code invalid_client} (401), and this decorator preserves that: it never
 * emits 429. A 429 on the credential path would itself be an oracle ("this {@code client_id} exists
 * and is under attack"); returning the same {@code invalid_client} as a wrong secret leaks nothing.
 *
 * <p>Enabled globally by its {@link Priority} (Quarkus/ArC honours {@code @Priority} on decorators —
 * no {@code beans.xml} needed). A no-op when {@code iam.ratelimit.enabled=false}.
 */
@Decorator
@Priority(Interceptor.Priority.APPLICATION)
public class LockoutClientSecretVerifier implements ClientSecretVerifierPort {

    /** Run the idle-eviction sweep once per this many verify calls. */
    private static final int SWEEP_INTERVAL = 1024;

    @Inject
    @Delegate
    ClientSecretVerifierPort delegate;

    @Inject
    RateLimitConfig config;

    private final ConcurrentMap<LockoutKey, BruteForceLockout> lockouts = new ConcurrentHashMap<>();
    private final AtomicLong callsSinceSweep = new AtomicLong();

    @Override
    public Uni<Boolean> verifySecret(RealmKey realm, ClientId clientId, String presentedSecret) {
        if (!config.enabled() || realm == null || clientId == null) {
            return delegate.verifySecret(realm, clientId, presentedSecret);
        }

        LockoutKey key = new LockoutKey(realm.tenant().value(), clientId.value());
        BruteForceLockout lockout = lockoutFor(key);
        if (lockout.isLockedOut()) {
            // Short-circuit: do NOT run Argon2. Collapses to invalid_client downstream, same as a
            // wrong secret — no 429, no client-existence oracle.
            return Uni.createFrom().item(Boolean.FALSE);
        }

        return delegate.verifySecret(realm, clientId, presentedSecret)
                .invoke(ok -> {
                    if (Boolean.TRUE.equals(ok)) {
                        lockout.reset();
                    } else {
                        lockout.recordFailure();
                    }
                });
    }

    private BruteForceLockout lockoutFor(LockoutKey key) {
        maybeSweep();
        return lockouts.computeIfAbsent(key, k -> new BruteForceLockout(
                config.credentialMaxFailures(),
                config.credentialLockout().toSeconds(),
                System::nanoTime));
    }

    private void maybeSweep() {
        if (callsSinceSweep.incrementAndGet() >= SWEEP_INTERVAL) {
            callsSinceSweep.set(0L);
            // Drop entries that carry no failures and no active lockout — recreating one is free.
            lockouts.values().removeIf(BruteForceLockout::isIdle);
        }
    }

    /** Composite lockout key: a lockout is scoped to one client within one tenant. */
    private record LockoutKey(UUID tenant, UUID clientId) {
    }
}
