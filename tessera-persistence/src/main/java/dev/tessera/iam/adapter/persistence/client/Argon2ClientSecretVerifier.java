package dev.tessera.iam.adapter.persistence.client;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import dev.tessera.iam.adapter.persistence.repository.OAuthClientRepository;
import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.WorkerExecutor;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import java.util.UUID;

/**
 * Persistence-backed {@link ClientSecretVerifierPort}: verifies a confidential client's
 * presented {@code client_secret} against the Argon2id PHC stored on {@code oauth_client}.
 *
 * <p>Argon2id is CPU- and memory-hard, so the check runs on a dedicated {@code argon2} worker
 * pool (never the reactive event loop, and never the shared worker pool — isolating the hashing
 * so a flood cannot starve other blocking work). The lookup is tenant-scoped through
 * {@link OAuthClientRepository} (RLS fail-closed). To avoid a client-existence timing oracle, the
 * reject path (unknown client, or a client with no stored secret) still runs one Argon2 check
 * against a fixed dummy hash before denying, so it costs the same order as a genuine secret
 * mismatch.
 *
 * <p>Like {@link DbClientRepositoryAdapter}, this plain {@code @ApplicationScoped} bean
 * replaces the fail-closed {@code @DefaultBean} fallback in the assembled server.
 */
@ApplicationScoped
public class Argon2ClientSecretVerifier implements ClientSecretVerifierPort {

    // OWASP Argon2id baseline (m=19 MiB, t=2, p=1) used only to mint the timing-equalizer
    // hash below. Real verification derives its parameters from the stored PHC string itself.
    private static final Argon2Function TIMING_ARGON2 =
            Argon2Function.getInstance(19456, 2, 1, 32, Argon2.ID);

    // Upper bounds on the cost parameters accepted from a stored PHC. A corrupt or hostile
    // registry row could otherwise encode an absurd memory cost (e.g. m=4 GiB) and OOM the
    // shared worker pool; anything above these OWASP-band ceilings is treated as malformed.
    private static final int MAX_MEMORY_KIB = 1 << 20; // 1 GiB
    private static final int MAX_ITERATIONS = 40;
    private static final int MAX_PARALLELISM = 16;

    // Init-on-demand holder: this valid-but-unmatchable PHC is (deliberately) expensive to
    // compute, so it is minted the first time the reject path references it — which happens
    // inside the off-event-loop worker supplier in check(), not in a static initializer that
    // would run the Argon2 pass on the caller (event-loop) thread on first use.
    private static final class TimingEqualizer {
        static final String PHC =
                Password.hash("tessera-timing-equalizer").with(TIMING_ARGON2).getResult();
    }

    @Inject
    OAuthClientRepository clients;

    @Inject
    @Named("argon2")
    WorkerExecutor argon2Executor;

    @Override
    public Uni<Boolean> verifySecret(RealmKey realm, ClientId clientId, String presentedSecret) {
        if (realm == null || clientId == null) {
            throw new IllegalArgumentException("realm and clientId must not be null");
        }
        UUID tenantId = realm.tenant().value();
        // The client lookup is a reactive DB read and must run (and commit) on the event loop.
        // Argon2 is CPU/memory-hard, so it runs on the dedicated argon2 worker via executeBlocking,
        // which completes back on the event-loop context — leaving the caller's pipeline on the
        // event loop. (emitOn/runSubscriptionOn would strand the downstream — and the next chained
        // DB call — on a worker thread, which Hibernate Reactive rejects with HR000068.)
        return clients.findById(tenantId, clientId.value())
                .map(entity -> entity == null ? null : entity.secretHash)
                .flatMap(storedHash ->
                        argon2Executor.executeBlocking(() -> check(storedHash, presentedSecret), false));
    }

    /**
     * Uniform-cost Argon2id verification. Returns {@code true} only when a stored secret
     * exists and matches the presented one; otherwise runs one dummy Argon2 check so the
     * reject path is not measurably faster than a real mismatch, then returns {@code false}.
     * Blocking — must be invoked off the event loop.
     */
    static boolean check(String storedHash, String presentedSecret) {
        if (presentedSecret == null || presentedSecret.isEmpty()
                || storedHash == null || storedHash.isBlank()) {
            // Uniform-cost reject: run one Argon2 pass against the dummy before denying.
            Password.check(presentedSecret == null ? "" : presentedSecret, TimingEqualizer.PHC)
                    .with(TIMING_ARGON2);
            return false;
        }
        try {
            // Argon2 parameters (m, t, p, salt) are read from the stored PHC string itself, so
            // verification uses exactly the cost the secret was hashed with — not a default.
            Argon2Function function = Argon2Function.getInstanceFromHash(storedHash);
            if (function.getMemory() > MAX_MEMORY_KIB
                    || function.getIterations() > MAX_ITERATIONS
                    || function.getParallelism() > MAX_PARALLELISM) {
                // Absurd cost parameters — corrupt or hostile registry row; fail closed.
                return false;
            }
            return Password.check(presentedSecret, storedHash).with(function);
        } catch (RuntimeException malformedStoredHash) {
            // A stored value that is not a valid Argon2id PHC is a registry data error, not a
            // usable credential — fail closed rather than surface it as a server error.
            return false;
        }
    }
}
