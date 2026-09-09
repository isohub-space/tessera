package dev.tessera.iam.adapter.persistence.credential;

import com.password4j.Argon2Function;
import com.password4j.Password;
import com.password4j.types.Argon2;
import dev.tessera.iam.adapter.persistence.entity.CredentialEntity;
import dev.tessera.iam.adapter.persistence.entity.CredentialKind;
import dev.tessera.iam.adapter.persistence.entity.UserEntity;
import dev.tessera.iam.adapter.persistence.repository.CredentialRepository;
import dev.tessera.iam.adapter.persistence.repository.UserRepository;
import dev.tessera.iam.application.port.out.PasswordCredentialVerifierPort;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.WorkerExecutor;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence-backed {@link PasswordCredentialVerifierPort}: verifies a presented
 * username/password against the end user's stored {@code PASSWORD_HASH} credential.
 *
 * <p>Deliberately mirrors {@link dev.tessera.iam.adapter.persistence.client.Argon2ClientSecretVerifier}
 * rather than sharing code with it: both do a tenant-scoped lookup followed by a uniform-cost
 * Argon2id check, but one keys on a client identity and the other on a username, and the two
 * are independent security-critical paths — duplicating the ~20 lines of verification logic
 * here keeps each file independently auditable and avoids coupling the client-secret and
 * user-password paths through a shared internal. The two properties both files enforce are the
 * same: Argon2id runs on the dedicated {@code argon2} worker pool (never the reactive event
 * loop or the shared Vert.x pool), and the reject path always costs one Argon2 pass — whether
 * the username is unknown, the credential is missing, or the password is simply wrong — so
 * this endpoint is not a username-existence oracle.
 */
@ApplicationScoped
public class Argon2PasswordCredentialVerifier implements PasswordCredentialVerifierPort {

    // OWASP Argon2id baseline (m=19 MiB, t=2, p=1), used only to mint the timing-equalizer
    // hash below. Real verification derives its parameters from the stored PHC string itself.
    private static final Argon2Function TIMING_ARGON2 =
            Argon2Function.getInstance(19456, 2, 1, 32, Argon2.ID);

    // Upper bounds on the cost parameters accepted from a stored PHC — guards against a
    // corrupt/hostile registry row encoding an absurd cost that would OOM the worker pool.
    private static final int MAX_MEMORY_KIB = 1 << 20; // 1 GiB
    private static final int MAX_ITERATIONS = 40;
    private static final int MAX_PARALLELISM = 16;

    // A fixed sentinel id: an unknown username still runs a (miss) credential lookup and the
    // full Argon2 pass below, so its timing matches a known username with a wrong password.
    private static final UUID NO_SUCH_USER = new UUID(0L, 0L);

    private static final class TimingEqualizer {
        static final String PHC =
                Password.hash("tessera-login-timing-equalizer").with(TIMING_ARGON2).getResult();
    }

    @Inject
    UserRepository users;

    @Inject
    CredentialRepository credentials;

    @Inject
    @Named("argon2")
    WorkerExecutor argon2Executor;

    @Override
    public Uni<Optional<String>> verify(RealmKey realm, String username, String password) {
        if (realm == null || username == null || password == null) {
            throw new IllegalArgumentException("realm, username and password must not be null");
        }
        UUID tenantId = realm.tenant().value();
        return users.findByUsername(tenantId, username)
                .flatMap(user -> credentials.findByUser(tenantId, userId(user))
                        .map(Argon2PasswordCredentialVerifier::storedHash)
                        .flatMap(storedHash -> argon2Executor.executeBlocking(
                                () -> check(storedHash, password), false))
                        .map(matched -> matched && user != null
                                ? Optional.of(user.subjectId)
                                : Optional.<String>empty()));
    }

    private static UUID userId(UserEntity user) {
        return user == null ? NO_SUCH_USER : user.id;
    }

    private static String storedHash(List<CredentialEntity> found) {
        return found.stream()
                .filter(c -> c.kind == CredentialKind.PASSWORD_HASH)
                .map(c -> new String(c.material, StandardCharsets.UTF_8))
                .findFirst()
                .orElse(null);
    }

    /**
     * Uniform-cost Argon2id verification, mirroring
     * {@link dev.tessera.iam.adapter.persistence.client.Argon2ClientSecretVerifier#check}.
     * Blocking — must be invoked off the event loop.
     */
    static boolean check(String storedHash, String presentedPassword) {
        if (presentedPassword.isEmpty() || storedHash == null || storedHash.isBlank()) {
            // Uniform-cost reject: run one Argon2 pass against the dummy before denying.
            Password.check(presentedPassword, TimingEqualizer.PHC).with(TIMING_ARGON2);
            return false;
        }
        try {
            // Argon2 parameters are read from the stored PHC string itself, so verification
            // uses exactly the cost the password was hashed with — not a default.
            Argon2Function function = Argon2Function.getInstanceFromHash(storedHash);
            if (function.getMemory() > MAX_MEMORY_KIB
                    || function.getIterations() > MAX_ITERATIONS
                    || function.getParallelism() > MAX_PARALLELISM) {
                // Absurd cost parameters — corrupt or hostile registry row; fail closed.
                return false;
            }
            return Password.check(presentedPassword, storedHash).with(function);
        } catch (RuntimeException malformedStoredHash) {
            // A stored value that is not a valid Argon2id PHC is a registry data error, not a
            // usable credential — fail closed rather than surface it as a server error.
            return false;
        }
    }
}
