package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.Optional;

/**
 * Outbound port that verifies an end user's presented {@code username}/{@code password}
 * against the stored {@link dev.tessera.iam.domain.credential.PasswordHash} credential.
 *
 * <p>Mirrors {@link ClientSecretVerifierPort}'s shape and its two hard requirements: the
 * comparison is Argon2id (CPU/memory-hard) and so must run off the reactive event loop, and
 * an unknown username must cost the same as a wrong password (a uniform-cost reject) so the
 * login path is not a username-existence oracle. The raw password is passed only to this
 * port and is never stored or logged.
 */
public interface PasswordCredentialVerifierPort {

    /**
     * Verifies a presented username/password pair.
     *
     * @param realm    the realm the user belongs to (RLS-scoped)
     * @param username the presented login identifier (never {@code null})
     * @param password the presented plaintext password (never {@code null})
     * @return a {@link Uni} emitting the resolved {@code sub} iff the credential matches;
     *         {@link Optional#empty()} otherwise (including unknown username)
     */
    Uni<Optional<String>> verify(RealmKey realm, String username, String password);
}
