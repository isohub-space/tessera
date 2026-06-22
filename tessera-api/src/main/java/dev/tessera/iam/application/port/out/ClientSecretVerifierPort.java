package dev.tessera.iam.application.port.out;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;

/**
 * Outbound port that verifies a confidential client's presented secret against its
 * stored credential.
 *
 * <p>The verification is a deliberately expensive Argon2id comparison (the secret is
 * stored as an Argon2id PHC string, never in plaintext). Because Argon2id is CPU- and
 * memory-hard, the implementing adapter <strong>must</strong> run it off the reactive
 * event loop (a worker thread / {@code executeBlocking}); the port returns a
 * {@link Uni} so the caller never blocks. The raw secret is passed only to this port
 * and never stored or logged.
 */
public interface ClientSecretVerifierPort {

    /**
     * Verifies a presented client secret for a confidential client.
     *
     * @param realm           the realm the client belongs to (RLS-scoped)
     * @param clientId        the resolved client identity
     * @param presentedSecret the secret presented at the token endpoint (never {@code null})
     * @return a {@link Uni} emitting {@code true} iff the secret matches the stored
     *         Argon2id credential; {@code false} otherwise (including unknown credential)
     */
    Uni<Boolean> verifySecret(RealmKey realm, ClientId clientId, String presentedSecret);
}
