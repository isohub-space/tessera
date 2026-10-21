package dev.tessera.iam.application.port.out;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

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
     * The identity to verify against when the request names no confidential client of the realm
     * (an unknown {@code client_id}, another tenant's, or a public client): a name-based UUID
     * derived from the presented {@code client_id}. No client is registered under it
     * ({@link #isReserved}), so verifying against it costs one full, failing comparison, the same
     * as a wrong secret. Because it is one identity per presented id, a decorator that budgets
     * failures per {@code (tenant, client id)} treats an unknown id exactly like a real one.
     *
     * @param presentedClientId the {@code client_id} the request presented ({@code null} is "")
     * @return the sentinel identity for that id
     */
    static ClientId unknownClient(String presentedClientId) {
        String name = "tessera:unknown-client:" + (presentedClientId == null ? "" : presentedClientId);
        return new ClientId(UUID.nameUUIDFromBytes(name.getBytes(StandardCharsets.UTF_8)));
    }

    /**
     * Whether a client id is reserved for sentinels and can never be registered: the nil UUID and
     * every name-based (version 3) UUID. Registered clients have random (version 4) ids.
     *
     * @param id a candidate client id (never {@code null})
     * @return {@code true} when no client may be registered under it
     */
    static boolean isReserved(UUID id) {
        return id.equals(new UUID(0L, 0L)) || id.version() == 3;
    }

    /**
     * Verifies a presented client secret for a confidential client.
     *
     * @param realm           the realm the client belongs to (RLS-scoped)
     * @param clientId        the resolved client identity
     * @param presentedSecret the secret presented, {@code ""} when none was (never {@code null})
     * @return a {@link Uni} emitting {@code true} iff the secret matches the stored
     *         Argon2id credential; {@code false} otherwise (including unknown credential)
     */
    Uni<Boolean> verifySecret(RealmKey realm, ClientId clientId, String presentedSecret);
}
