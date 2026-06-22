package dev.tessera.iam.application.port.out;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.signingkey.PublicJwk;
import dev.tessera.iam.domain.tenancy.RealmKey;
import java.util.List;

/**
 * Outbound port for token signing-key operations, modelled as <em>sign-as-operation</em>:
 * the private key never leaves the provider.
 *
 * <p>Callers never hold a private key. They ask the provider to <em>sign</em> a JWS
 * signing-input, or to publish the realm's public JWKS; the private key is loaded,
 * used and discarded entirely inside the implementing adapter. This keeps the trust
 * boundary tight regardless of how the key is stored.
 *
 * <h2>Backing store is an implementation detail</h2>
 * The contract is identical whichever way a key is protected:
 * <ul>
 *   <li>A <b>production</b> implementation backs onto a KMS or HSM — the private key
 *       is generated in, and never exported from, the hardware/managed boundary;
 *       {@code sign} is a remote operation against that boundary.</li>
 *   <li>A <b>development</b> implementation stores the private key in the database
 *       under envelope encryption (a per-key data key wrapped by a master key) and
 *       decrypts it in-process only for the duration of a {@code sign} call.</li>
 * </ul>
 * Either way the caller sees the same port: signing happens <em>inside</em> the
 * provider and the key bytes are never returned.
 */
public interface KeyProviderPort {

    /**
     * Signs a JWS signing-input with a realm's signing key, inside the provider. The
     * private key is never exposed to the caller.
     *
     * <p>The realm is required so the provider can resolve and load the key under the
     * correct tenant boundary (a fail-closed, tenant-scoped lookup); the {@code kid}
     * names which of that realm's keys to use — normally the current {@code ACTIVE}
     * key returned by {@link #currentSigningKey(RealmKey)}.
     *
     * @param realm        the realm whose key signs
     * @param keyId        the {@code kid} of the key to sign with
     * @param signingInput the bytes to sign (typically {@code base64url(header) + "." +
     *                     base64url(payload)})
     * @return a {@link Uni} emitting the {@link SignatureResult}
     */
    Uni<SignatureResult> sign(RealmKey realm, KeyId keyId, byte[] signingInput);

    /**
     * The realm's published public JWKS: every publishable key — the {@code PENDING},
     * {@code ACTIVE} and {@code RETIRING} public keys (only {@code RETIRED} is withdrawn).
     * A {@code PENDING} key is published <em>before</em> it is promoted to {@code ACTIVE}
     * and signs, so a verifier can pre-trust it (publish-before-sign); a {@code RETIRING}
     * key stays published so a token signed just before a rotation still verifies.
     *
     * @param realm the realm whose JWKS to publish
     * @return a {@link Uni} emitting the published public JWKs (never {@code null})
     */
    Uni<List<PublicJwk>> publishedJwks(RealmKey realm);

    /**
     * The realm's current signing key (the single {@code ACTIVE} key) — its {@code kid},
     * algorithm and public JWK. The caller uses it to build a JWS header before asking
     * {@link #sign(KeyId, byte[])} to sign; no private material is returned.
     *
     * @param realm the realm whose signing key to resolve
     * @return a {@link Uni} emitting the current {@link ActiveKey}
     */
    Uni<ActiveKey> currentSigningKey(RealmKey realm);
}
