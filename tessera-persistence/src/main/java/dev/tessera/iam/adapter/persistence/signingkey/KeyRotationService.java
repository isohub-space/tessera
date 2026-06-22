package dev.tessera.iam.adapter.persistence.signingkey;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.persistence.crypto.Ed25519Keys;
import dev.tessera.iam.adapter.persistence.crypto.EnvelopeCipher;
import dev.tessera.iam.adapter.persistence.crypto.JwkJson;
import dev.tessera.iam.adapter.persistence.entity.SigningKeyEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.signingkey.KeyRotationPolicy;
import dev.tessera.iam.domain.signingkey.KeyUse;
import dev.tessera.iam.domain.signingkey.PublicJwk;
import dev.tessera.iam.domain.signingkey.SigningAlgorithm;
import dev.tessera.iam.domain.signingkey.SigningKeyState;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.KeyPair;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.hibernate.reactive.mutiny.Mutiny;

/**
 * Mints and promotes signing keys, driven by the pure {@link KeyRotationPolicy}.
 *
 * <p>Two operations make up a rotation:
 * <ul>
 *   <li>{@link #mintPending} — generate a fresh Ed25519 key pair, store the public JWK
 *       and the envelope-encrypted private key as a {@code PENDING} key. Minting a key
 *       PENDING publishes it (PENDING is publishable) <em>before</em> it ever signs —
 *       the publish-before-sign rule.</li>
 *   <li>{@link #promoteToActive} — promote a PENDING key to {@code ACTIVE}, first
 *       demoting any current ACTIVE key to {@code RETIRING}. Both moves are validated
 *       against {@link KeyRotationPolicy#isLegalTransition}, so an illegal jump can
 *       never be persisted.</li>
 * </ul>
 * All writes go through {@link TenantScopedSession} so row-level security binds them to
 * the realm's tenant.
 */
@ApplicationScoped
public class KeyRotationService {

    @Inject
    TenantScopedSession scoped;

    @Inject
    EnvelopeCipher envelopeCipher;

    @Inject
    SigningKeyConfig config;

    /**
     * Generates and persists a new {@code PENDING} signing key for the realm: a fresh
     * Ed25519 key pair whose public JWK is stored in cleartext and whose private key is
     * stored envelope-encrypted.
     *
     * @param realm the owning realm
     * @param kid   the key id to assign
     * @return a {@link Uni} emitting the published public JWK of the new key
     */
    public Uni<PublicJwk> mintPending(RealmKey realm, KeyId kid) {
        UUID tenantId = realm.tenant().value();
        KeyPair keyPair = Ed25519Keys.generate();
        PublicJwk publicJwk = Ed25519Keys.toPublicJwk(kid, KeyUse.SIGNATURE, keyPair.getPublic());
        EnvelopeCipher.Envelope envelope =
                envelopeCipher.seal(Ed25519Keys.encodePrivate(keyPair.getPrivate()));

        SigningKeyEntity entity = new SigningKeyEntity();
        entity.id = UUID.randomUUID();
        entity.tenantId = tenantId;
        entity.kid = kid.value();
        entity.algorithm = SigningAlgorithm.EdDSA.algIdentifier();
        entity.state = SigningKeyState.PENDING;
        entity.publicJwk = JwkJson.toJwk(publicJwk);
        entity.privateKeyEnc = envelope.ciphertext();
        entity.privateKeyNonce = envelope.nonce();
        entity.dekWrapped = envelope.wrappedDek();
        entity.keyUse = KeyUse.SIGNATURE.jwkValue();
        entity.issuer = config.issuer();
        entity.activatedAt = null;
        entity.createdAt = Instant.now();

        return scoped.inTenant(tenantId, session ->
                session.persist(entity).call(session::flush).replaceWith(publicJwk));
    }

    /**
     * Promotes the {@code PENDING} key {@code kid} to {@code ACTIVE}, demoting any
     * current {@code ACTIVE} key to {@code RETIRING} first. Every move is checked
     * against the pure policy before it is applied.
     *
     * @param realm the owning realm
     * @param kid   the PENDING key to activate
     * @param now   the activation instant (the clock is the caller's, not the policy's)
     * @return a {@link Uni} completing when the rotation is persisted
     */
    public Uni<Void> promoteToActive(RealmKey realm, KeyId kid, Instant now) {
        UUID tenantId = realm.tenant().value();
        return scoped.inTenant(tenantId, session ->
                allKeys(session).chain(keys -> {
                    SigningKeyEntity pending = require(keys, kid.value());
                    // Demote the current ACTIVE (if any) to RETIRING.
                    Uni<Void> demote = Uni.createFrom().voidItem();
                    for (SigningKeyEntity key : keys) {
                        if (key.state == SigningKeyState.ACTIVE) {
                            key.state = KeyRotationPolicy.transition(
                                    key.state, SigningKeyState.RETIRING);
                        }
                    }
                    // Promote the PENDING key to ACTIVE and stamp its activation instant.
                    pending.state = KeyRotationPolicy.transition(
                            pending.state, SigningKeyState.ACTIVE);
                    pending.activatedAt = now;
                    return demote.call(session::flush);
                }));
    }

    private Uni<List<SigningKeyEntity>> allKeys(Mutiny.Session session) {
        return session
                .createQuery("from SigningKeyEntity", SigningKeyEntity.class)
                .getResultList();
    }

    private static SigningKeyEntity require(List<SigningKeyEntity> keys, String kid) {
        return keys.stream()
                .filter(k -> k.kid.equals(kid))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No signing key with kid " + kid));
    }
}
