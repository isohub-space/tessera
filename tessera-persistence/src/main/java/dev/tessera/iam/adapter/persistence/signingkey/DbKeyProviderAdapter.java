package dev.tessera.iam.adapter.persistence.signingkey;

import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.persistence.crypto.Ed25519Keys;
import dev.tessera.iam.adapter.persistence.crypto.EnvelopeCipher;
import dev.tessera.iam.adapter.persistence.entity.SigningKeyEntity;
import dev.tessera.iam.adapter.persistence.rls.TenantScopedSession;
import dev.tessera.iam.application.port.out.ActiveKey;
import dev.tessera.iam.application.port.out.KeyProviderPort;
import dev.tessera.iam.application.port.out.SignatureResult;
import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.signingkey.KeyRotationPolicy;
import dev.tessera.iam.domain.signingkey.KeyUse;
import dev.tessera.iam.domain.signingkey.PublicJwk;
import dev.tessera.iam.domain.signingkey.SigningAlgorithm;
import dev.tessera.iam.domain.signingkey.SigningKeyDescriptor;
import dev.tessera.iam.domain.signingkey.SigningKeyState;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.security.PrivateKey;
import java.util.List;
import java.util.UUID;
import org.hibernate.reactive.mutiny.Mutiny;

/**
 * Development DB-backed {@link KeyProviderPort}: a signing-key provider whose private
 * keys are stored in the database under envelope encryption.
 *
 * <p>This is the development half of the KMS/HSM-vs-DB split documented on the port.
 * The contract is identical to a production KMS/HSM-backed provider: signing happens
 * <em>inside</em> the adapter — the private key is loaded, envelope-decrypted, used to
 * produce an Ed25519 signature, and then discarded; it never crosses the port. All
 * database access flows through {@link TenantScopedSession} so row-level security
 * scopes every read and write to the realm's tenant (fail-closed).
 *
 * <p>To move to a real KMS, replace the {@link EnvelopeCipher} wrap/unwrap step (the
 * documented seam in that class) with KMS {@code Encrypt}/{@code Decrypt} of the data
 * key and have {@code sign} delegate to the KMS — no caller changes.
 */
@ApplicationScoped
public class DbKeyProviderAdapter implements KeyProviderPort {

    @Inject
    TenantScopedSession scoped;

    @Inject
    EnvelopeCipher envelopeCipher;

    @Override
    public Uni<SignatureResult> sign(RealmKey realm, KeyId keyId, byte[] signingInput) {
        byte[] input = signingInput.clone();
        UUID tenantId = realm.tenant().value();
        // Tenant-scoped (RLS) lookup of the key by kid, then decrypt the private key and
        // sign — the key bytes are loaded, used and discarded entirely inside the adapter.
        return scoped.inTenant(tenantId, session ->
                loadByKid(session, keyId).map(entity -> {
                    PrivateKey privateKey = recoverPrivateKey(entity);
                    byte[] signature = Ed25519Keys.sign(privateKey, input);
                    return new SignatureResult(keyId, SigningAlgorithm.EdDSA, signature);
                }));
    }

    @Override
    public Uni<List<PublicJwk>> publishedJwks(RealmKey realm) {
        UUID tenantId = realm.tenant().value();
        return scoped.inTenant(tenantId, session ->
                publishedKeys(session).map(KeyRotationPolicy::publishedJwks));
    }

    @Override
    public Uni<ActiveKey> currentSigningKey(RealmKey realm) {
        UUID tenantId = realm.tenant().value();
        return scoped.inTenant(tenantId, session ->
                allKeys(session).map(descriptors -> {
                    SigningKeyDescriptor current = KeyRotationPolicy.currentSigningKey(descriptors)
                            .orElseThrow(() -> new IllegalStateException(
                                    "No ACTIVE signing key for realm " + tenantId));
                    return new ActiveKey(current.keyId(), current.algorithm(), current.publicJwk());
                }));
    }

    // ------------------------------------------------------------------ mapping

    private Uni<List<SigningKeyDescriptor>> allKeys(Mutiny.Session session) {
        return session
                .createQuery("from SigningKeyEntity", SigningKeyEntity.class)
                .getResultList()
                .map(rows -> rows.stream().map(DbKeyProviderAdapter::toDescriptor).toList());
    }

    private Uni<List<SigningKeyDescriptor>> publishedKeys(Mutiny.Session session) {
        // PENDING, ACTIVE and RETIRING keys are published; only RETIRED is withdrawn.
        // PENDING keys are pre-published so a verifier can pre-trust a key before it is
        // promoted to ACTIVE and signs (publish-before-sign). KeyRotationPolicy is the
        // source of truth (isPublishable); this query excludes only RETIRED.
        return session
                .createQuery(
                        "from SigningKeyEntity k where k.state in (:pending, :active, :retiring)",
                        SigningKeyEntity.class)
                .setParameter("pending", SigningKeyState.PENDING)
                .setParameter("active", SigningKeyState.ACTIVE)
                .setParameter("retiring", SigningKeyState.RETIRING)
                .getResultList()
                .map(rows -> rows.stream().map(DbKeyProviderAdapter::toDescriptor).toList());
    }

    private Uni<SigningKeyEntity> loadByKid(Mutiny.Session session, KeyId keyId) {
        return session
                .createQuery("from SigningKeyEntity k where k.kid = :kid", SigningKeyEntity.class)
                .setParameter("kid", keyId.value())
                .getSingleResult();
    }

    private PrivateKey recoverPrivateKey(SigningKeyEntity entity) {
        EnvelopeCipher.Envelope envelope = new EnvelopeCipher.Envelope(
                entity.privateKeyEnc, entity.privateKeyNonce, entity.dekWrapped);
        byte[] pkcs8 = envelopeCipher.open(envelope);
        return Ed25519Keys.decodePrivate(pkcs8);
    }

    private static SigningKeyDescriptor toDescriptor(SigningKeyEntity entity) {
        PublicJwk publicJwk = parsePublicJwk(entity);
        return new SigningKeyDescriptor(
                KeyId.of(entity.kid), publicJwk, entity.state, entity.activatedAt);
    }

    /**
     * Rebuilds the {@link PublicJwk} domain value from the entity's stored {@code x}
     * coordinate and metadata. The persisted {@code public_jwk} JSON keeps the wire
     * form; the domain value is reconstructed from the columns that drive selection.
     */
    private static PublicJwk parsePublicJwk(SigningKeyEntity entity) {
        KeyUse use = "enc".equals(entity.keyUse) ? KeyUse.ENCRYPTION : KeyUse.SIGNATURE;
        String x = extractJsonString(entity.publicJwk, "x");
        return new PublicJwk(KeyId.of(entity.kid), SigningAlgorithm.EdDSA, use, x, null);
    }

    /** Minimal extraction of a string member from the stored compact JWK JSON. */
    private static String extractJsonString(String json, String member) {
        String needle = "\"" + member + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) {
            throw new IllegalStateException("Stored JWK missing member '" + member + "'");
        }
        start += needle.length();
        int end = json.indexOf('"', start);
        return json.substring(start, end);
    }
}
