package dev.tessera.iam.adapter.persistence.entity;

import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import dev.tessera.iam.domain.signingkey.SigningKeyState;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Panache Reactive entity backing the {@code signing_key} table.
 *
 * <p>Carries {@code tenant_id}; the table's row-level-security policy scopes every
 * read and write to the tenant bound via {@code app.tenant_id}, so a signing key of
 * tenant A is never visible to a call bound to tenant B. Backs the signing-key
 * readiness gate (a tenant is ready iff it owns ≥1 {@link SigningKeyState#ACTIVE}
 * key).</p>
 */
@Entity
@Table(name = "signing_key")
public class SigningKeyEntity extends PanacheEntityBase {

    /** Primary key. */
    @Id
    @Column(name = "id", nullable = false, updatable = false)
    public UUID id;

    /** Owning tenant — the row-level-security scoping key. */
    @Column(name = "tenant_id", nullable = false, updatable = false)
    public UUID tenantId;

    /** JWK key id, unique within the tenant. */
    @Column(name = "kid", nullable = false)
    public String kid;

    /** Signature algorithm (e.g. {@code EdDSA}). */
    @Column(name = "algorithm", nullable = false)
    public String algorithm;

    /** Lifecycle state, stored as the enum name. */
    @Enumerated(EnumType.STRING)
    @Column(name = "state", nullable = false, length = 16)
    public SigningKeyState state;

    /** Serialized public JWK. */
    @Column(name = "public_jwk", nullable = false)
    public String publicJwk;

    /** Envelope-encrypted private key (AES-256-GCM ciphertext). Never cleartext. */
    @Column(name = "private_key_enc")
    public byte[] privateKeyEnc;

    /** 96-bit GCM nonce for {@link #privateKeyEnc}. */
    @Column(name = "private_key_nonce")
    public byte[] privateKeyNonce;

    /** Per-key data-encryption key, wrapped by the master key (KMS/HSM in production). */
    @Column(name = "dek_wrapped")
    public byte[] dekWrapped;

    /** JWK {@code use} member; defaults to {@code sig} (these are token signing keys). */
    @Column(name = "key_use", nullable = false, length = 8)
    public String keyUse = "sig";

    /** Token issuer ({@code iss}) this key signs for. */
    @Column(name = "issuer")
    public String issuer;

    /** Instant the key became {@code ACTIVE}, or {@code null} if never activated. */
    @Column(name = "activated_at")
    public Instant activatedAt;

    /** Creation instant (UTC). */
    @Column(name = "created_at", nullable = false, updatable = false)
    public Instant createdAt;
}
