package dev.tessera.iam.adapter.persistence.entity;

import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Panache Reactive entity backing the {@code iam_credential} table.
 *
 * <p>Carries {@code tenant_id} and {@code baseline_id}; the table's row-level-security
 * policy scopes every read and write to the tenant bound via {@code app.tenant_id}.
 * The {@link #material} bytes are always verifier-side — an already-hashed password, a
 * stored WebAuthn public key, a TOTP secret or a hashed recovery code — never a
 * plaintext secret.
 */
@Entity
@Table(name = "iam_credential")
public class CredentialEntity extends PanacheEntityBase {

    /** Primary key (random v4). */
    @Id
    @Column(name = "id", nullable = false, updatable = false)
    public UUID id;

    /** Owning tenant — the row-level-security scoping key. */
    @Column(name = "tenant_id", nullable = false, updatable = false)
    public UUID tenantId;

    /** Configuration baseline scope. */
    @Column(name = "baseline_id", nullable = false, updatable = false)
    public UUID baselineId;

    /** Owning {@code iam_user.id}. */
    @Column(name = "user_id", nullable = false, updatable = false)
    public UUID userId;

    /** Credential kind, stored as the enum name. */
    @Enumerated(EnumType.STRING)
    @Column(name = "kind", nullable = false, length = 24)
    public CredentialKind kind;

    /** Already-hashed / opaque verifier-side material; never plaintext. */
    @Column(name = "material", nullable = false)
    public byte[] material;

    /** Optional user-facing label (e.g. an authenticator name). */
    @Column(name = "label")
    public String label;

    /** Creation instant (UTC). */
    @Column(name = "created_at", nullable = false, updatable = false)
    public Instant createdAt;
}
