package dev.tessera.iam.adapter.persistence.entity;

import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Panache Reactive entity backing the {@code iam_user} table.
 *
 * <p>Carries {@code tenant_id} and {@code baseline_id}; the table's row-level-security
 * policy scopes every read and write to the tenant bound via {@code app.tenant_id}, so
 * a user of tenant A is never visible to a call bound to tenant B. A user is a
 * credential-bearing projection correlated by its stable {@code subject_id}.
 */
@Entity
@Table(name = "iam_user")
public class UserEntity extends PanacheEntityBase {

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

    /** Stable OIDC {@code sub}, unique within {@code (tenant, baseline)}. */
    @Column(name = "subject_id", nullable = false)
    public String subjectId;

    /** Optional login identifier. */
    @Column(name = "username")
    public String username;

    /** Creation instant (UTC). */
    @Column(name = "created_at", nullable = false, updatable = false)
    public Instant createdAt;
}
