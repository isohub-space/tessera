package dev.tessera.iam.adapter.persistence.entity;

import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Panache Reactive entity backing the {@code consent} table.
 *
 * <p>Carries {@code tenant_id} and {@code baseline_id}; the table's row-level-security
 * policy scopes every read and write to the tenant bound via {@code app.tenant_id}.
 * One row records the scopes a user consented to for a given client, unique within
 * {@code (tenant, baseline, user, client)}.
 */
@Entity
@Table(name = "consent")
public class ConsentEntity extends PanacheEntityBase {

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

    /** The consenting {@code iam_user.id}. */
    @Column(name = "user_id", nullable = false, updatable = false)
    public UUID userId;

    /** The {@code oauth_client.id} the consent was granted to. */
    @Column(name = "client_id", nullable = false, updatable = false)
    public UUID clientId;

    /** Space-separated scopes the user consented to. */
    @Column(name = "granted_scopes", nullable = false)
    public String grantedScopes;

    /** Instant the consent was granted (UTC). */
    @Column(name = "granted_at", nullable = false)
    public Instant grantedAt;

    /** Creation instant (UTC). */
    @Column(name = "created_at", nullable = false, updatable = false)
    public Instant createdAt;
}
