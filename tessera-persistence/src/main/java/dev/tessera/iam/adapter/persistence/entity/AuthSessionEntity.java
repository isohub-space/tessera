package dev.tessera.iam.adapter.persistence.entity;

import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Panache Reactive entity backing the {@code auth_session} table.
 *
 * <p>Carries {@code tenant_id} and {@code baseline_id}; the table's row-level-security
 * policy scopes every read and write to the tenant bound via {@code app.tenant_id}.
 *
 * <p>The primary key is a time-ordered UUID (version 7). Authorization sessions are
 * append-heavy and short-lived, so a time-ordered key keeps inserts at the right-hand
 * edge of the B-tree index rather than scattering them as a random v4 key would,
 * avoiding index fragmentation on a hot write path.
 */
@Entity
@Table(name = "auth_session")
public class AuthSessionEntity extends PanacheEntityBase {

    /** Primary key — a time-ordered UUID (v7); see the class javadoc. */
    @Id
    @Column(name = "id", nullable = false, updatable = false)
    public UUID id;

    /** Owning tenant — the row-level-security scoping key. */
    @Column(name = "tenant_id", nullable = false, updatable = false)
    public UUID tenantId;

    /** Configuration baseline scope. */
    @Column(name = "baseline_id", nullable = false, updatable = false)
    public UUID baselineId;

    /** Resolved OIDC {@code sub}; {@code null} until the user is authenticated. */
    @Column(name = "subject_id")
    public String subjectId;

    /** The {@code oauth_client.id} this session belongs to, if any. */
    @Column(name = "client_id")
    public UUID clientId;

    /** Session lifecycle state. */
    @Column(name = "state", nullable = false, length = 24)
    public String state;

    /** Creation instant (UTC). */
    @Column(name = "created_at", nullable = false, updatable = false)
    public Instant createdAt;

    /** Expiry instant, or {@code null} if the session does not expire. */
    @Column(name = "expires_at")
    public Instant expiresAt;
}
