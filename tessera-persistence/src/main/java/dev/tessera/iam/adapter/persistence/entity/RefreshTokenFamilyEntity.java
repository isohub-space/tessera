package dev.tessera.iam.adapter.persistence.entity;

import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Panache Reactive entity backing the {@code refresh_token_family} table.
 *
 * <p>Carries {@code tenant_id} and {@code baseline_id}; the table's row-level-security
 * policy scopes every read and write to the tenant bound via {@code app.tenant_id}.
 *
 * <p>The primary key is a time-ordered UUID (version 7). Token families are created on
 * a hot, append-heavy path (one per refresh-token issuance), so a time-ordered key
 * keeps inserts at the right-hand edge of the B-tree index rather than scattering them
 * as a random v4 key would, avoiding index fragmentation.
 *
 * <p>A family models refresh-token rotation: {@link #currentTokenHash} holds only the
 * hash of the latest token (never the token itself), {@link #generation} counts
 * rotations, and {@link #reused} flips to {@code true} when a superseded token is
 * presented — a replay signal that revokes the whole family.
 */
@Entity
@Table(name = "refresh_token_family")
public class RefreshTokenFamilyEntity extends PanacheEntityBase {

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

    /** The owning {@code iam_user.id}. */
    @Column(name = "user_id", nullable = false, updatable = false)
    public UUID userId;

    /** The {@code oauth_client.id} this family was issued to. */
    @Column(name = "client_id", nullable = false, updatable = false)
    public UUID clientId;

    /** Hash of the latest token in the family; never the token itself. */
    @Column(name = "current_token_hash", nullable = false)
    public String currentTokenHash;

    /** Rotation counter; incremented on each successful rotation. */
    @Column(name = "generation", nullable = false)
    public int generation;

    /** Set {@code true} on detected replay, which revokes the family. */
    @Column(name = "reused", nullable = false)
    public boolean reused;

    /** Creation instant (UTC). */
    @Column(name = "created_at", nullable = false, updatable = false)
    public Instant createdAt;

    /** Expiry instant, or {@code null} if the family does not expire. */
    @Column(name = "expires_at")
    public Instant expiresAt;
}
