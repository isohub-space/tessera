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
 * Panache Reactive entity backing the {@code oauth_client} table.
 *
 * <p>Carries {@code tenant_id} and {@code baseline_id}; the table's row-level-security
 * policy scopes every read and write to the tenant bound via {@code app.tenant_id}.
 *
 * <p>{@link #authMethod} is stored as the {@code ClientAuthMethod} enum name and is
 * {@code null} for public clients (which cannot authenticate by definition).
 * {@link #allowedGrants} keeps the comma-separated {@code grant_type} values as text;
 * the application layer maps them to/from the domain grant set.
 */
@Entity
@Table(name = "oauth_client")
public class OAuthClientEntity extends PanacheEntityBase {

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

    /** External client identifier, unique within {@code (tenant, baseline)}. */
    @Column(name = "client_key", nullable = false)
    public String clientKey;

    /** Client kind, stored as the enum name. */
    @Enumerated(EnumType.STRING)
    @Column(name = "client_type", nullable = false, length = 16)
    public ClientType clientType;

    /** Token-endpoint authentication method name; {@code null} for public clients. */
    @Column(name = "auth_method", length = 32)
    public String authMethod;

    /** Comma-separated allowed {@code grant_type} values. */
    @Column(name = "allowed_grants", nullable = false)
    public String allowedGrants;

    /** Creation instant (UTC). */
    @Column(name = "created_at", nullable = false, updatable = false)
    public Instant createdAt;
}
