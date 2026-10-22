package dev.tessera.iam.adapter.persistence.entity;

import dev.tessera.iam.application.port.out.ClientSecretVerifierPort;
import dev.tessera.iam.domain.client.RedirectUriPolicy;
import io.quarkus.hibernate.reactive.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.List;
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
 *
 * <p>Every insert and update checks {@link #redirectUris} against {@link RedirectUriPolicy}, so
 * no registration path can store a redirect URI that would carry a code over plain http.
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

    /**
     * Argon2id PHC string for a confidential client that authenticates with a shared
     * {@code client_secret}; never plaintext. {@code null} for public clients and for
     * confidential clients that authenticate by MTLS or {@code private_key_jwt}.
     */
    @Column(name = "secret_hash")
    public String secretHash;

    /**
     * JWK Set JSON of the public keys a {@code PRIVATE_KEY_JWT} client signs its client assertions
     * with (RFC 7523); {@code null} for every other client. The database refuses keys on any other
     * client, and a secret on a {@code PRIVATE_KEY_JWT} client.
     */
    @Column(name = "jwks")
    public String jwks;

    /** Comma-separated allowed {@code grant_type} values. */
    @Column(name = "allowed_grants", nullable = false)
    public String allowedGrants;

    /**
     * Whitespace-separated registered redirect URIs (exact-match allow-list for
     * {@code /authorize}); {@code null} for a client with no registered URI.
     */
    @Column(name = "redirect_uris")
    public String redirectUris;

    /** Whitespace-separated scopes the client may be granted by {@code client_credentials}. */
    @Column(name = "allowed_scopes")
    public String allowedScopes;

    /** Whitespace-separated audiences its {@code client_credentials} tokens may name. */
    @Column(name = "audiences")
    public String audiences;

    /** Whitespace-separated roles its {@code client_credentials} tokens carry. */
    @Column(name = "roles")
    public String roles;

    /** Creation instant (UTC). */
    @Column(name = "created_at", nullable = false, updatable = false)
    public Instant createdAt;

    /**
     * Refuses, on insert and on update, a client id reserved for the sentinels unknown clients are
     * verified against ({@link ClientSecretVerifierPort#isReserved}: the nil UUID and name-based
     * ids), and a redirect URI the policy does not allow (RFC 9700 §2.6). A client registered
     * under a sentinel id would share its failure budget with every unknown {@code client_id} that
     * maps to it.
     *
     * <p>The update check runs on every update of the row, not only one that changes
     * {@link #redirectUris}. A row registered before this check that holds a non-compliant URI
     * therefore cannot be updated at all, for example to rotate its secret, until its redirect
     * URIs are fixed in the same update.
     */
    @PrePersist
    @PreUpdate
    void checkRegistration() {
        if (id != null && ClientSecretVerifierPort.isReserved(id)) {
            throw new IllegalArgumentException("client id " + id + " is reserved and cannot be registered");
        }
        if (redirectUris == null || redirectUris.isBlank()) {
            return;
        }
        RedirectUriPolicy.requireRegistrable(
                List.of(redirectUris.trim().split("\\s+")), clientType == ClientType.PUBLIC);
    }
}
