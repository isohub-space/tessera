package dev.tessera.iam.adapter.persistence.entity;

/**
 * Persisted discriminator for an OAuth2/OIDC client's kind, written to the
 * {@code oauth_client.client_type} column ({@code VARCHAR(16)}).
 *
 * <p>Mirrors the sealed domain {@code Client} pair: a {@link #CONFIDENTIAL} client can
 * hold credentials and authenticates to the token endpoint, while a {@link #PUBLIC}
 * client cannot keep a secret. The enum name is the stored value, so it must stay
 * within the column width and round-trip exactly.
 */
public enum ClientType {

    /** A client that can hold credentials and authenticate to the token endpoint. */
    CONFIDENTIAL,

    /** A client that cannot keep a secret (PKCE/DPoP-bound by construction). */
    PUBLIC
}
