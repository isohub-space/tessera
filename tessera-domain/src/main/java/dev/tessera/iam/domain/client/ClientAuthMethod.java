package dev.tessera.iam.domain.client;

/**
 * How a {@link ConfidentialClient} authenticates to the token endpoint
 *.
 *
 * <p>Note the deliberate absence of a {@code NONE} member: a confidential client
 * <em>by definition</em> authenticates. "No client authentication" is not a
 * weaker confidential method — it is a {@link PublicClient}, a different type
 * entirely. Modelling the absence of auth out of this enum keeps the
 * public/confidential distinction honest at compile time.
 */
public enum ClientAuthMethod {

    /** Mutual-TLS client authentication (RFC 8705); also enables mTLS-bound tokens. */
    MTLS,

    /** {@code private_key_jwt} client assertion (RFC 7523) — asymmetric, no shared secret. */
    PRIVATE_KEY_JWT,

    /** Shared {@code client_secret} (basic/post) — the weakest accepted method. */
    CLIENT_SECRET
}
