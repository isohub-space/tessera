package dev.tessera.iam.domain.signingkey;

/**
 * Lifecycle state of an OIDC/OAuth2 token signing key.
 *
 * <p>Pure-Java domain enum (no framework imports). The signing-key readiness gate
 * treats a tenant as ready iff it has at least one {@link #ACTIVE} key.
 * Key rotation (PENDING → ACTIVE → RETIRING → RETIRED) is fleshed out by later
 * stories; this slice only needs the ACTIVE distinction.</p>
 */
public enum SigningKeyState {

    /** Generated but not yet promoted to signing. */
    PENDING,

    /** Currently used to sign newly issued tokens. */
    ACTIVE,

    /** No longer signing, but still published for verification of in-flight tokens. */
    RETIRING,

    /** Fully withdrawn; no longer published. */
    RETIRED
}
