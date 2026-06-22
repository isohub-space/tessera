package dev.tessera.iam.domain.authcode;

/**
 * The PKCE (RFC 7636) {@code code_challenge_method} this server honours.
 *
 * <p>Like the grant-type model, this is a deliberate <em>WON'T-list</em> statement:
 * the {@code plain} method is <strong>not representable</strong>. RFC 7636 §4.2
 * permits {@code plain} only where the client cannot compute a SHA-256, but a
 * {@code plain} challenge offers no protection against an intercepted authorization
 * code (the challenge equals the verifier on the wire). Modelling only {@code S256}
 * turns "PKCE S256 is mandatory" into a compile-time guarantee — code that switches
 * over this type can never accept {@code plain}.
 */
public enum PkceMethod {

    /** SHA-256 challenge: {@code code_challenge = BASE64URL(SHA256(code_verifier))}. */
    S256;

    /** The wire {@code code_challenge_method} value for this method. */
    public String wireValue() {
        return name();
    }
}
