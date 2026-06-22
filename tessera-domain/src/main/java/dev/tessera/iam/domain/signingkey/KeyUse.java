package dev.tessera.iam.domain.signingkey;

/**
 * The JWK {@code use} (public key use, RFC 7517 §4.2) of a published key.
 *
 * <p>A signing key is published with {@code use=sig} so verifiers select it for
 * signature verification rather than encryption. Encryption keys ({@code use=enc})
 * are out of scope for the token-signing pipeline but the member exists so selection
 * by {@code use} is total.
 */
public enum KeyUse {

    /** Signature use ({@code "sig"}). */
    SIGNATURE("sig"),

    /** Encryption use ({@code "enc"}). */
    ENCRYPTION("enc");

    private final String jwkValue;

    KeyUse(String jwkValue) {
        this.jwkValue = jwkValue;
    }

    /** The JWK {@code use} member value (e.g. {@code "sig"}). */
    public String jwkValue() {
        return jwkValue;
    }
}
