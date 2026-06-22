package dev.tessera.iam.domain.signingkey;

/**
 * The asymmetric digital-signature algorithms a token signing key may use.
 *
 * <p>This authorization server signs JWTs (ID Tokens, JWT access tokens) with an
 * asymmetric key pair so that any relying party can verify a token using only the
 * server's public JWKS — the private key never leaves the signer. {@code EdDSA}
 * (Ed25519, RFC 8037) is the default; {@code ES256} (ECDSA on P-256, RFC 7518) is
 * offered for interoperability with verifiers that do not yet support EdDSA.
 *
 * <p>Symmetric MAC algorithms ({@code HS256}/{@code HS384}/{@code HS512}) are
 * <strong>deliberately not representable</strong> by this type. A shared-secret MAC
 * cannot back a public JWKS — every verifier would need the signing secret — so an
 * {@code HS*} key can never be selected for signing. Making the family unrepresentable
 * turns "no symmetric signing" into a compile-time guarantee rather than a runtime
 * check.
 */
public enum SigningAlgorithm {

    /** Edwards-curve Digital Signature Algorithm (Ed25519, RFC 8037). The default. */
    EdDSA("OKP", "Ed25519"),

    /** ECDSA using P-256 and SHA-256 (RFC 7518). Offered for interoperability. */
    ES256("EC", "P-256");

    private final String keyType;
    private final String curve;

    SigningAlgorithm(String keyType, String curve) {
        this.keyType = keyType;
        this.curve = curve;
    }

    /** The default algorithm for newly minted signing keys. */
    public static SigningAlgorithm defaultAlgorithm() {
        return EdDSA;
    }

    /** The JWK {@code kty} (key type) member value for this algorithm. */
    public String keyType() {
        return keyType;
    }

    /** The JWK {@code crv} (curve) member value for this algorithm. */
    public String curve() {
        return curve;
    }

    /** The JWA {@code alg} identifier (the enum name is the registered identifier). */
    public String algIdentifier() {
        return name();
    }
}
