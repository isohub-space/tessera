package dev.tessera.iam.domain.token;

/**
 * A token's {@code cnf} (confirmation) claim — the sender-constraining binding
 *.
 *
 * <p>Modelled as a small sealed pair tagging the two binding methods the design
 * requires (RFC 9449 DPoP and RFC 8705 mTLS). A bound token always carries exactly
 * one; a public client's token is DPoP-bound, a confidential service client's
 * token is mTLS-bound. The design rejects a token of those classes that has no
 * {@code cnf} at the resource server — there is no "unbound" member here, so an
 * unbound token simply has no {@code Confirmation}.
 */
public sealed interface Confirmation permits Confirmation.DpopJkt, Confirmation.MtlsX5tS256 {

    /**
     * The JWK SHA-256 thumbprint binding for a DPoP-bound token
     * ({@code cnf.jkt}, RFC 9449).
     *
     * @param jkt base64url SHA-256 thumbprint of the client's DPoP public key
     *            (never {@code null} or blank)
     */
    record DpopJkt(String jkt) implements Confirmation {
        public DpopJkt {
            if (jkt == null || jkt.isBlank()) {
                throw new IllegalArgumentException("DpopJkt jkt must not be blank");
            }
        }
    }

    /**
     * The certificate SHA-256 thumbprint binding for an mTLS-bound token
     * ({@code cnf["x5t#S256"]}, RFC 8705).
     *
     * @param x5tS256 base64url SHA-256 thumbprint of the client certificate
     *                (never {@code null} or blank)
     */
    record MtlsX5tS256(String x5tS256) implements Confirmation {
        public MtlsX5tS256 {
            if (x5tS256 == null || x5tS256.isBlank()) {
                throw new IllegalArgumentException("MtlsX5tS256 x5tS256 must not be blank");
            }
        }
    }
}
