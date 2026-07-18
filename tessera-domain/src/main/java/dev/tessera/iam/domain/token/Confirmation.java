package dev.tessera.iam.domain.token;

import java.util.Map;

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
     * Renders this confirmation as the JSON object that becomes a token's {@code cnf}
     * claim (RFC 7800 §3.1): a single-member map keyed by the binding method's
     * confirmation-key — {@code jkt} for DPoP (RFC 9449 §6.1), {@code x5t#S256} for
     * mTLS (RFC 8705 §3.1). Pure: no framework, no serialisation — the adapter that
     * signs the JWT places this map under the {@code cnf} claim verbatim.
     *
     * @return an immutable single-entry {@code cnf} object
     */
    Map<String, Object> asCnfClaim();

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

        @Override
        public Map<String, Object> asCnfClaim() {
            return Map.of("jkt", jkt);
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

        @Override
        public Map<String, Object> asCnfClaim() {
            return Map.of("x5t#S256", x5tS256);
        }
    }
}
