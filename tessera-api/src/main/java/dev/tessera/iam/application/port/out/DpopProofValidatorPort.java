package dev.tessera.iam.application.port.out;

import io.smallrye.mutiny.Uni;
import java.time.Instant;

/**
 * Outbound port that validates a DPoP proof JWT (RFC 9449) presented at the token endpoint
 * by a public client, and — on success — yields the JWK SHA-256 thumbprint ({@code jkt},
 * RFC 7638) that sender-constrains the issued access token ({@code cnf.jkt}).
 *
 * <p>The proof is a compact JWS the client signs with the private key whose public half it
 * embeds in the proof header ({@code jwk}). Verifying it is CPU-bound asymmetric crypto over
 * a <em>client-chosen</em> algorithm and a client-supplied key, so it is an adapter concern
 * (the bundled adapter uses a JOSE library) and runs <strong>off the reactive event loop</strong>;
 * the domain and application core never touch JOSE or {@code java.security}. The application
 * service threads in only the request-independent expectations — the HTTP method/URI the proof
 * must be bound to and the current instant — keeping this port pure of framework and transport.
 *
 * <p>The adapter is responsible for the full RFC 9449 §4.3 check set: {@code typ=dpop+jwt};
 * an allowed asymmetric {@code alg} (never {@code none}/symmetric); a well-formed public
 * {@code jwk} carrying no private parameters; a valid signature; {@code htm}/{@code htu}
 * equal to the expected method/URI; an {@code iat} within the acceptance window; and a
 * {@code jti} not seen before within that window (single-use replay defence). Any failure
 * yields {@link Result.Invalid} — the application collapses it to an OAuth error without
 * revealing which check failed.
 */
public interface DpopProofValidatorPort {

    /**
     * Validates a DPoP proof against the expected binding and current time.
     *
     * @param request the proof and the expectations it must satisfy (never {@code null})
     * @return a {@link Uni} emitting {@link Result.Valid} (with the {@code jkt}) or
     *         {@link Result.Invalid}
     */
    Uni<Result> validate(Request request);

    /**
     * A DPoP proof and the request-bound expectations it must satisfy.
     *
     * @param proofJwt the compact DPoP proof JWS from the {@code DPoP} header (never blank)
     * @param htm      the HTTP method the proof must be bound to — {@code POST} for the token
     *                 endpoint (never blank)
     * @param htu      the HTTP URI the proof must be bound to — the token endpoint URL,
     *                 without query or fragment (never blank)
     * @param now      the current instant, for the {@code iat} freshness check (never {@code null})
     */
    record Request(String proofJwt, String htm, String htu, Instant now) {

        public Request {
            if (proofJwt == null || proofJwt.isBlank()) {
                throw new IllegalArgumentException("DPoP Request proofJwt must not be blank");
            }
            if (htm == null || htm.isBlank()) {
                throw new IllegalArgumentException("DPoP Request htm must not be blank");
            }
            if (htu == null || htu.isBlank()) {
                throw new IllegalArgumentException("DPoP Request htu must not be blank");
            }
            if (now == null) {
                throw new IllegalArgumentException("DPoP Request now must not be null");
            }
        }
    }

    /** The outcome of proof validation: the bound thumbprint, or a non-revealing failure. */
    sealed interface Result permits Result.Valid, Result.Invalid {

        /**
         * The proof is valid; {@code jkt} is the base64url SHA-256 JWK thumbprint (RFC 7638)
         * to place in the access token's {@code cnf.jkt}.
         *
         * @param jkt the JWK thumbprint (never {@code null} or blank)
         */
        record Valid(String jkt) implements Result {
            public Valid {
                if (jkt == null || jkt.isBlank()) {
                    throw new IllegalArgumentException("DPoP Valid jkt must not be blank");
                }
            }
        }

        /**
         * The proof failed a check. {@code reason} is a short, non-sensitive tag for audit
         * logging only — it is never surfaced to the client verbatim.
         *
         * @param reason a short diagnostic tag (never {@code null})
         */
        record Invalid(String reason) implements Result {
            public Invalid {
                if (reason == null) {
                    throw new IllegalArgumentException("DPoP Invalid reason must not be null");
                }
            }
        }
    }
}
