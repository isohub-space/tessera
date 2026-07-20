package dev.tessera.iam.adapter.rest.token;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.tessera.iam.adapter.rest.config.DpopConfig;
import dev.tessera.iam.application.port.out.DpopProofValidatorPort;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.Vertx;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Inbound-adapter implementation of {@link DpopProofValidatorPort}: validates a DPoP proof
 * JWT (RFC 9449) with a JOSE library (Nimbus) and, on success, returns the RFC 7638 JWK
 * thumbprint ({@code jkt}) that sender-constrains the access token.
 *
 * <p>Verification runs <strong>off the reactive event loop</strong> (Vert.x worker) because
 * it does asymmetric signature crypto over a client-supplied key. The full RFC 9449 §4.3
 * check set is enforced here — {@code typ}, {@code alg}, the embedded public {@code jwk},
 * the signature, {@code htm}/{@code htu}, {@code iat} freshness and single-use {@code jti} —
 * and any failure returns {@link Result.Invalid} without revealing which check failed.
 *
 * <p><strong>Algorithm scope.</strong> This build accepts {@code ES256} (ECDSA P-256), the
 * de-facto DPoP algorithm and the value advertised in {@code dpop_signing_alg_values_supported}.
 * {@code EdDSA} proofs are a documented follow-up (Nimbus verifies Ed25519 only via an extra
 * crypto backend); discovery advertises exactly what is enforced here, so it stays honest.
 *
 * <p><strong>Replay store.</strong> Spent {@code jti}s are held in an in-process map for the
 * acceptance window (single-node, matching the bundled authorization-code and rate-limit
 * stores); a clustered deployment swaps in a shared-cache adapter with the same contract.
 */
@ApplicationScoped
public class NimbusDpopProofValidator implements DpopProofValidatorPort {

    private static final JOSEObjectType DPOP_TYP = new JOSEObjectType("dpop+jwt");
    /** The only DPoP proof algorithm this build accepts (see class note). */
    private static final JWSAlgorithm ACCEPTED_ALG = JWSAlgorithm.ES256;

    private final ConcurrentMap<String, Instant> seenJti = new ConcurrentHashMap<>();

    @Inject
    DpopConfig config;

    @Inject
    Vertx vertx;

    @Override
    public Uni<Result> validate(Request request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }
        // Signature verification is CPU-bound crypto — run it on a Vert.x worker, never the
        // event loop; executeBlocking completes back on the calling context.
        return vertx.executeBlocking(() -> validateSync(request), false);
    }

    private Result validateSync(Request request) {
        SignedJWT proof;
        try {
            proof = SignedJWT.parse(request.proofJwt());
        } catch (Exception malformed) {
            return invalid("malformed");
        }

        JWSHeader header = proof.getHeader();
        if (!DPOP_TYP.equals(header.getType())) {
            return invalid("typ");
        }
        if (!ACCEPTED_ALG.equals(header.getAlgorithm())) {
            return invalid("alg");
        }

        JWK jwk = header.getJWK();
        // The proof must embed the client's PUBLIC key; a private JWK (or none) is rejected —
        // the key is what the token is bound to, and it must be verifiable by anyone.
        if (jwk == null || jwk.isPrivate() || !(jwk instanceof ECKey ecKey)) {
            return invalid("jwk");
        }

        try {
            if (!proof.verify(new ECDSAVerifier(ecKey.toPublicJWK()))) {
                return invalid("signature");
            }
        } catch (Exception badSignature) {
            return invalid("signature");
        }

        JWTClaimsSet claims;
        try {
            claims = proof.getJWTClaimsSet();
        } catch (Exception badClaims) {
            return invalid("claims");
        }

        // htm/htu must bind the proof to THIS request (the configured token endpoint, POST).
        if (!request.htm().equals(claims.getClaim("htm"))) {
            return invalid("htm");
        }
        Object htu = claims.getClaim("htu");
        if (!(htu instanceof String htuStr) || !request.htu().equals(stripQueryFragment(htuStr))) {
            return invalid("htu");
        }

        Instant now = request.now();
        Date iat = claims.getIssueTime();
        if (iat == null || !withinWindow(iat.toInstant(), now)) {
            return invalid("iat");
        }

        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) {
            return invalid("jti");
        }
        // Single-use: record the jti for the freshness window; a second presentation misses.
        // Pruning first bounds the map to the live window.
        pruneExpired(now);
        Instant retainUntil = now.plus(config.proofMaxAge()).plus(config.clockSkew());
        if (seenJti.putIfAbsent(jti, retainUntil) != null) {
            return invalid("replay");
        }

        try {
            // RFC 7638 SHA-256 JWK thumbprint, base64url — the cnf.jkt binding.
            return new Result.Valid(ecKey.toPublicJWK().computeThumbprint().toString());
        } catch (Exception thumbprintFailed) {
            return invalid("thumbprint");
        }
    }

    private boolean withinWindow(Instant iat, Instant now) {
        Duration maxAge = config.proofMaxAge();
        Duration skew = config.clockSkew();
        // iat must not be older than now-maxAge, nor further in the future than the skew bound.
        return !iat.isBefore(now.minus(maxAge)) && !iat.isAfter(now.plus(skew));
    }

    private void pruneExpired(Instant now) {
        seenJti.values().removeIf(expiry -> expiry.isBefore(now));
    }

    private static Result invalid(String reason) {
        return new Result.Invalid(reason);
    }

    /** Drops any query or fragment from the presented {@code htu} (RFC 9449 §4.3 comparison). */
    private static String stripQueryFragment(String uri) {
        int cut = uri.length();
        int q = uri.indexOf('?');
        int f = uri.indexOf('#');
        if (q >= 0) {
            cut = Math.min(cut, q);
        }
        if (f >= 0) {
            cut = Math.min(cut, f);
        }
        return uri.substring(0, cut);
    }
}
