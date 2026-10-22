// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.tessera.iam.adapter.rest.config.ClientAssertionConfig;
import dev.tessera.iam.adapter.rest.config.OidcDiscoveryConfig;
import dev.tessera.iam.application.port.out.ClientAssertionVerifierPort;
import dev.tessera.iam.application.port.out.ClientKeySourcePort.AssertionTrust;
import dev.tessera.iam.domain.oidc.OidcCapabilities;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.Vertx;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * {@link ClientAssertionVerifierPort} with Nimbus JOSE: verifies a JWT client assertion
 * (RFC 7523 §3, OIDC Core §9) against the key source's {@link AssertionTrust}.
 *
 * <p><strong>Checks, all fail-closed.</strong> The {@code alg} is one of
 * {@link OidcCapabilities#CLIENT_ASSERTION_SIGNING_ALGS} ({@code none} does not parse as a JWS and
 * an HMAC is not on the list); the key is the single trusted key matching the {@code kid}, the
 * algorithm's key type and curve, between 2048 and 4096 bits for RSA, and, where the JWK says,
 * meant for signature verification ({@code use}, {@code key_ops}, {@code alg}); {@code iss} and
 * {@code sub} are the trusted ones; {@code aud} is exactly one value, this server's issuer
 * identifier;
 * {@code exp} is required and not past, {@code iat} and {@code nbf} are not in the future, all
 * within {@link ClientAssertionConfig#clockSkew()}; the validity is at most
 * {@link ClientAssertionConfig#maxLifetime()}; and the {@code jti} is used once.
 *
 * <p><strong>No oracle.</strong> Every assertion with an allowed {@code alg} costs one signature
 * verification. With no trust, or no matching key (an unknown {@code kid}), the signature is
 * checked against a sentinel key generated at start-up that no client holds, and fails. The
 * answer is a bare {@code false} whatever the reason. The sentinel RSA key is 2048 bits, so a client
 * registered with a larger RSA key verifies slightly slower against its own key than against the
 * sentinel; that tells only the key size the client chose.
 *
 * <p><strong>Issuer-only audience.</strong> The token endpoint URL is not accepted as {@code aud}.
 * The 2025 disclosure on {@code private_key_jwt} audience injection showed that a client which
 * builds {@code aud} from a token endpoint published in some other authorization server's
 * metadata can be made to sign an assertion for this server; the update to RFC 7523 that followed
 * restricts the audience to the authorization server's issuer identifier, which a client checks
 * against where it fetched the metadata (RFC 8414 §3.3).
 *
 * <p><strong>Replay store, per instance.</strong> A {@code jti} is recorded only once every other
 * check has passed, keyed by realm and issuer, and kept until the assertion expires plus the skew,
 * in an {@link AssertionReplayStore} bounded per client
 * ({@link ClientAssertionConfig#replayCacheMaxEntriesPerClient()}) and in total
 * ({@link ClientAssertionConfig#replayCacheMaxEntries()}), like the DPoP proof store and the
 * credential throttles. With several instances, a captured assertion could be replayed once on
 * each other instance within its lifetime, which the maximum lifetime bounds; a shared-cache store
 * with the same contract closes that.
 */
@Singleton
public class NimbusClientAssertionVerifier implements ClientAssertionVerifierPort {

    private static final Set<JWSAlgorithm> ALLOWED_ALGS = OidcCapabilities.CLIENT_ASSERTION_SIGNING_ALGS.stream()
            .map(JWSAlgorithm::parse).collect(Collectors.toUnmodifiableSet());
    private static final int MIN_RSA_BITS = 2048;
    private static final int MAX_RSA_BITS = 4096;
    private static final int MAX_JTI_LENGTH = 256;

    private final Vertx vertx;
    private final Clock clock;
    private final String audience;
    private final Duration maxLifetime;
    private final Duration skew;
    private final AssertionReplayStore spent;
    private final ECKey ecSentinel;
    private final RSAKey rsaSentinel;

    @Inject
    public NimbusClientAssertionVerifier(Vertx vertx, Clock clock, OidcDiscoveryConfig oidc,
            ClientAssertionConfig config) {
        this(vertx, clock, oidc.issuer(), config.maxLifetime(), config.clockSkew(),
                new AssertionReplayStore(config.replayCacheMaxEntriesPerClient(), config.replayCacheMaxEntries()));
    }

    NimbusClientAssertionVerifier(Vertx vertx, Clock clock, String issuer, Duration maxLifetime, Duration skew,
            AssertionReplayStore spent) {
        this.vertx = vertx;
        this.clock = clock;
        this.audience = issuer;
        this.maxLifetime = maxLifetime;
        this.skew = skew;
        this.spent = spent;
        try {
            this.ecSentinel = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK();
            this.rsaSentinel = new RSAKeyGenerator(MIN_RSA_BITS).generate().toPublicJWK();
        } catch (JOSEException e) {
            throw new IllegalStateException("cannot generate the sentinel verification keys", e);
        }
    }

    @Override
    public Uni<Boolean> verify(RealmKey realm, AssertionTrust trust, String assertion) {
        // Signature verification is CPU-bound: run it on a worker, never the event loop.
        return vertx.executeBlocking(() -> verifyNow(realm, trust, assertion, clock.instant()), false);
    }

    boolean verifyNow(RealmKey realm, AssertionTrust trust, String assertion, Instant now) {
        SignedJWT jwt;
        JWTClaimsSet claims;
        try {
            jwt = SignedJWT.parse(assertion);
            claims = jwt.getJWTClaimsSet();
        } catch (Exception malformed) {
            return false;
        }
        JWSAlgorithm alg = jwt.getHeader().getAlgorithm();
        if (!ALLOWED_ALGS.contains(alg)) {
            return false;
        }
        JWK key = trust == null ? null : trustedKey(trust.jwks(), jwt.getHeader().getKeyID(), alg);
        boolean signed = verifySignature(jwt, alg, key);
        return signed && key != null
                && claimsHold(claims, trust, now)
                && spent.firstUse(realm, trust.issuer(), claims.getJWTID(),
                        claims.getExpirationTime().toInstant().plus(skew), now);
    }

    private boolean verifySignature(SignedJWT jwt, JWSAlgorithm alg, JWK key) {
        try {
            JWSVerifier verifier = JWSAlgorithm.Family.EC.contains(alg)
                    ? new ECDSAVerifier(key != null ? key.toECKey() : ecSentinel)
                    : new RSASSAVerifier(key != null ? key.toRSAKey() : rsaSentinel);
            return jwt.verify(verifier);
        } catch (JOSEException | RuntimeException failed) {
            return false;
        }
    }

    /** The one registered key the assertion names (or, without a {@code kid}, the only one that fits). */
    private static JWK trustedKey(String jwks, String kid, JWSAlgorithm alg) {
        List<JWK> keys;
        try {
            keys = JWKSet.parse(jwks).getKeys();
        } catch (Exception malformed) {
            return null;
        }
        List<JWK> candidates = keys.stream()
                .filter(k -> kid == null || kid.equals(k.getKeyID()))
                .filter(k -> k.getKeyUse() == null || KeyUse.SIGNATURE.equals(k.getKeyUse()))
                .filter(k -> k.getKeyOperations() == null || k.getKeyOperations().contains(KeyOperation.VERIFY))
                .filter(k -> k.getAlgorithm() == null || alg.equals(k.getAlgorithm()))
                .filter(k -> fits(k, alg))
                .toList();
        return candidates.size() == 1 ? candidates.get(0).toPublicJWK() : null;
    }

    private static boolean fits(JWK key, JWSAlgorithm alg) {
        if (JWSAlgorithm.Family.EC.contains(alg)) {
            return key instanceof ECKey ec && Curve.forJWSAlgorithm(alg).contains(ec.getCurve());
        }
        return key instanceof RSAKey rsa && rsa.size() >= MIN_RSA_BITS && rsa.size() <= MAX_RSA_BITS;
    }

    private boolean claimsHold(JWTClaimsSet claims, AssertionTrust trust, Instant now) {
        List<String> aud = claims.getAudience();
        Date exp = claims.getExpirationTime();
        Date iat = claims.getIssueTime();
        Date nbf = claims.getNotBeforeTime();
        String jti = claims.getJWTID();
        if (!trust.issuer().equals(claims.getIssuer()) || !trust.subject().equals(claims.getSubject())
                || aud.size() != 1 || !audience.equals(aud.get(0))
                || exp == null || jti == null || jti.isBlank() || jti.length() > MAX_JTI_LENGTH) {
            return false;
        }
        // iat is at most the skew ahead, so exp - iat <= maxLifetime keeps exp within now + skew + maxLifetime.
        Instant expiry = exp.toInstant();
        Instant latestStart = now.plus(skew);
        Instant start = iat == null ? now : iat.toInstant();
        return expiry.isAfter(now.minus(skew))
                && !start.isAfter(latestStart)
                && (nbf == null || !nbf.toInstant().isAfter(latestStart))
                && Duration.between(start, expiry).compareTo(maxLifetime) <= 0;
    }
}
