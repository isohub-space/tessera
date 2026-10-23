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
import io.quarkus.runtime.Startup;
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
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;

/**
 * {@link ClientAssertionVerifierPort} with Nimbus JOSE: verifies a JWT client assertion
 * (RFC 7523 §3, OIDC Core §9) against the key source's {@link AssertionTrust}.
 *
 * <p><strong>Two kinds of trust, one path.</strong> A {@code private_key_jwt} client's trust carries
 * its registered keys; it must send a {@code jti} (OIDC Core §9) and its assertion may live at most
 * {@link ClientAssertionConfig#maxLifetime()}. A client of a trusted external issuer (a platform's
 * workload identity) carries no keys: they come from {@link TrustedIssuerJwks}, refreshed once,
 * rate-limited, when the token names a {@code kid} the cached set lacks, and the issuer's own
 * maximum lifetime and {@code jti} switch apply. Its {@code jti} is tracked when present; without
 * one, the same token is accepted again until its own {@code exp}, as such tokens are reused for
 * their lifetime. An issuer that is not configured has no keys.
 *
 * <p><strong>Checks, all fail-closed.</strong> The {@code alg} is one of
 * {@link OidcCapabilities#CLIENT_ASSERTION_SIGNING_ALGS} ({@code none} does not parse as a JWS and
 * an HMAC is not on the list); the key is the single trusted key matching the {@code kid}, the
 * algorithm's key type and curve, between 2048 and 4096 bits for RSA, and, where the JWK says,
 * meant for signature verification ({@code use}, {@code key_ops}, {@code alg}); {@code iss} and
 * {@code sub} are the trusted ones; {@code aud} is exactly one value, this server's issuer
 * identifier;
 * {@code exp} is required and not past, {@code iat} and {@code nbf} are not in the future, all
 * within {@link ClientAssertionConfig#clockSkew()}; the validity is at most the maximum lifetime
 * that applies; and a {@code jti} is used once.
 *
 * <p><strong>No oracle.</strong> Every assertion with an allowed {@code alg} costs one signature
 * verification. With no trust, or no matching key (an unknown {@code kid}), the signature is
 * checked against a sentinel key generated at start-up that no client holds, and fails. The
 * answer is a bare {@code false} whatever the reason. A client of an external issuer may cause a
 * key-set fetch, at most once per refresh interval per issuer, which an unknown client never does.
 * The sentinel RSA key is 2048 bits, so a client
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
 * check has passed, keyed by realm, issuer and subject (by issuer and subject alone for an external
 * issuer, whose workload is one identity wherever its token is presented), and kept until the
 * assertion expires plus the skew, in an {@link AssertionReplayStore} bounded per realm, issuer and subject
 * ({@link ClientAssertionConfig#replayCacheMaxEntriesPerClient()}), per realm
 * ({@link ClientAssertionConfig#replayCacheMaxEntriesPerRealm()}) and in total
 * ({@link ClientAssertionConfig#replayCacheMaxEntries()}), like the DPoP proof store and the
 * credential throttles. With several instances, a captured assertion could be replayed once on
 * each other instance within its lifetime, which the maximum lifetime bounds; a shared-cache store
 * with the same contract closes that.
 *
 * <p>The settings are checked at startup ({@link Startup}), so a deployment whose replay caps do
 * not nest fails to boot instead of refusing its first assertion.
 */
@Startup
@Singleton
public class NimbusClientAssertionVerifier implements ClientAssertionVerifierPort {

    private static final Set<JWSAlgorithm> ALLOWED_ALGS = OidcCapabilities.CLIENT_ASSERTION_SIGNING_ALGS.stream()
            .map(JWSAlgorithm::parse).collect(Collectors.toUnmodifiableSet());
    private static final int MIN_RSA_BITS = 2048;
    private static final int MAX_RSA_BITS = 4096;
    private static final int MAX_JTI_LENGTH = 256;
    private static final Logger LOG = Logger.getLogger(NimbusClientAssertionVerifier.class);

    private final Vertx vertx;
    private final Clock clock;
    private final String audience;
    private final Duration maxLifetime;
    private final Duration skew;
    private final AssertionReplayStore spent;
    private final TrustedIssuerJwks issuers;
    private final Set<String> unlistedIssuers = ConcurrentHashMap.newKeySet();
    private final ECKey ecSentinel;
    private final RSAKey rsaSentinel;

    @Inject
    public NimbusClientAssertionVerifier(Vertx vertx, Clock clock, OidcDiscoveryConfig oidc,
            ClientAssertionConfig config, TrustedIssuerJwks issuers) {
        this(vertx, clock, oidc.issuer(), config.maxLifetime(), config.clockSkew(),
                new AssertionReplayStore(config.replayCacheMaxEntriesPerClient(),
                        config.replayCacheMaxEntriesPerRealm(), config.replayCacheMaxEntries()), issuers);
    }

    NimbusClientAssertionVerifier(Vertx vertx, Clock clock, String issuer, Duration maxLifetime, Duration skew,
            AssertionReplayStore spent, TrustedIssuerJwks issuers) {
        this.vertx = vertx;
        this.clock = clock;
        this.audience = issuer;
        this.maxLifetime = maxLifetime;
        this.skew = skew;
        this.spent = spent;
        this.issuers = issuers;
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
        String kid = jwt.getHeader().getKeyID();
        TrustedIssuerJwks.Policy external = trust == null || trust.jwks() != null ? null : issuers.policy(trust.issuer());
        if (trust != null && trust.jwks() == null && external == null && unlistedIssuers.add(trust.issuer())) {
            // A registration naming an issuer the operator did not list can never authenticate: say so once.
            LOG.warnf("a workload-identity client is registered with issuer %s, which is not a configured "
                    + "trusted issuer (iam.client-assertion.trusted-issuers); its assertions are refused", trust.issuer());
        }
        JWK key = null;
        if (trust != null && trust.jwks() != null) {
            key = trustedKey(trust.jwks(), kid, alg);
        } else if (external != null) {
            // An issuer rotates its keys: a kid the cached set lacks asks for one rate-limited refresh.
            String jwks = issuers.jwksNow(trust.issuer(), false);
            key = jwks == null ? null : trustedKey(jwks, kid, alg);
            if (key == null && jwks != null && kid != null) {
                String refreshed = issuers.jwksNow(trust.issuer(), true);
                key = refreshed == null ? null : trustedKey(refreshed, kid, alg);
            }
        }
        boolean signed = verifySignature(jwt, alg, key);
        if (!signed || key == null) {
            return false;
        }
        // private_key_jwt: OIDC Core §9 requires a jti. An external issuer's token may lack one (RFC 7523
        // §3); without it, replay is bounded by its own exp within the issuer's maximum lifetime.
        Duration lifetime = external == null ? maxLifetime : external.maxLifetime();
        boolean jtiRequired = external == null || external.requireJti();
        String jti = claims.getJWTID();
        return claimsHold(claims, trust, now, lifetime)
                && (jti == null ? !jtiRequired : !jti.isBlank() && jti.length() <= MAX_JTI_LENGTH
                        && spent.firstUse(realm, trust.issuer(), trust.subject(), jti, external != null,
                                claims.getExpirationTime().toInstant().plus(skew), now));
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

    private boolean claimsHold(JWTClaimsSet claims, AssertionTrust trust, Instant now, Duration maxLifetime) {
        List<String> aud = claims.getAudience();
        Date exp = claims.getExpirationTime();
        Date iat = claims.getIssueTime();
        Date nbf = claims.getNotBeforeTime();
        if (!trust.issuer().equals(claims.getIssuer()) || !trust.subject().equals(claims.getSubject())
                || aud.size() != 1 || !audience.equals(aud.get(0)) || exp == null) {
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
