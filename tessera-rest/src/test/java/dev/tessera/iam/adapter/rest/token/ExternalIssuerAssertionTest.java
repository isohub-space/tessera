// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.JWTClaimsSet;
import dev.tessera.iam.adapter.rest.support.AssertionTestClient;
import dev.tessera.iam.application.port.out.ClientKeySourcePort.AssertionTrust;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Keyless client authentication against a stub Kubernetes-style issuer: the issuer, its key-set URL,
 * its maximum lifetime and its {@code jti} rule are configuration, and the same verifier serves it.
 */
@DisplayName("Trusted external issuer assertions — a stub Kubernetes issuer, configured, not coded")
class ExternalIssuerAssertionTest {

    private static final String AUDIENCE = "https://tessera.example";
    private static final String CLUSTER = "https://kubernetes.default.svc.cluster.local";
    private static final String SA = "system:serviceaccount:orders:billing";
    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-23T10:00:00Z"));
    private final AtomicReference<AssertionTestClient> clusterKey = new AtomicReference<>(new AssertionTestClient());
    private final AtomicInteger fetches = new AtomicInteger();
    private final AssertionTrust trust = AssertionTrust.ofIssuer(CLUSTER, SA);

    private NimbusClientAssertionVerifier verifier(Duration maxLifetime, boolean requireJti, int maxPerOwner) {
        TrustedIssuerJwks issuers = new TrustedIssuerJwks(null, now::get,
                Map.of(CLUSTER, new TrustedIssuerJwks.Issuer("https://cluster.example/openid/v1/jwks",
                        new TrustedIssuerJwks.Policy(maxLifetime, requireJti))),
                Duration.ofMinutes(10), Duration.ofSeconds(30), uri -> {
                    fetches.incrementAndGet();
                    return new TrustedIssuerJwks.Transport.Response(200,
                            clusterKey.get().jwks().getBytes(StandardCharsets.UTF_8));
                }, host -> new InetAddress[] {InetAddress.getByName("203.0.113.7")});
        return new NimbusClientAssertionVerifier(null, null, AUDIENCE, Duration.ofMinutes(5), Duration.ofSeconds(30),
                new AssertionReplayStore(maxPerOwner, 100, 100), issuers);
    }

    /** A cluster token for the service account: one-hour lifetime, no jti unless the caller adds one. */
    private String token(UnaryOperator<JWTClaimsSet.Builder> claims) {
        JWTClaimsSet.Builder base = AssertionTestClient.claims(SA, AUDIENCE, now.get())
                .issuer(CLUSTER)
                .expirationTime(Date.from(now.get().plus(Duration.ofHours(1))))
                .jwtID(null);
        return clusterKey.get().sign(claims.apply(base).build());
    }

    private boolean verify(NimbusClientAssertionVerifier verifier, AssertionTrust trust, String token) {
        return verifier.verifyNow(REALM, trust, token, now.get());
    }

    @Test
    @DisplayName("a configured issuer's token without jti is accepted, and again while it lives")
    void reusableTokenWithoutJti() {
        NimbusClientAssertionVerifier verifier = verifier(Duration.ofHours(1), false, 10);
        String token = token(c -> c);
        assertThat(verify(verifier, trust, token)).isTrue();
        assertThat(verify(verifier, trust, token)).isTrue();
        assertThat(fetches).hasValue(1);
    }

    @Test
    @DisplayName("the issuer's maximum lifetime applies: a one-hour token is refused under the five-minute default")
    void perIssuerMaximumLifetime() {
        assertThat(verify(verifier(Duration.ofMinutes(5), false, 10), trust, token(c -> c))).isFalse();
        assertThat(verify(verifier(Duration.ofHours(1), false, 10), trust,
                token(c -> c.expirationTime(Date.from(now.get().plus(Duration.ofMinutes(61))))))).isFalse();
    }

    @Test
    @DisplayName("a jti is used once when present, and required when the issuer is configured so")
    void jtiRule() {
        NimbusClientAssertionVerifier lenient = verifier(Duration.ofHours(1), false, 10);
        String withJti = token(c -> c.jwtID("once"));
        assertThat(verify(lenient, trust, withJti)).isTrue();
        assertThat(verify(lenient, trust, withJti)).isFalse();

        NimbusClientAssertionVerifier strict = verifier(Duration.ofHours(1), true, 10);
        assertThat(verify(strict, trust, token(c -> c))).isFalse();
        assertThat(verify(strict, trust, token(c -> c.jwtID("fresh")))).isTrue();
    }

    @Test
    @DisplayName("wrong subject, wrong audience, an unconfigured issuer and a foreign key are refused")
    void claimAndIssuerViolationsAreRefused() {
        NimbusClientAssertionVerifier verifier = verifier(Duration.ofHours(1), false, 10);
        assertThat(verify(verifier, trust, token(c -> c.subject("system:serviceaccount:orders:other")))).isFalse();
        assertThat(verify(verifier, trust, token(c -> c.audience("https://elsewhere.example")))).isFalse();
        assertThat(verify(verifier, AssertionTrust.ofIssuer("https://unconfigured.example", SA),
                token(c -> c.issuer("https://unconfigured.example")))).isFalse();
        String foreign = new AssertionTestClient().sign(
                AssertionTestClient.claims(SA, AUDIENCE, now.get()).issuer(CLUSTER).build());
        assertThat(verify(verifier, trust, foreign)).isFalse();
    }

    @Test
    @DisplayName("a rotated key is found by one rate-limited refresh of the issuer's key set")
    void keyRotationRefreshesOnce() {
        NimbusClientAssertionVerifier verifier = verifier(Duration.ofHours(1), false, 10);
        assertThat(verify(verifier, trust, token(c -> c))).isTrue();
        clusterKey.set(new AssertionTestClient("rotated"));
        assertThat(verify(verifier, trust, token(c -> c))).as("within the refresh interval").isFalse();
        now.set(now.get().plusSeconds(30));
        assertThat(verify(verifier, trust, token(c -> c))).as("after it").isTrue();
        assertThat(fetches).hasValue(2);
    }

    @Test
    @DisplayName("the replay cap belongs to realm, issuer and subject: one subject's cap leaves another's free")
    void replayCapOwnerIsTheSubject() {
        NimbusClientAssertionVerifier verifier = verifier(Duration.ofHours(1), false, 1);
        assertThat(verify(verifier, trust, token(c -> c.jwtID("a")))).isTrue();
        assertThat(verify(verifier, trust, token(c -> c.jwtID("b")))).as("same subject, over its cap").isFalse();
        String other = "system:serviceaccount:orders:shipping";
        assertThat(verify(verifier, AssertionTrust.ofIssuer(CLUSTER, other),
                token(c -> c.subject(other).jwtID("c")))).as("another subject of the same issuer").isTrue();
    }
}
