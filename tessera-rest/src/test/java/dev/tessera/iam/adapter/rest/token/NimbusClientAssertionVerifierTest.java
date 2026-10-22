// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyOperation;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import dev.tessera.iam.adapter.rest.support.AssertionTestClient;
import dev.tessera.iam.application.port.out.ClientKeySourcePort.AssertionTrust;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("NimbusClientAssertionVerifier — RFC 7523 client assertion checks, all fail-closed")
class NimbusClientAssertionVerifierTest {

    private static final String ISSUER = "https://issuer.example";
    private static final String CLIENT = "keyed-service";
    private static final Instant NOW = Instant.parse("2026-10-22T10:00:00Z");
    private static final RealmKey REALM = new RealmKey(TenantId.generate(), BaselineId.generate());

    private final AssertionTestClient client = new AssertionTestClient();
    private final AssertionTrust trust = new AssertionTrust(CLIENT, CLIENT, client.jwks());
    private final NimbusClientAssertionVerifier verifier = verifier(1000, 1000, 1000);

    private static NimbusClientAssertionVerifier verifier(int maxPerClient, int maxPerRealm, int maxTotal) {
        return new NimbusClientAssertionVerifier(null, null, ISSUER, Duration.ofMinutes(5), Duration.ofSeconds(30),
                new AssertionReplayStore(maxPerClient, maxPerRealm, maxTotal));
    }

    private boolean verify(String assertion) {
        return verifier.verifyNow(REALM, trust, assertion, NOW);
    }

    private String signed(UnaryOperator<JWTClaimsSet.Builder> claims) {
        return client.sign(claims.apply(AssertionTestClient.claims(CLIENT, ISSUER, NOW)).build());
    }

    @Test
    @DisplayName("a valid assertion verifies, with the issuer as audience")
    void validAssertionVerifies() {
        assertThat(verify(signed(c -> c))).isTrue();
        assertThat(verify(signed(c -> c.issueTime(null)))).isTrue();
    }

    @Test
    @DisplayName("each claim violation is refused")
    void eachClaimViolationIsRefused() {
        Map<String, UnaryOperator<JWTClaimsSet.Builder>> violations = Map.of(
                "wrong sub", c -> c.subject("other-client"),
                "wrong iss", c -> c.issuer("other-client"),
                "wrong aud", c -> c.audience("https://elsewhere.example"),
                "token endpoint as aud", c -> c.audience(ISSUER + "/token"),
                "extra aud", c -> c.audience(java.util.List.of(ISSUER, "https://elsewhere.example")),
                "expired", c -> c.issueTime(Date.from(NOW.minusSeconds(300))).expirationTime(Date.from(NOW.minusSeconds(31))),
                "nbf in the future", c -> c.notBeforeTime(Date.from(NOW.plusSeconds(60))),
                "iat in the future", c -> c.issueTime(Date.from(NOW.plusSeconds(60))),
                "over-long lifetime", c -> c.expirationTime(Date.from(NOW.plus(Duration.ofMinutes(6)))),
                "no exp", c -> c.expirationTime(null));
        violations.forEach((name, violation) -> assertThat(verify(signed(violation))).as(name).isFalse());
        assertThat(verify(signed(c -> c.jwtID(null)))).as("no jti").isFalse();
    }

    @Test
    @DisplayName("a replayed jti is refused within the assertion's lifetime")
    void replayedJtiIsRefused() {
        String assertion = signed(c -> c.jwtID("once"));
        assertThat(verify(assertion)).isTrue();
        assertThat(verify(assertion)).isFalse();
        assertThat(verify(signed(c -> c.jwtID("once")))).isFalse();
    }

    @Test
    @DisplayName("a client at its jti cap refuses only itself, never another tenant's client")
    void replayCapIsPerClient() {
        NimbusClientAssertionVerifier capped = verifier(2, 100, 100);
        RealmKey otherTenant = new RealmKey(TenantId.generate(), BaselineId.generate());
        assertThat(capped.verifyNow(REALM, trust, signed(c -> c), NOW)).isTrue();
        assertThat(capped.verifyNow(REALM, trust, signed(c -> c), NOW)).isTrue();
        assertThat(capped.verifyNow(REALM, trust, signed(c -> c), NOW)).as("the same client, over its cap").isFalse();
        assertThat(capped.verifyNow(otherTenant, trust, signed(c -> c), NOW)).as("another tenant's client").isTrue();
        Instant later = NOW.plus(Duration.ofMinutes(2));
        assertThat(capped.verifyNow(REALM, trust,
                client.sign(AssertionTestClient.claims(CLIENT, ISSUER, later).build()), later))
                .as("after its entries expire").isTrue();
    }

    @Test
    @DisplayName("a realm at its jti cap across many clients refuses only itself, never another realm's client")
    void replayCapIsPerRealm() {
        NimbusClientAssertionVerifier capped = verifier(2, 4, 100);
        RealmKey otherRealm = new RealmKey(TenantId.generate(), BaselineId.generate());
        for (int i = 0; i < 4; i++) {
            String clientId = "client-" + (i / 2);
            assertThat(capped.verifyNow(REALM, trustFor(clientId), signedBy(clientId), NOW)).as("fill " + i).isTrue();
        }
        assertThat(capped.verifyNow(REALM, trustFor("client-9"), signedBy("client-9"), NOW))
                .as("a fresh client of the full realm").isFalse();
        assertThat(capped.verifyNow(otherRealm, trustFor("client-9"), signedBy("client-9"), NOW))
                .as("a client of another realm").isTrue();
    }

    private AssertionTrust trustFor(String clientId) {
        return new AssertionTrust(clientId, clientId, client.jwks());
    }

    private String signedBy(String clientId) {
        return client.sign(AssertionTestClient.claims(clientId, ISSUER, NOW).build());
    }

    @Test
    @DisplayName("a key not meant for verification, and an RSA key over 4096 bits, are refused")
    void unfitKeysAreRefused() throws Exception {
        ECKey encryptOnly = new ECKey.Builder(JWKSet.parse(client.jwks()).getKeys().get(0).toECKey())
                .keyOperations(Set.of(KeyOperation.ENCRYPT)).build();
        AssertionTrust encryptTrust = new AssertionTrust(CLIENT, CLIENT, new JWKSet(encryptOnly).toString());
        assertThat(verifier.verifyNow(REALM, encryptTrust, signed(c -> c), NOW)).as("key_ops=encrypt").isFalse();

        RSAKey large = new RSAKeyGenerator(4608).keyID(AssertionTestClient.KID).generate();
        SignedJWT rs256 = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(AssertionTestClient.KID).build(),
                AssertionTestClient.claims(CLIENT, ISSUER, NOW).build());
        rs256.sign(new RSASSASigner(large));
        AssertionTrust largeTrust = new AssertionTrust(CLIENT, CLIENT, new JWKSet(large.toPublicJWK()).toString());
        assertThat(verifier.verifyNow(REALM, largeTrust, rs256.serialize(), NOW)).as("RSA 4608").isFalse();
    }

    @Test
    @DisplayName("alg=none, an HMAC alg and an unknown kid are refused")
    void algorithmAndKeyViolationsAreRefused() throws Exception {
        JWTClaimsSet claims = AssertionTestClient.claims(CLIENT, ISSUER, NOW).build();
        assertThat(verify(new PlainJWT(claims).serialize())).as("none").isFalse();

        SignedJWT hmac = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID(AssertionTestClient.KID).build(),
                claims);
        hmac.sign(new MACSigner(client.jwks().repeat(2).getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertThat(verify(hmac.serialize())).as("HS256").isFalse();

        assertThat(verify(client.sign(claims, h -> h.keyID("unknown-kid")))).as("unknown kid").isFalse();
    }

    @Test
    @DisplayName("a key the client did not register, and no trust at all, are refused")
    void untrustedKeysAreRefused() {
        String foreign = new AssertionTestClient().sign(AssertionTestClient.claims(CLIENT, ISSUER, NOW).build());
        assertThat(verify(foreign)).isFalse();
        assertThat(verifier.verifyNow(REALM, null, signed(c -> c), NOW)).isFalse();
        assertThat(verify("not-a-jwt")).isFalse();
    }
}
