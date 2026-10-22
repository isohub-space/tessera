// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("TrustedIssuerJwks — external issuer key sets over https, cached, failing closed")
class TrustedIssuerJwksTest {

    private static final String ISSUER = "https://issuer.example";
    private static final String JWKS_URI = "https://keys.example/jwks";
    private static final Duration TTL = Duration.ofMinutes(10);
    private static final Duration MIN_REFRESH = Duration.ofSeconds(30);

    private final AtomicReference<Instant> now = new AtomicReference<>(Instant.parse("2026-10-23T10:00:00Z"));
    private final AtomicInteger fetches = new AtomicInteger();
    private final ECKey key = generate();
    private Supplier<TrustedIssuerJwks.Transport.Response> response = () -> ok(new JWKSet(key.toPublicJWK()).toString());
    private InetAddress[] addresses = {address("203.0.113.7")};

    private final Supplier<Instant> clock = now::get;

    private final TrustedIssuerJwks jwks = new TrustedIssuerJwks(null, clock, Map.of(ISSUER, JWKS_URI), TTL,
            MIN_REFRESH, uri -> {
                fetches.incrementAndGet();
                assertThat(uri.toString()).isEqualTo(JWKS_URI);
                return response.get();
            }, host -> addresses);

    private static ECKey generate() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID("k1").generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static InetAddress address(String literal) {
        try {
            return InetAddress.getByName(literal);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static TrustedIssuerJwks.Transport.Response ok(String body) {
        return new TrustedIssuerJwks.Transport.Response(200,
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
    }

    private void advance(Duration by) {
        now.set(now.get().plus(by));
    }

    @Test
    @DisplayName("a trusted issuer's public key set is fetched once and served from cache until it expires")
    void fetchesAndCaches() throws Exception {
        String first = jwks.jwksNow(ISSUER, false);
        assertThat(JWKSet.parse(first).getKeyByKeyId("k1")).isNotNull();
        assertThat(jwks.jwksNow(ISSUER, false)).isEqualTo(first);
        assertThat(fetches).hasValue(1);

        advance(TTL);
        assertThat(jwks.jwksNow(ISSUER, false)).isEqualTo(first);
        assertThat(fetches).hasValue(2);
    }

    @Test
    @DisplayName("an untrusted issuer has no keys and causes no fetch")
    void untrustedIssuerHasNoKeys() {
        assertThat(jwks.jwksNow("https://other.example", false)).isNull();
        assertThat(jwks.jwksNow(null, false)).isNull();
        assertThat(fetches).hasValue(0);
    }

    @Test
    @DisplayName("a refresh for an unknown kid is honoured at most once per interval")
    void refreshIsRateLimited() {
        jwks.jwksNow(ISSUER, false);
        assertThat(jwks.jwksNow(ISSUER, true)).isNotNull();
        assertThat(fetches).hasValue(1);
        advance(MIN_REFRESH);
        jwks.jwksNow(ISSUER, true);
        assertThat(fetches).hasValue(2);
    }

    @Test
    @DisplayName("an unreachable issuer keeps its cached keys only until they expire, then fails closed")
    void unreachableIssuerFailsClosed() {
        String cached = jwks.jwksNow(ISSUER, false);
        response = () -> {
            throw new IllegalStateException("connection refused");
        };
        advance(MIN_REFRESH);
        assertThat(jwks.jwksNow(ISSUER, true)).isEqualTo(cached);
        advance(TTL);
        assertThat(jwks.jwksNow(ISSUER, false)).isNull();
        assertThat(jwks.jwksNow(ISSUER, false)).as("no retry before the interval").isNull();
        assertThat(fetches).hasValue(3);
    }

    @Test
    @DisplayName("private, loopback and link-local targets are refused without a request")
    void nonPublicTargetsAreRefused() {
        for (String target : new String[] {"127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
                "::1", "fd00::1", "fe80::1", "0.0.0.0"}) {
            addresses = new InetAddress[] {address("203.0.113.7"), address(target)};
            TrustedIssuerJwks fresh = new TrustedIssuerJwks(null, clock, Map.of(ISSUER, JWKS_URI), TTL,
                    MIN_REFRESH, uri -> {
                        fetches.incrementAndGet();
                        return response.get();
                    }, host -> addresses);
            assertThat(fresh.jwksNow(ISSUER, false)).as(target).isNull();
        }
        assertThat(fetches).hasValue(0);
    }

    @Test
    @DisplayName("a non-200 answer, an oversized body, private or symmetric keys and malformed JSON are refused")
    void badKeySetsAreRefused() {
        Map<String, Supplier<TrustedIssuerJwks.Transport.Response>> bad = Map.of(
                "redirect", () -> new TrustedIssuerJwks.Transport.Response(302, new ByteArrayInputStream(new byte[0])),
                "oversized", () -> ok("{\"keys\":[],\"pad\":\"" + "x".repeat(TrustedIssuerJwks.MAX_BYTES) + "\"}"),
                "private key", () -> ok(new JWKSet(key).toString(false)),
                "symmetric key", () -> ok("{\"keys\":[{\"kty\":\"oct\",\"k\":\"c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0\"}]}"),
                "no keys", () -> ok("{\"keys\":[]}"),
                "malformed", () -> ok("not json"));
        bad.forEach((name, answer) -> {
            response = answer;
            advance(MIN_REFRESH);
            assertThat(jwks.jwksNow(ISSUER, false)).as(name).isNull();
        });
    }

    @Test
    @DisplayName("a trusted issuer or key-set URL that is not https is refused at startup")
    void configurationIsCheckedAtStartup() {
        assertThat(TrustedIssuerJwks.class).hasAnnotation(io.quarkus.runtime.Startup.class);
        for (Map<String, String> config : java.util.List.of(
                Map.of(ISSUER, "http://keys.example/jwks"),
                Map.of("http://issuer.example", JWKS_URI),
                Map.of(ISSUER, "https://user@keys.example/jwks"),
                Map.of(ISSUER, "not a url"))) {
            assertThatThrownBy(() -> new TrustedIssuerJwks(null, clock, config, TTL, MIN_REFRESH, null, null))
                    .as(config.toString())
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("iam.client-assertion.trusted-issuers");
        }
    }
}
