// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
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
        return new TrustedIssuerJwks.Transport.Response(200, body.getBytes(StandardCharsets.UTF_8));
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
                "::1", "fd00::1", "fe80::1", "0.0.0.0", "0.0.0.1", "192.0.0.192", "198.18.0.1", "240.0.0.1",
                "255.255.255.255", "64:ff9b::a9fe:a9fe", "64:ff9b::a00:1", "64:ff9b:1::1", "::127.0.0.1",
                "::a9fe:a9fe", "2002:7f00:1::1"}) {
            addresses = new InetAddress[] {address("203.0.113.7"), address(target)};
            TrustedIssuerJwks fresh = new TrustedIssuerJwks(null, clock, Map.of(ISSUER, JWKS_URI), TTL,
                    MIN_REFRESH, uri -> {
                        fetches.incrementAndGet();
                        return response.get();
                    }, host -> addresses);
            assertThat(fresh.jwksNow(ISSUER, false)).as(target).isNull();
        }
        assertThat(fetches).hasValue(0);
        for (String target : new String[] {"203.0.113.7", "2606:4700::1111", "64:ff9b::cb00:7107", "2002:cb00:7107::1"}) {
            assertThat(TrustedIssuerJwks.isPublic(address(target))).as(target).isTrue();
        }
    }

    @Test
    @DisplayName("one deadline covers the whole exchange: a server that trickles its body is cut off")
    void slowDripIsCutOffAtTheDeadline() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.createContext("/drip", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            try (OutputStream body = exchange.getResponseBody()) {
                for (int i = 0; i < 40; i++) {
                    body.write('{');
                    body.flush();
                    Thread.sleep(200);
                }
            } catch (IOException | InterruptedException clientGone) {
                // The client gave up, as it should.
            }
        });
        server.createContext("/large", exchange -> {
            byte[] large = new byte[TrustedIssuerJwks.MAX_BYTES + 1];
            exchange.sendResponseHeaders(200, large.length);
            try (OutputStream body = exchange.getResponseBody()) {
                body.write(large);
            } catch (IOException clientGone) {
                // The client stopped reading at the limit.
            }
        });
        server.start();
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            TrustedIssuerJwks.Transport transport = TrustedIssuerJwks.https(Duration.ofSeconds(1));
            long started = System.nanoTime();
            assertThatThrownBy(() -> transport.get(URI.create(base + "/drip")))
                    .isInstanceOf(java.util.concurrent.TimeoutException.class);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(3));
            assertThatThrownBy(() -> transport.get(URI.create(base + "/large"))).isNotNull();
        } finally {
            server.stop(0);
        }
    }

    @Test
    @DisplayName("a non-200 answer, an oversized body, private or symmetric keys and malformed JSON are refused")
    void badKeySetsAreRefused() {
        Map<String, Supplier<TrustedIssuerJwks.Transport.Response>> bad = Map.of(
                "redirect", () -> new TrustedIssuerJwks.Transport.Response(302, new byte[0]),
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
        for (Duration refresh : new Duration[] {Duration.ZERO, Duration.ofSeconds(4), TTL}) {
            assertThatThrownBy(() -> new TrustedIssuerJwks(null, clock, Map.of(), TTL, refresh, null, null))
                    .as(refresh.toString())
                    .hasMessageContaining("jwks-min-refresh-interval");
        }
    }
}
