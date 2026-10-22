// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.token;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import dev.tessera.iam.adapter.rest.config.ClientAssertionConfig;
import io.quarkus.runtime.Startup;
import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.Vertx;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.InputStream;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * The key sets of trusted external issuers ({@link ClientAssertionConfig#trustedIssuers()}),
 * fetched by their configured URL and cached.
 *
 * <p><strong>Fetching.</strong> Over {@code https} only, with the JDK's trust store and host-name
 * check, no redirects, a 2-second connect and 5-second request timeout, and a body of at most
 * 64 KiB. The host must resolve only to public addresses: loopback, private, link-local, unique-local,
 * shared (CGNAT) and multicast targets are refused. The URL is operator configuration, never taken
 * from a request or from issuer metadata. A key set is accepted only when it parses, holds 1 to 20
 * keys and none with private or symmetric material.
 *
 * <p><strong>Caching, failing closed.</strong> A key set is used for
 * {@link ClientAssertionConfig#jwksCacheTtl()}. A caller that met an unknown {@code kid} may ask
 * for a refresh, honoured at most once per {@link ClientAssertionConfig#jwksMinRefreshInterval()}
 * per issuer, which is also the pause after a failed fetch. When the issuer cannot be reached the
 * cached set is used only until it expires; after that there are no keys, so every assertion from
 * that issuer is refused. An untrusted issuer has no keys.
 *
 * <p><strong>Known limit.</strong> The address check resolves the host before the connection, which
 * resolves it again, so a host that changes its answer in between could reach a refused address.
 * The URLs come from configuration, which bounds that to an operator's own mistake or a hostile DNS.
 *
 * <p>The configuration is checked at startup ({@link Startup}).
 */
@Startup
@Singleton
public class TrustedIssuerJwks {

    static final int MAX_BYTES = 64 * 1024;
    static final int MAX_KEYS = 20;

    /** Fetches a URL. */
    interface Transport {
        Response get(URI uri) throws Exception;

        record Response(int status, InputStream body) {
        }
    }

    /** Resolves a host name. */
    interface Resolver {
        InetAddress[] resolve(String host) throws Exception;
    }

    private final Supplier<Instant> clock;
    private final Vertx vertx;
    private final Map<String, URI> jwksUriByIssuer;
    private final Duration ttl;
    private final Duration minRefreshInterval;
    private final Transport transport;
    private final Resolver resolver;
    private final ConcurrentMap<URI, Cached> cache = new ConcurrentHashMap<>();
    private final ConcurrentMap<URI, Instant> lastAttempt = new ConcurrentHashMap<>();

    @Inject
    public TrustedIssuerJwks(Vertx vertx, Clock clock, ClientAssertionConfig config) {
        this(vertx, clock::instant,
                config.trustedIssuers().values().stream().collect(Collectors.toMap(
                        ClientAssertionConfig.TrustedIssuer::issuer, ClientAssertionConfig.TrustedIssuer::jwksUri)),
                config.jwksCacheTtl(), config.jwksMinRefreshInterval(), https(), InetAddress::getAllByName);
    }

    TrustedIssuerJwks(Vertx vertx, Supplier<Instant> clock, Map<String, String> jwksUriByIssuer, Duration ttl,
            Duration minRefreshInterval, Transport transport, Resolver resolver) {
        if (ttl == null || !ttl.isPositive() || minRefreshInterval == null || minRefreshInterval.isNegative()) {
            throw new IllegalArgumentException(
                    "iam.client-assertion.jwks-cache-ttl must be positive and jwks-min-refresh-interval not negative");
        }
        Map<String, URI> uris = new HashMap<>();
        jwksUriByIssuer.forEach((issuer, jwksUri) -> uris.put(requireHttps("issuer", issuer),
                URI.create(requireHttps("jwks-uri", jwksUri))));
        this.vertx = vertx;
        this.clock = clock;
        this.jwksUriByIssuer = Map.copyOf(uris);
        this.ttl = ttl;
        this.minRefreshInterval = minRefreshInterval;
        this.transport = transport;
        this.resolver = resolver;
    }

    /**
     * @param issuer  the {@code iss} of an assertion
     * @param refresh whether the caller met a {@code kid} the cached set does not hold
     * @return the issuer's public JWK Set JSON, or {@code null} when it is not trusted or no
     *         unexpired key set can be had
     */
    public Uni<String> jwksFor(String issuer, boolean refresh) {
        // A fetch blocks: run it on a worker, never the event loop.
        return vertx.executeBlocking(() -> jwksNow(issuer, refresh), false);
    }

    String jwksNow(String issuer, boolean refresh) {
        URI uri = issuer == null ? null : jwksUriByIssuer.get(issuer);
        if (uri == null) {
            return null;
        }
        Instant now = clock.get();
        Cached cached = cache.get(uri);
        boolean fresh = cached != null && now.isBefore(cached.fetchedAt().plus(ttl));
        if ((fresh && !refresh) || !mayAttempt(uri, now)) {
            return fresh ? cached.jwks() : null;
        }
        String fetched = fetch(uri);
        if (fetched == null) {
            return fresh ? cached.jwks() : null;
        }
        cache.put(uri, new Cached(fetched, now));
        return fetched;
    }

    /** At most one fetch per issuer per interval, successful or not. */
    private boolean mayAttempt(URI uri, Instant now) {
        Instant previous = lastAttempt.get(uri);
        if (previous != null && now.isBefore(previous.plus(minRefreshInterval))) {
            return false;
        }
        return previous == null ? lastAttempt.putIfAbsent(uri, now) == null : lastAttempt.replace(uri, previous, now);
    }

    private String fetch(URI uri) {
        try {
            for (InetAddress address : resolver.resolve(uri.getHost())) {
                if (!isPublic(address)) {
                    return null;
                }
            }
            Transport.Response response = transport.get(uri);
            try (InputStream body = response.body()) {
                if (response.status() != 200 || body == null) {
                    return null;
                }
                byte[] bytes = body.readNBytes(MAX_BYTES + 1);
                if (bytes.length > MAX_BYTES) {
                    return null;
                }
                JWKSet set = JWKSet.parse(new String(bytes, StandardCharsets.UTF_8));
                if (set.getKeys().isEmpty() || set.getKeys().size() > MAX_KEYS
                        || set.getKeys().stream().anyMatch(JWK::isPrivate)) {
                    return null;
                }
                return set.toString();
            }
        } catch (Exception unreachableOrMalformed) {
            return null;
        }
    }

    static boolean isPublic(InetAddress address) {
        byte[] raw = address.getAddress();
        boolean uniqueLocal = address instanceof Inet6Address && (raw[0] & 0xfe) == 0xfc;
        boolean sharedCgnat = raw.length == 4 && (raw[0] & 0xff) == 100 && (raw[1] & 0xc0) == 64;
        return !(address.isAnyLocalAddress() || address.isLoopbackAddress() || address.isLinkLocalAddress()
                || address.isSiteLocalAddress() || address.isMulticastAddress() || uniqueLocal || sharedCgnat);
    }

    private static String requireHttps(String name, String value) {
        URI uri;
        try {
            uri = value == null ? null : URI.create(value);
        } catch (IllegalArgumentException malformed) {
            uri = null;
        }
        if (uri == null || !"https".equals(uri.getScheme()) || uri.getHost() == null
                || uri.getRawUserInfo() != null || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("iam.client-assertion.trusted-issuers.*." + name
                    + " must be an https URL with a host and no user info or fragment, was " + value);
        }
        return value;
    }

    private static Transport https() {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(2))
                .build();
        return uri -> {
            HttpResponse<InputStream> response = client.send(
                    HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).header("Accept", "application/json")
                            .GET().build(),
                    HttpResponse.BodyHandlers.ofInputStream());
            return new Transport.Response(response.statusCode(), response.body());
        };
    }

    private record Cached(String jwks, Instant fetchedAt) {
    }
}
