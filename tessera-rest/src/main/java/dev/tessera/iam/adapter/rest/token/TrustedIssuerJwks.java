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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.jboss.logging.Logger;

/**
 * The key sets of trusted external issuers ({@link ClientAssertionConfig#trustedIssuers()}),
 * fetched by their configured URL and cached.
 *
 * <p><strong>Fetching.</strong> Over {@code https} only, with the JDK's trust store and host-name
 * check, no redirects, no proxy (the JVM's proxy settings are ignored), and one 5-second deadline
 * over the whole exchange, body included, so a server that trickles its answer cannot hold a
 * worker; the body is limited to 64 KiB while it streams. The host must resolve only to public
 * addresses: loopback, private, link-local, unique-local, shared (CGNAT), benchmarking, reserved,
 * broadcast and multicast targets are refused, also when embedded in an IPv6 address (NAT64,
 * 6to4, IPv4-compatible). The URL is operator configuration, never taken from a request or from
 * issuer metadata. A key set is accepted only when it parses, holds 1 to 20 keys and none with
 * private or symmetric material. A failed fetch is logged with the issuer and the kind of failure,
 * never the response body.
 *
 * <p><strong>Caching, failing closed.</strong> A key set is used for
 * {@link ClientAssertionConfig#jwksCacheTtl()}. A caller that met an unknown {@code kid} may ask
 * for a refresh, honoured at most once per {@link ClientAssertionConfig#jwksMinRefreshInterval()}
 * per issuer, which is also the pause after a failed fetch. When the issuer cannot be reached the
 * cached set is used only until it expires; after that there are no keys, so every assertion from
 * that issuer is refused. An untrusted issuer has no keys.
 *
 * <p><strong>Known limit.</strong> The address check resolves the host before the connection, which
 * resolves it again; only the JVM's positive DNS cache makes the two answers agree, so a host that
 * changes its answer in between could reach a refused address. The URLs come from configuration,
 * which bounds that to an operator's own mistake or a hostile DNS.
 *
 * <p>The configuration is checked at startup ({@link Startup}).
 */
@Startup
@Singleton
public class TrustedIssuerJwks {

    static final int MAX_BYTES = 64 * 1024;
    static final int MAX_KEYS = 20;
    static final Duration MIN_REFRESH_FLOOR = Duration.ofSeconds(5);
    private static final Duration DEADLINE = Duration.ofSeconds(5);
    private static final Logger LOG = Logger.getLogger(TrustedIssuerJwks.class);

    /** Fetches a URL, within its own deadline and size limit. */
    interface Transport {
        Response get(URI uri) throws Exception;

        record Response(int status, byte[] body) {
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
                config.jwksCacheTtl(), config.jwksMinRefreshInterval(), https(DEADLINE), InetAddress::getAllByName);
    }

    TrustedIssuerJwks(Vertx vertx, Supplier<Instant> clock, Map<String, String> jwksUriByIssuer, Duration ttl,
            Duration minRefreshInterval, Transport transport, Resolver resolver) {
        if (ttl == null || minRefreshInterval == null || minRefreshInterval.compareTo(MIN_REFRESH_FLOOR) < 0
                || minRefreshInterval.compareTo(ttl) >= 0) {
            throw new IllegalArgumentException("iam.client-assertion.jwks-min-refresh-interval must be at least "
                    + MIN_REFRESH_FLOOR + " and shorter than jwks-cache-ttl, were " + minRefreshInterval + " and " + ttl);
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
        String fetched = fetch(issuer, uri);
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

    private String fetch(String issuer, URI uri) {
        try {
            for (InetAddress address : resolver.resolve(uri.getHost())) {
                if (!isPublic(address)) {
                    return failed(issuer, "a non-public address");
                }
            }
            Transport.Response response = transport.get(uri);
            if (response.status() != 200 || response.body() == null || response.body().length > MAX_BYTES) {
                return failed(issuer, "HTTP status " + response.status());
            }
            JWKSet set = JWKSet.parse(new String(response.body(), StandardCharsets.UTF_8));
            if (set.getKeys().isEmpty() || set.getKeys().size() > MAX_KEYS
                    || set.getKeys().stream().anyMatch(JWK::isPrivate)) {
                return failed(issuer, "an unacceptable key set");
            }
            return set.toString();
        } catch (Exception unreachableOrMalformed) {
            Throwable cause = unreachableOrMalformed instanceof ExecutionException && unreachableOrMalformed.getCause() != null
                    ? unreachableOrMalformed.getCause() : unreachableOrMalformed;
            return failed(issuer, cause.getClass().getSimpleName());
        }
    }

    private static String failed(String issuer, String failure) {
        LOG.warnf("trusted issuer %s: key set not fetched: %s", issuer, failure);
        return null;
    }

    static boolean isPublic(InetAddress address) {
        byte[] a = address.getAddress();
        return a.length == 4 ? isPublicIpv4(a, 0) : isPublicIpv6(a);
    }

    private static boolean isPublicIpv4(byte[] a, int at) {
        int b0 = a[at] & 0xff;
        int b1 = a[at + 1] & 0xff;
        return !(b0 == 0 || b0 == 10 || b0 == 127 || b0 >= 224                // this net, private, loopback, multicast, reserved, broadcast
                || (b0 == 100 && (b1 & 0xc0) == 64) || (b0 == 169 && b1 == 254)   // shared (CGNAT), link-local
                || (b0 == 172 && (b1 & 0xf0) == 16) || (b0 == 192 && b1 == 168)   // private
                || (b0 == 192 && b1 == 0 && a[at + 2] == 0)                      // IETF protocol assignments
                || (b0 == 198 && (b1 & 0xfe) == 18));                            // benchmarking
    }

    private static boolean isPublicIpv6(byte[] a) {
        int b0 = a[0] & 0xff;
        int b1 = a[1] & 0xff;
        if (b0 == 0xff || (b0 & 0xfe) == 0xfc || (b0 == 0xfe && (b1 & 0x80) == 0x80)) {
            return false;                                                        // multicast, unique-local, link- and site-local
        }
        if (zeros(a, 0, 10) && (zeros(a, 10, 12) || ((a[10] & a[11]) == (byte) 0xff))) {
            return isPublicIpv4(a, 12);                                          // ::, ::1, IPv4-compatible, IPv4-mapped
        }
        if (b0 == 0 && b1 == 0x64 && (a[2] & 0xff) == 0xff && (a[3] & 0xff) == 0x9b) {
            return zeros(a, 4, 12) && isPublicIpv4(a, 12);                        // NAT64 64:ff9b::/96; 64:ff9b:1::/48 is local
        }
        return b0 != 0x20 || b1 != 0x02 || isPublicIpv4(a, 2);                    // 6to4 2002::/16
    }

    private static boolean zeros(byte[] a, int from, int to) {
        for (int i = from; i < to; i++) {
            if (a[i] != 0) {
                return false;
            }
        }
        return true;
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

    /** One deadline over connection, headers and body; the body is limited while it streams. */
    static Transport https(Duration deadline) {
        HttpClient client = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(HttpClient.Builder.NO_PROXY)
                .connectTimeout(deadline)
                .build();
        return uri -> {
            CompletableFuture<HttpResponse<byte[]>> exchange = client.sendAsync(
                    HttpRequest.newBuilder(uri).timeout(deadline).header("Accept", "application/json").GET().build(),
                    HttpResponse.BodyHandlers.limiting(HttpResponse.BodyHandlers.ofByteArray(), MAX_BYTES));
            try {
                HttpResponse<byte[]> response = exchange.get(deadline.toMillis(), TimeUnit.MILLISECONDS);
                return new Transport.Response(response.statusCode(), response.body());
            } catch (TimeoutException | InterruptedException stopped) {
                exchange.cancel(true);
                throw stopped;
            }
        };
    }

    private record Cached(String jwks, Instant fetchedAt) {
    }
}
