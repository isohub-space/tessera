package dev.tessera.iam.launcher.edge;

import io.quarkus.vertx.http.runtime.filters.Filters;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Keeps the authorization endpoint outside the CORS policy (RFC 9700 §2.6).
 *
 * <p>The Quarkus CORS policy ({@code quarkus.http.cors.*}) is global: once an operator lists an
 * origin in {@code TESSERA_CORS_ORIGINS} so a relying party's page can call {@code /login} or
 * the token endpoints, the same origin would also be allowed to read {@code /authorize}. That
 * endpoint is reached only by top-level browser navigation, so it never needs CORS, and RFC 9700
 * says it must not answer cross-origin requests. Here, every {@code Access-Control-*} header is
 * stripped from a response to {@code /authorize} just before it is written, so neither a
 * preflight nor an actual request from a listed origin is ever allowed. Everything else about
 * the CORS policy is unchanged: an unlisted origin is still refused by the CORS filter, and the
 * other endpoints keep the configured allow-list.
 *
 * <p>Registered ahead of the CORS filter (priority 300), which answers a preflight and ends the
 * response itself, so the strip is in place before any CORS header can be written.
 *
 * <p>The match is deliberately wider than the routing: Quarkus REST strips matrix parameters
 * ({@code ;x=1}) from each segment before it routes, so {@code /authorize;x=1} reaches the
 * endpoint and must be matched too. The router's normalized path (dot segments resolved,
 * unreserved characters decoded) is percent-decoded, split into segments, each segment loses its
 * matrix parameters, empty segments are dropped, and the path matches when the last segment is
 * {@code authorize}. That also covers a trailing slash, a doubled slash and any realm-scoped
 * {@code …/authorize} route. Matching a path that is not really the endpoint only removes CORS
 * headers it never needed; missing one would open the endpoint.
 */
@ApplicationScoped
public class AuthorizeCorsExclusion {

    /** Above the Quarkus CORS filter's priority (300): a higher priority runs first. */
    static final int PRIORITY = 310;

    private static final String AUTHORIZE_SEGMENT = "authorize";

    private static final List<String> CORS_RESPONSE_HEADERS = List.of(
            "Access-Control-Allow-Origin",
            "Access-Control-Allow-Credentials",
            "Access-Control-Allow-Methods",
            "Access-Control-Allow-Headers",
            "Access-Control-Allow-Private-Network",
            "Access-Control-Expose-Headers",
            "Access-Control-Max-Age");

    void register(@Observes Filters filters) {
        filters.register(this::handle, PRIORITY);
    }

    void handle(RoutingContext ctx) {
        if (isAuthorizeEndpoint(ctx.normalizedPath())) {
            ctx.addHeadersEndHandler(v -> {
                MultiMap headers = ctx.response().headers();
                CORS_RESPONSE_HEADERS.forEach(headers::remove);
            });
        }
        ctx.next();
    }

    /**
     * @param normalizedPath the router's normalized request path
     * @return whether the path can route to the authorization endpoint
     */
    static boolean isAuthorizeEndpoint(String normalizedPath) {
        if (normalizedPath == null) {
            return false;
        }
        String lastSegment = null;
        for (String segment : percentDecode(normalizedPath).split("/")) {
            int matrix = segment.indexOf(';');
            String name = matrix < 0 ? segment : segment.substring(0, matrix);
            if (!name.isEmpty()) {
                lastSegment = name;
            }
        }
        return AUTHORIZE_SEGMENT.equals(lastSegment);
    }

    private static String percentDecode(String path) {
        try {
            // '+' is literal in a path; keep URLDecoder from turning it into a space.
            return URLDecoder.decode(path.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException malformed) {
            return path;
        }
    }
}
