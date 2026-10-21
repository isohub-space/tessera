package dev.tessera.iam.launcher.edge;

import io.quarkus.vertx.http.runtime.filters.Filters;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import java.util.ArrayList;
import java.util.List;
import org.jboss.resteasy.reactive.common.util.Encode;
import org.jboss.resteasy.reactive.common.util.PathSegmentImpl;

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
 * <p>The match is computed in two steps so it cannot be narrower than the routing:
 *
 * <ol>
 *   <li>The path the router actually matches is rebuilt with Quarkus REST's own code, the way
 *       {@code ResteasyReactiveRequestContext.initPathSegments} does it: the router's normalized
 *       path is split on {@code /}, each segment is parsed by {@link PathSegmentImpl} (matrix
 *       parameters cut, the name decoded by {@link Encode#decodePath}), and when any segment
 *       carried matrix parameters the path is rebuilt from the decoded names. So
 *       {@code /authorize;x=1} and {@code /authorize%2F;x=1} both become routable paths here
 *       exactly as they do for the router.</li>
 *   <li>That path is then matched widely: each segment is cut at {@code ;}, decoded, split on
 *       {@code /} again and cut at {@code ;} again, empty names are dropped, and the path matches
 *       when the last name is {@code authorize}. This also covers a trailing slash, a doubled
 *       slash and any realm-scoped {@code …/authorize} route.</li>
 * </ol>
 *
 * <p>Erring toward a match only removes CORS headers a path never needed; missing one would open
 * the endpoint.
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
        String lastName = null;
        for (String rawSegment : routedPath(normalizedPath).split("/")) {
            for (String piece : decode(cutMatrix(rawSegment)).split("/")) {
                String name = cutMatrix(piece);
                if (!name.isEmpty()) {
                    lastName = name;
                }
            }
        }
        return AUTHORIZE_SEGMENT.equals(lastName);
    }

    /**
     * The path Quarkus REST routes on, rebuilt with its own segment parsing: unchanged unless a
     * segment carries matrix parameters, then {@code /}-joined decoded segment names, keeping a
     * trailing slash.
     */
    static String routedPath(String normalizedPath) {
        List<PathSegmentImpl> segments = new ArrayList<>();
        boolean matrix = false;
        try {
            for (String segment : normalizedPath.split("/")) {
                if (segment.isEmpty()) {
                    continue;
                }
                PathSegmentImpl parsed = new PathSegmentImpl(segment, true);
                matrix |= parsed.hasMatrixParams();
                segments.add(parsed);
            }
        } catch (RuntimeException unparseable) {
            // The router cannot parse it either; the wide match below still applies.
            return normalizedPath;
        }
        if (!matrix) {
            return normalizedPath;
        }
        StringBuilder rebuilt = new StringBuilder();
        for (PathSegmentImpl segment : segments) {
            rebuilt.append('/').append(segment.getPath());
        }
        if (normalizedPath.endsWith("/")) {
            rebuilt.append('/');
        }
        return rebuilt.toString();
    }

    private static String cutMatrix(String segment) {
        int matrix = segment.indexOf(';');
        return matrix < 0 ? segment : segment.substring(0, matrix);
    }

    private static String decode(String segment) {
        try {
            return Encode.decodePath(segment);
        } catch (RuntimeException malformed) {
            return segment;
        }
    }
}
