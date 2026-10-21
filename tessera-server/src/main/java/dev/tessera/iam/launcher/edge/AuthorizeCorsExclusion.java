package dev.tessera.iam.launcher.edge;

import io.quarkus.vertx.http.runtime.filters.Filters;
import io.vertx.core.MultiMap;
import io.vertx.ext.web.RoutingContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
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
 * response itself, so the strip is in place before any CORS header can be written. The match is
 * on the router's normalized path and covers a trailing slash and any realm-scoped
 * {@code …/authorize} route.
 */
@ApplicationScoped
public class AuthorizeCorsExclusion {

    /** Above the Quarkus CORS filter's priority (300): a higher priority runs first. */
    static final int PRIORITY = 310;

    private static final String AUTHORIZE_SEGMENT = "/authorize";

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

    static boolean isAuthorizeEndpoint(String path) {
        if (path == null) {
            return false;
        }
        String trimmed = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        return trimmed.endsWith(AUTHORIZE_SEGMENT);
    }
}
