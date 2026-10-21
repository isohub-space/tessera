package dev.tessera.iam.launcher.edge;

import static org.assertj.core.api.Assertions.assertThat;

import io.vertx.core.http.impl.HttpUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The path matcher, fed the way the filter feeds it: the raw path goes through Vert.x's own
 * normalization first, as {@code RoutingContext.normalizedPath()} does.
 */
@DisplayName("AuthorizeCorsExclusion — which paths count as the authorization endpoint")
class AuthorizeCorsExclusionTest {

    private static boolean matches(String rawPath) {
        return AuthorizeCorsExclusion.isAuthorizeEndpoint(HttpUtils.normalizePath(rawPath));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
        "/authorize", "/authorize/", "//authorize", "/%61uthorize", "/x/../authorize", "/./authorize",
        "/authorize;x=1", "/authorize;x=1/", "/authorize;x=1;y=2", "/authorize/;x=1", "/authorize%3Bx=1",
        "/realms/r1/authorize", "/realms;v=1/r1/authorize;x=1",
        // An encoded '/' inside a matrix value stays inside its segment, as it does for the router.
        "/authorize;x=%2Fy", "/authorize;x=a%2Fb", "/authorize;x=%2F..", "/authorize;%2F..",
        "/authorize;x=%2e%2e%2Fy", "/authorize;x=+%2Fy",
        // With a ';' the router rebuilds the path from decoded names: authorize%2F becomes authorize/.
        "/authorize%2F;x=1", "/authorize%2F;x=1/", "/x%2Fauthorize;x=1"
    })
    @DisplayName("every shape that can route to /authorize matches")
    void authorizeShapesMatch(String rawPath) {
        assertThat(matches(rawPath)).isTrue();
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
        "/", "/token", "/introspect", "/revoke", "/q/health", "/authorizex", "/xauthorize", "/authorize/x",
        "/authorize;x=1/token", "/.well-known/openid-configuration",
        // Double encoding is decoded once by the router too, so these do not route to /authorize.
        "/authorize%253Bx=1", "/authoriz%2565"
    })
    @DisplayName("other endpoints do not match")
    void otherPathsDoNotMatch(String rawPath) {
        assertThat(matches(rawPath)).isFalse();
    }
}
