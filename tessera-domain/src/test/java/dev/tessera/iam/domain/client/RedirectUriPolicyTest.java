package dev.tessera.iam.domain.client;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("RedirectUriPolicy — https only, loopback http and private-use schemes for public clients")
class RedirectUriPolicyTest {

    private static final boolean PUBLIC = true;
    private static final boolean CONFIDENTIAL = false;

    private static void assertAccepted(String uri, boolean publicClient) {
        assertThatCode(() -> RedirectUriPolicy.requireRegistrable(List.of(uri), publicClient))
                .doesNotThrowAnyException();
    }

    private static void assertRefused(String uri, boolean publicClient) {
        assertThatThrownBy(() -> RedirectUriPolicy.requireRegistrable(List.of(uri), publicClient))
                .isInstanceOfSatisfying(InvalidRedirectUriException.class, e -> {
                    org.assertj.core.api.Assertions.assertThat(e.error()).isEqualTo("invalid_redirect_uri");
                    org.assertj.core.api.Assertions.assertThat(e.redirectUri()).isEqualTo(uri);
                });
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"https://client.example/callback", "HTTPS://client.example:8443/cb?x=1"})
    @DisplayName("https is accepted for either client type")
    void httpsIsAccepted(String uri) {
        assertAccepted(uri, CONFIDENTIAL);
        assertAccepted(uri, PUBLIC);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"http://client.example/callback", "http://127.0.0.2/cb", "http://localhost.example/cb"})
    @DisplayName("http to a non-loopback host is refused for either client type")
    void httpToANonLoopbackHostIsRefused(String uri) {
        assertRefused(uri, CONFIDENTIAL);
        assertRefused(uri, PUBLIC);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"http://127.0.0.1/cb", "http://127.0.0.1:51004/cb", "http://[::1]:8080/cb",
        "http://localhost/cb", "http://LOCALHOST:3000/cb"})
    @DisplayName("loopback http is accepted for a public (native) client (RFC 8252 §7.3)")
    void loopbackHttpIsAcceptedForAPublicClient(String uri) {
        assertAccepted(uri, PUBLIC);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"http://127.0.0.1/cb", "http://[::1]:8080/cb", "http://localhost/cb"})
    @DisplayName("loopback http is refused for a confidential client")
    void loopbackHttpIsRefusedForAConfidentialClient(String uri) {
        assertRefused(uri, CONFIDENTIAL);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"com.example.app:/oauth2redirect", "com.example.app://callback"})
    @DisplayName("a reverse-domain private-use scheme is accepted for a public (native) client (RFC 8252 §7.1)")
    void privateUseSchemeIsAcceptedForAPublicClient(String uri) {
        assertAccepted(uri, PUBLIC);
    }

    @Test
    @DisplayName("a private-use scheme is refused for a confidential client")
    void privateUseSchemeIsRefusedForAConfidentialClient() {
        assertRefused("com.example.app:/oauth2redirect", CONFIDENTIAL);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"myapp:/callback", "javascript:alert(1)", "data:text/html,x", "file:///etc/passwd",
        "ftp://client.example/cb"})
    @DisplayName("any other scheme is refused, even for a public client")
    void otherSchemesAreRefused(String uri) {
        assertRefused(uri, PUBLIC);
        assertRefused(uri, CONFIDENTIAL);
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {"/callback", "client.example/callback", "https:///callback", "https://bad host/cb"})
    @DisplayName("a relative, host-less or malformed URI is refused")
    void malformedUrisAreRefused(String uri) {
        assertRefused(uri, PUBLIC);
        assertRefused(uri, CONFIDENTIAL);
    }

    @Test
    @DisplayName("one bad URI refuses the whole registration")
    void oneBadUriRefusesTheSet() {
        assertThatThrownBy(() -> RedirectUriPolicy.requireRegistrable(
                        List.of("https://client.example/callback", "http://client.example/callback"), CONFIDENTIAL))
                .isInstanceOf(InvalidRedirectUriException.class)
                .hasMessageContaining("invalid_redirect_uri")
                .hasMessageContaining("http://client.example/callback");
    }
}
