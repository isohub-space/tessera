// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("Sign-in page policy — the redirect origin, and nothing else, reaches form-action")
class SignInPagePolicyTest {

    @ParameterizedTest(name = "{0} → {1}")
    @CsvSource({
        "https://client.example/callback, https://client.example",
        "https://Client.Example:8443/cb?x=1, https://client.example:8443",
        "http://127.0.0.1:53111/cb, http://127.0.0.1:53111",
        "http://[::1]:53111/cb, http://[::1]:53111",
        "com.example.app:/oauth2redirect, com.example.app:",
    })
    void originOfRedirectUri(String redirectUri, String expected) {
        assertThat(SignInPagePolicy.source(redirectUri)).isEqualTo(expected);
    }

    @ParameterizedTest
    @ValueSource(strings = {"not a uri", "/relative/only", "https://user@host;evil/cb"})
    void malformedYieldsNothing(String redirectUri) {
        assertThat(SignInPagePolicy.source(redirectUri)).isNull();
    }

    @Test
    @DisplayName("a form page allows 'self' plus the origin; a page with no form allows no form")
    void policies() {
        assertThat(SignInPagePolicy.form("https://client.example/cb"))
                .contains("form-action 'self' https://client.example")
                .contains("default-src 'none'")
                .contains("style-src 'self'")
                .contains("frame-ancestors 'none'")
                .doesNotContain("script-src");
        assertThat(SignInPagePolicy.form("not a uri")).endsWith("form-action 'self'");
        assertThat(SignInPagePolicy.closed()).contains("form-action 'none'");
    }
}
