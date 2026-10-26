// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import dev.tessera.iam.domain.authcode.AuthorizationError;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Builds the authorization response delivered to a client's redirect URI (RFC 6749 §4.1.2),
 * always with the RFC 9207 {@code iss} so a client can detect a mix-up attack. Shared by
 * {@code /authorize} and the sign-in page, which both answer authorization requests.
 *
 * <p>Callers pass only a redirect URI that has been validated as registered to the client.
 */
public final class AuthorizationResponses {

    private AuthorizationResponses() {
    }

    /** Success: {@code code}, {@code state} and {@code iss}. */
    public static URI success(String redirectUri, String code, String state, String issuer) {
        String query = "code=" + encode(code)
                + "&state=" + encode(state)
                + "&iss=" + encode(issuer);
        return appendQuery(redirectUri, query);
    }

    /** Error: {@code error}, {@code error_description}, {@code iss}, and {@code state} when present. */
    public static URI error(
            String redirectUri, AuthorizationError error, String description, String state, String issuer) {
        StringBuilder query = new StringBuilder()
                .append("error=").append(encode(error.code()))
                .append("&error_description=").append(encode(description))
                .append("&iss=").append(encode(issuer));
        if (state != null && !state.isBlank()) {
            query.append("&state=").append(encode(state));
        }
        return appendQuery(redirectUri, query.toString());
    }

    /** Appends a query string to a redirect URI, preserving any query it already carries. */
    private static URI appendQuery(String redirectUri, String query) {
        String separator = redirectUri.indexOf('?') >= 0 ? "&" : "?";
        return URI.create(redirectUri + separator + query);
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
