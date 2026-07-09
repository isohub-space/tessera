package dev.tessera.iam.adapter.rest;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Parsed HTTP Basic client credentials ({@code Authorization: Basic base64(id:secret)},
 * RFC 6749 §2.3.1), shared by the OAuth endpoints that authenticate a client ({@code /token},
 * {@code /revoke}). The {@code client_id} and {@code client_secret} are
 * {@code application/x-www-form-urlencoded} per the spec; they are decoded so a credential
 * containing reserved characters round-trips.
 *
 * @param clientId     the decoded client identifier
 * @param clientSecret the decoded client secret
 */
record BasicCredentials(String clientId, String clientSecret) {

    /**
     * Parses an {@code Authorization} header value, or returns {@code null} when it is absent, not
     * the {@code Basic} scheme, not valid base64, or missing the {@code id:secret} separator — in
     * which case the caller falls back to the form-body credentials.
     */
    static BasicCredentials parse(String authorization) {
        if (authorization == null) {
            return null;
        }
        String prefix = "Basic ";
        if (!authorization.regionMatches(true, 0, prefix, 0, prefix.length())) {
            return null;
        }
        String encoded = authorization.substring(prefix.length()).trim();
        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException ex) {
            return null;
        }
        String pair = new String(decoded, StandardCharsets.UTF_8);
        int colon = pair.indexOf(':');
        if (colon < 0) {
            return null;
        }
        String id = formDecode(pair.substring(0, colon));
        String secret = formDecode(pair.substring(colon + 1));
        return new BasicCredentials(id, secret);
    }

    private static String formDecode(String value) {
        return URLDecoder.decode(value, StandardCharsets.UTF_8);
    }
}
