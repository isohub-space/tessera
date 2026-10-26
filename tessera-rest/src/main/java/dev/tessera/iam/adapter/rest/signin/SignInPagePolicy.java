// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The Content-Security-Policy of the sign-in page, which replaces the server-wide one on that
 * path alone.
 *
 * <p>The page loads its stylesheet from tessera and nothing else, runs no script, and cannot be
 * framed. Its form posts to tessera ({@code form-action 'self'}), but the post is answered with
 * a redirect to the client, and browsers that enforce {@code form-action} on the redirects that
 * follow a submission would block that last hop unless the client's origin is listed too. So the
 * policy of a form page names the origin of the redirect URI it will end at, which has already
 * been validated as registered to the client. Pages that carry no form keep
 * {@code form-action 'none'}.
 */
final class SignInPagePolicy {

    private static final String BASE =
            "default-src 'none'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'";
    private static final Pattern SCHEME = Pattern.compile("[A-Za-z][A-Za-z0-9+.-]*");
    private static final Pattern HOST = Pattern.compile("[A-Za-z0-9.-]+|\\[[0-9A-Fa-f:.]+\\]");

    private SignInPagePolicy() {
    }

    /** The policy of a page carrying the sign-in form for a request redirecting to {@code redirectUri}. */
    static String form(String redirectUri) {
        String target = source(redirectUri);
        return BASE + "; form-action 'self'" + (target == null ? "" : " " + target);
    }

    /** The policy of a page with no form. */
    static String closed() {
        return BASE + "; form-action 'none'";
    }

    /**
     * The CSP source expression for a redirect URI's origin: {@code scheme://host[:port]}, or
     * {@code scheme:} for a private-use scheme with no host (a native app's callback). Anything
     * that does not parse into those plain shapes yields {@code null}, so nothing from the URI
     * can reach the header unless it is a well-formed origin.
     */
    static String source(String redirectUri) {
        URI uri;
        try {
            uri = new URI(redirectUri);
        } catch (URISyntaxException | NullPointerException e) {
            return null;
        }
        String scheme = uri.getScheme();
        if (scheme == null || !SCHEME.matcher(scheme).matches()) {
            return null;
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        String host = uri.getHost();
        if (host == null) {
            return uri.getRawAuthority() == null ? scheme + ":" : null;
        }
        if (!HOST.matcher(host).matches()) {
            return null;
        }
        return scheme + "://" + host.toLowerCase(Locale.ROOT) + (uri.getPort() >= 0 ? ":" + uri.getPort() : "");
    }
}
