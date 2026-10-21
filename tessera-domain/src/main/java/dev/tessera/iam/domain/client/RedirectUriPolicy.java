package dev.tessera.iam.domain.client;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collection;
import java.util.Locale;
import java.util.Set;

/**
 * Which redirect URIs a client may register (RFC 9700 §2.6, RFC 8252 §7), so an authorization
 * code never travels over an unencrypted redirect.
 *
 * <ul>
 *   <li>{@code https} with a host is accepted for every client.</li>
 *   <li>{@code http} is accepted only for a public client and only on a loopback host
 *       ({@code 127.0.0.1}, {@code [::1]}, {@code localhost}): the native-app loopback redirect
 *       of RFC 8252 §7.3, which never leaves the device.</li>
 *   <li>A private-use scheme is accepted only for a public client and only in the
 *       reverse-domain form RFC 8252 §7.1 requires ({@code com.example.app:/callback}).</li>
 *   <li>Anything else, including a relative, host-less or malformed URI, is refused.</li>
 * </ul>
 *
 * <p>A confidential client is a server-side application, so only {@code https} is open to it.
 * Every refusal is an {@link InvalidRedirectUriException} ({@code invalid_redirect_uri}).
 */
public final class RedirectUriPolicy {

    private static final Set<String> LOOPBACK_HOSTS = Set.of("127.0.0.1", "[::1]", "::1", "localhost");

    private RedirectUriPolicy() {
    }

    /**
     * Checks every URI a client is about to register.
     *
     * @param redirectUris the URIs to register (never {@code null})
     * @param publicClient whether the client is public (SPA or native app)
     * @throws InvalidRedirectUriException on the first URI the policy refuses
     */
    public static void requireRegistrable(Collection<String> redirectUris, boolean publicClient) {
        for (String uri : redirectUris) {
            String reason = refusal(uri, publicClient);
            if (reason != null) {
                throw new InvalidRedirectUriException(uri, reason);
            }
        }
    }

    /** @return why {@code uri} is refused, or {@code null} when it may be registered */
    private static String refusal(String uri, boolean publicClient) {
        URI parsed;
        try {
            parsed = new URI(uri);
        } catch (URISyntaxException | NullPointerException e) {
            return "not a valid URI";
        }
        if (parsed.getScheme() == null) {
            return "not an absolute URI";
        }
        String scheme = parsed.getScheme().toLowerCase(Locale.ROOT);
        String host = parsed.getHost() == null ? null : parsed.getHost().toLowerCase(Locale.ROOT);
        return switch (scheme) {
            case "https" -> host == null ? "https without a host" : null;
            case "http" -> {
                if (host == null || !LOOPBACK_HOSTS.contains(host)) {
                    yield "http is allowed only on a loopback host";
                }
                yield publicClient ? null : "loopback http is allowed only for a public client";
            }
            default -> {
                if (!scheme.contains(".")) {
                    yield "scheme " + scheme + " is neither https nor a reverse-domain private-use scheme";
                }
                yield publicClient ? null : "a private-use scheme is allowed only for a public client";
            }
        };
    }
}
