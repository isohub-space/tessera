package dev.tessera.iam.adapter.rest.session;

import jakarta.ws.rs.core.NewCookie;

/**
 * Builds the {@code Set-Cookie} response for the session cookie.
 *
 * <p>Flags are fixed, not configurable, decided explicitly rather than defaulted:
 * {@code HttpOnly} (the cookie is never readable from script — this is a
 * session credential, not UI state), {@code Secure} (never sent over plain HTTP; every real
 * deployment of this server sits behind a TLS-terminating gateway, and dev/test tolerate the
 * cookie simply not being echoed back by a non-TLS client) and {@code SameSite=Strict} (the
 * login/consent page is always same-site with the server that reads this cookie — there is
 * no legitimate cross-site navigation that should carry it, so the strictest setting costs
 * nothing and closes off CSRF on the login/consent/authorize surfaces).
 */
public final class SessionCookies {

    /**
     * The session cookie's name. Fixed, not configurable: it is an implementation detail
     * (unlike the security flags above, an operator has no reason to tune it), and keeping it
     * a plain constant lets {@link SessionCookieFilter} — instantiated eagerly at JAX-RS
     * deployment setup, before {@code @ConfigMapping} beans are guaranteed resolvable — read
     * it without an injection point.
     */
    public static final String NAME = "tessera_session";

    private SessionCookies() {
    }

    /** Builds the {@code Set-Cookie} for a freshly established session. */
    public static NewCookie issue(String value, long maxAgeSeconds) {
        return new NewCookie.Builder(NAME)
                .value(value)
                .path("/")
                .httpOnly(true)
                .secure(true)
                .sameSite(NewCookie.SameSite.STRICT)
                .maxAge((int) Math.min(Integer.MAX_VALUE, maxAgeSeconds))
                .build();
    }

    /** Builds the {@code Set-Cookie} that clears the session cookie (logout). */
    public static NewCookie clear() {
        return new NewCookie.Builder(NAME)
                .value("")
                .path("/")
                .httpOnly(true)
                .secure(true)
                .sameSite(NewCookie.SameSite.STRICT)
                .maxAge(0)
                .build();
    }
}
