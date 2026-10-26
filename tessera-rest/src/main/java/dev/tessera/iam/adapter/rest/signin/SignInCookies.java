// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest.signin;

import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.UriInfo;

/**
 * The cookie that binds a pending sign-in to the browser that started it.
 *
 * <p>{@code /authorize} sets it on the redirect to the sign-in page; the page refuses to show
 * or accept a form without it. It is {@code HttpOnly} and {@code Secure} like the session
 * cookie, but {@code SameSite=Lax}, not {@code Strict}: the browser reaches the sign-in page by
 * a redirect chain that a client on another site started, and a {@code Strict} cookie would not
 * be sent on that navigation. Its path is the sign-in page alone, and it lives no longer than
 * the transaction it binds.
 */
public final class SignInCookies {

    /** The binding cookie's name. */
    public static final String NAME = "tessera_authz";

    private SignInCookies() {
    }

    /** The binding cookie for a freshly started sign-in. */
    public static NewCookie issue(UriInfo uriInfo, String binding, long maxAgeSeconds) {
        return builder(uriInfo)
                .value(binding)
                .maxAge((int) Math.min(Integer.MAX_VALUE, maxAgeSeconds))
                .build();
    }

    /** Clears the binding cookie once the sign-in it bound is finished. */
    public static NewCookie clear(UriInfo uriInfo) {
        return builder(uriInfo).value("").maxAge(0).build();
    }

    /** The path of the sign-in page, under whatever base path the server is mounted at. */
    public static String signInPath(UriInfo uriInfo) {
        String base = uriInfo.getBaseUri().getPath();
        return (base == null || base.isEmpty() ? "/" : base.endsWith("/") ? base : base + "/") + "signin";
    }

    private static NewCookie.Builder builder(UriInfo uriInfo) {
        return new NewCookie.Builder(NAME)
                .path(signInPath(uriInfo))
                .httpOnly(true)
                .secure(true)
                .sameSite(NewCookie.SameSite.LAX);
    }
}
