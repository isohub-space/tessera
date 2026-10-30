// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.adapter.rest;

import com.nimbusds.jwt.SignedJWT;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import jakarta.ws.rs.core.Response;

/**
 * The client credential a request presents, read the same way by every endpoint that
 * authenticates a client ({@code /token} for {@code client_credentials}, {@code /introspect},
 * {@code /revoke}): HTTP Basic, which takes precedence over the body (RFC 6749 §2.3.1), the body's
 * {@code client_id} and {@code client_secret}, or a JWT client assertion (RFC 7523 §2.2).
 *
 * <p>Only the shape of the request is checked here. Whether the credential authenticates the client
 * is decided once, by the application layer's shared client-authentication step, so an assertion is
 * verified by the same verifier, with the same single-use rule and within the same request realm on
 * every endpoint.
 */
sealed interface PresentedClientCredentials {

    /** The only client assertion type accepted (RFC 7523 §2.2). */
    String JWT_BEARER_ASSERTION = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    /**
     * A well-formed presentation.
     *
     * @param clientId        the presented {@code client_id}, or, with an assertion and no
     *                        {@code client_id}, the assertion's unverified {@code sub}; may be
     *                        {@code null} or blank, which each endpoint refuses
     * @param clientSecret    the presented secret, or {@code null}
     * @param clientAssertion the presented assertion, or {@code null}
     */
    record Presented(String clientId, String clientSecret, String clientAssertion)
            implements PresentedClientCredentials {
    }

    /** A presentation refused before any credential is checked. */
    record Refused(Response.Status status, AuthorizationError error, String description)
            implements PresentedClientCredentials {
    }

    /** Whether the request presents a client assertion at all. */
    static boolean assertionPresented(String clientAssertionType, String clientAssertion) {
        return clientAssertionType != null || clientAssertion != null;
    }

    static PresentedClientCredentials read(
            String authorization, String clientId, String clientSecret,
            String clientAssertionType, String clientAssertion) {
        BasicCredentials basic = BasicCredentials.parse(authorization);
        String resolvedClientId = basic != null ? basic.clientId() : clientId;
        String resolvedSecret = basic != null ? basic.clientSecret() : clientSecret;
        if (!assertionPresented(clientAssertionType, clientAssertion)) {
            return new Presented(resolvedClientId, resolvedSecret, null);
        }
        // RFC 6749 §2.3: one authentication method per request.
        if (basic != null || clientSecret != null) {
            return new Refused(Response.Status.BAD_REQUEST, AuthorizationError.INVALID_REQUEST,
                    "use one client authentication method");
        }
        if (!JWT_BEARER_ASSERTION.equals(clientAssertionType) || isBlank(clientAssertion)) {
            return new Refused(Response.Status.UNAUTHORIZED, AuthorizationError.INVALID_CLIENT,
                    "client authentication failed");
        }
        // client_id is optional with an assertion (RFC 7521 §4.2); its subject names the client.
        if (isBlank(resolvedClientId)) {
            resolvedClientId = unverifiedSubject(clientAssertion);
        }
        return new Presented(resolvedClientId, null, clientAssertion);
    }

    /** The assertion's {@code sub}, read before verification only to look the client up. */
    private static String unverifiedSubject(String assertion) {
        try {
            return SignedJWT.parse(assertion).getJWTClaimsSet().getSubject();
        } catch (Exception malformed) {
            return null;
        }
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
