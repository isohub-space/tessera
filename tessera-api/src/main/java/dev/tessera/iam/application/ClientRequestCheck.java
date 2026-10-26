// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.application;

import dev.tessera.iam.application.port.in.AuthorizeUseCase.AuthorizeResult;
import dev.tessera.iam.domain.authcode.AuthorizationError;
import dev.tessera.iam.domain.authcode.AuthorizationRequest;
import dev.tessera.iam.domain.client.Client;
import dev.tessera.iam.domain.client.grant.AuthorizationCode;
import dev.tessera.iam.domain.client.grant.GrantType;

/**
 * The checks an authorization request must pass against its registered client before anything
 * happens on its behalf: a code is minted, or the browser is sent to the sign-in page.
 *
 * <p>Shared by {@link AuthorizationService} and {@link SignInService} so the two paths cannot
 * drift apart. Every refusal is non-redirectable: until the client and its redirect URI are
 * validated, the redirect target is itself untrusted.
 */
final class ClientRequestCheck {

    private static final GrantType AUTHORIZATION_CODE = new AuthorizationCode();

    private ClientRequestCheck() {
    }

    /**
     * @param client  the client the request names, or {@code null} if none is registered
     * @param request the authorization request
     * @return the refusal, or {@code null} when the request may proceed
     */
    static AuthorizeResult.Failed refusal(Client client, AuthorizationRequest request) {
        if (client == null) {
            return new AuthorizeResult.Failed(AuthorizationError.INVALID_REQUEST, "unknown client", false);
        }
        if (!client.allowedGrants().contains(AUTHORIZATION_CODE)) {
            return new AuthorizeResult.Failed(AuthorizationError.UNAUTHORIZED_CLIENT,
                    "client may not use the authorization_code grant", false);
        }
        if (!client.redirectUris().contains(request.redirectUri())) {
            // Exact match. Delivering anything to an unregistered URI would be an open redirect.
            return new AuthorizeResult.Failed(AuthorizationError.INVALID_REQUEST,
                    "redirect_uri is not registered for this client", false);
        }
        return null;
    }
}
