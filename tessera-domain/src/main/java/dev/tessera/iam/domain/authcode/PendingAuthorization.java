// SPDX-License-Identifier: Apache-2.0
package dev.tessera.iam.domain.authcode;

import dev.tessera.iam.domain.tenancy.RealmKey;
import java.time.Instant;

/**
 * An authorization request that has passed client and redirect-URI validation and is waiting
 * for the end user to sign in on tessera's own page.
 *
 * <p>{@code /authorize} creates one when the request carries no authenticated subject; the
 * sign-in page reads it to render the form and consumes it once the credential verifies, then
 * issues the code for the stored request. The client never handles anything but the
 * {@code transactionId}, so the request that is finally answered is exactly the one that was
 * validated, whatever the browser posts back.
 *
 * <p>Two secrets guard it. The {@code csrfToken} is the synchronizer token the form carries; it
 * is kept in clear because the form is re-rendered after a failed attempt. The binding secret
 * travels only in a cookie on the browser that started the flow; only its hash is kept, so a
 * leaked store entry cannot be replayed from another browser.
 *
 * @param transactionId the opaque handle in the sign-in URL (never {@code null} or blank)
 * @param request       the validated authorization request (never {@code null})
 * @param csrfToken     the form's synchronizer token (never {@code null} or blank)
 * @param bindingHash   the base64url SHA-256 of the browser-binding secret (never {@code null}
 *                      or blank)
 * @param createdAt     when the request was accepted (never {@code null})
 * @param expiresAt     when it stops being usable; strictly after {@code createdAt}
 */
public record PendingAuthorization(
        String transactionId,
        AuthorizationRequest request,
        String csrfToken,
        String bindingHash,
        Instant createdAt,
        Instant expiresAt) {

    public PendingAuthorization {
        if (transactionId == null || transactionId.isBlank()) {
            throw new IllegalArgumentException("PendingAuthorization transactionId must not be blank");
        }
        if (request == null) {
            throw new IllegalArgumentException("PendingAuthorization request must not be null");
        }
        if (csrfToken == null || csrfToken.isBlank()) {
            throw new IllegalArgumentException("PendingAuthorization csrfToken must not be blank");
        }
        if (bindingHash == null || bindingHash.isBlank()) {
            throw new IllegalArgumentException("PendingAuthorization bindingHash must not be blank");
        }
        if (createdAt == null || expiresAt == null) {
            throw new IllegalArgumentException("PendingAuthorization instants must not be null");
        }
        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException("PendingAuthorization expiresAt must be after createdAt");
        }
    }

    /** @return the realm the request runs within. */
    public RealmKey realm() {
        return request.realm();
    }

    /**
     * @param now the current instant (never {@code null})
     * @return {@code true} once {@code now} has reached {@code expiresAt}
     */
    public boolean isExpired(Instant now) {
        if (now == null) {
            throw new IllegalArgumentException("now must not be null");
        }
        return !now.isBefore(expiresAt);
    }
}
