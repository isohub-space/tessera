package dev.tessera.iam.application.port.in;

import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Inbound port for the token-revocation endpoint ({@code POST /revoke}, RFC 7009).
 *
 * <p>A client, having authenticated, asks the server to invalidate a token it holds. For a
 * rotating refresh token this revokes the whole family; a self-contained access token is accepted
 * without server-side action (its short TTL bounds it). The endpoint is deliberately a
 * <strong>non-oracle</strong>: the outcome is the same — success, empty body — whether the token
 * was live, already revoked, unknown, malformed, or belongs to another tenant, so a caller learns
 * nothing about a token it does not own. The only failure surfaced is a client-authentication
 * failure. Revocation is scoped to the caller's own (header-bound) realm and is a no-op outside it,
 * and is idempotent (RFC 7009 §2.2).
 */
public interface RevokeUseCase {

    /**
     * Revokes the presented token if it is a refresh token owned by the authenticated client within
     * the caller's realm; otherwise does nothing. Always succeeds once the client authenticates.
     *
     * @param command the revocation request (never {@code null})
     * @return a {@link Uni} emitting {@link RevokeResult.Done} on success (token acted on or not), or
     *         {@link RevokeResult.ClientAuthenticationFailed} if the client could not authenticate
     */
    Uni<RevokeResult> revoke(RevokeCommand command);

    /**
     * A parsed revocation request.
     *
     * @param realm        the caller's header-bound tenant — the only realm a token is revoked within
     *                     (never {@code null})
     * @param token        the token to revoke; may be {@code null}/blank (nothing to do) or any token
     *                     type — a non-refresh or malformed token is silently a no-op
     * @param tokenTypeHint the optional {@code token_type_hint} (RFC 7009 §2.1); advisory only — the
     *                      server classifies the token itself and may ignore the hint
     * @param clientId     the wire {@code client_id} (never {@code null} or blank)
     * @param clientSecret the presented secret for a confidential client, or {@code null} for a public one
     */
    record RevokeCommand(
            RealmKey realm,
            String token,
            String tokenTypeHint,
            String clientId,
            String clientSecret) {

        public RevokeCommand {
            if (realm == null) {
                throw new IllegalArgumentException("RevokeCommand realm must not be null");
            }
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalArgumentException("RevokeCommand clientId must not be blank");
            }
        }
    }

    /** The outcome of a revocation request. */
    sealed interface RevokeResult {

        /** The client authenticated and the request was processed (token acted on, or nothing to do). */
        record Done() implements RevokeResult {
        }

        /** The client could not be authenticated ({@code invalid_client}, HTTP 401). */
        record ClientAuthenticationFailed() implements RevokeResult {
        }
    }
}
