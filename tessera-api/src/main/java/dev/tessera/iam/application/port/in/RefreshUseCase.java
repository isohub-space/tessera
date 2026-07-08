package dev.tessera.iam.application.port.in;

import dev.tessera.iam.application.port.in.TokenUseCase.TokenResult;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Inbound port for the refresh-token grant ({@code grant_type=refresh_token}, RFC 6749 §6) at
 * {@code /token}.
 *
 * <p>Redeeming a refresh token issues a fresh access token <em>and</em> a fresh refresh token,
 * invalidating the presented one (single-use rotation). Replaying a superseded token revokes the
 * whole family (OAuth 2.0 Security BCP / RFC 9700 §4.14). The token's authoritative tenant is
 * resolved from server-stored state, not the request header, so a replay is detected even under a
 * wrong or absent tenant header; issuance nevertheless stays fail-closed in the header direction.
 * Every failure collapses to {@code invalid_grant} (or {@code invalid_client} for a client-auth
 * failure) so a caller cannot probe which check failed. Reuses {@link TokenResult}.
 */
public interface RefreshUseCase {

    /**
     * Redeems a refresh token for a new access + refresh token pair.
     *
     * @param command the refresh request (never {@code null})
     * @return a {@link Uni} emitting the {@link TokenResult}
     */
    Uni<TokenResult> redeem(RefreshCommand command);

    /**
     * A parsed refresh-token request.
     *
     * @param requestRealm the header-derived tenant of the request — used only for the fail-closed
     *                     issuance check, never as the authoritative family tenant (never {@code null})
     * @param refreshToken the opaque refresh token being redeemed (never {@code null} or blank)
     * @param clientId     the wire {@code client_id} (never {@code null} or blank)
     * @param clientSecret the presented secret for a confidential client, or {@code null} for a public one
     * @param scope        the requested scope, or {@code null} — currently ignored (see the service)
     */
    record RefreshCommand(
            RealmKey requestRealm,
            String refreshToken,
            String clientId,
            String clientSecret,
            String scope) {

        public RefreshCommand {
            if (requestRealm == null) {
                throw new IllegalArgumentException("RefreshCommand requestRealm must not be null");
            }
            if (refreshToken == null || refreshToken.isBlank()) {
                throw new IllegalArgumentException("RefreshCommand refreshToken must not be blank");
            }
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalArgumentException("RefreshCommand clientId must not be blank");
            }
        }
    }
}
