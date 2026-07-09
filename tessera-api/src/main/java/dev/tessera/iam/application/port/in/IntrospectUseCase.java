package dev.tessera.iam.application.port.in;

import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;

/**
 * Inbound port for the token-introspection endpoint ({@code POST /introspect}, RFC 7662).
 *
 * <p>A client (typically a protected resource) authenticates and asks the server whether a token is
 * currently valid. Tessera introspects two token kinds within the caller's own realm:
 * <ul>
 *   <li>a <strong>JWT access token</strong> — active iff its EdDSA signature verifies against a
 *       published key of the caller's realm and it has not expired;</li>
 *   <li>an <strong>opaque refresh token</strong> — active iff its family is present in the caller's
 *       realm, not revoked, not expired, and the presented token is the family's current (live)
 *       token.</li>
 * </ul>
 * The endpoint is <strong>realm-bound and non-oracle</strong>: a token that is unknown, malformed,
 * expired, revoked, or belongs to another tenant yields exactly {@code {"active": false}} — a caller
 * learns nothing about a token it does not legitimately hold. The only surfaced failure is a
 * client-authentication failure.
 */
public interface IntrospectUseCase {

    /**
     * Introspects the presented token.
     *
     * @param command the introspection request (never {@code null})
     * @return a {@link Uni} emitting {@link IntrospectionResult.Active} (with the echoable claims),
     *         {@link IntrospectionResult.Inactive}, or
     *         {@link IntrospectionResult.ClientAuthenticationFailed}
     */
    Uni<IntrospectionResult> introspect(IntrospectCommand command);

    /**
     * A parsed introspection request.
     *
     * @param realm         the caller's header-bound tenant — the only realm a token is introspected
     *                      within (never {@code null})
     * @param token         the token to introspect; may be {@code null}/blank (nothing active) or any
     *                      token kind — a non-token or malformed value is simply inactive
     * @param tokenTypeHint the optional {@code token_type_hint} (RFC 7662 §2.1); advisory only — the
     *                      server classifies the token itself and may ignore the hint
     * @param clientId      the wire {@code client_id} of the authenticating caller (never {@code null}
     *                      or blank)
     * @param clientSecret  the presented secret for a confidential caller, or {@code null} for a public one
     */
    record IntrospectCommand(
            RealmKey realm,
            String token,
            String tokenTypeHint,
            String clientId,
            String clientSecret) {

        public IntrospectCommand {
            if (realm == null) {
                throw new IllegalArgumentException("IntrospectCommand realm must not be null");
            }
            if (clientId == null || clientId.isBlank()) {
                throw new IllegalArgumentException("IntrospectCommand clientId must not be blank");
            }
        }
    }

    /** The outcome of an introspection request. */
    sealed interface IntrospectionResult {

        /** The token is active; {@code token} carries the claims to echo (RFC 7662 §2.2). */
        record Active(ActiveToken token) implements IntrospectionResult {
            public Active {
                if (token == null) {
                    throw new IllegalArgumentException("Active token must not be null");
                }
            }
        }

        /** The token is not active — the response is exactly {@code {"active": false}}. */
        record Inactive() implements IntrospectionResult {
        }

        /** The caller could not be authenticated ({@code invalid_client}, HTTP 401). */
        record ClientAuthenticationFailed() implements IntrospectionResult {
        }
    }

    /**
     * The subset of RFC 7662 introspection members Tessera returns for an active token. A
     * {@code null} member is omitted from the response (e.g. a refresh token carries no {@code scope}
     * or {@code jti}). {@code exp}/{@code iat} are seconds since the epoch (RFC 7662 §2.2).
     *
     * @param scope     space-delimited scopes, or {@code null} if not carried
     * @param clientId  the client the token was issued to
     * @param subject   the token's subject
     * @param tokenType the token type ({@code "Bearer"} for an access token), or {@code null}
     * @param exp       expiry (epoch seconds), or {@code null}
     * @param iat       issuance (epoch seconds), or {@code null}
     * @param jti       token id, or {@code null}
     */
    record ActiveToken(
            String scope,
            String clientId,
            String subject,
            String tokenType,
            Long exp,
            Long iat,
            String jti) {
    }
}
