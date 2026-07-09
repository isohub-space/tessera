package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.Optional;

/**
 * Outbound port that verifies a self-contained JWT access token against a realm's published keys
 * and returns its claims. Verification (JWS parsing, EdDSA signature check, JWK-to-key
 * reconstruction) is an adapter concern — it needs JSON and JDK crypto — so it lives behind this
 * port, keeping the introspection application service framework-free.
 *
 * <p>The contract is deliberately strict and realm-bound: an {@link Optional} is emitted
 * <em>only</em> when the token is a well-formed RFC 9068 access token ({@code typ=at+jwt},
 * {@code alg=EdDSA}) whose signature verifies against a <em>published</em> key of {@code realm}
 * (a key issued by another tenant will not be published under this realm and so will not verify).
 * Any malformedness, an unknown {@code kid}, a bad signature, or a foreign-realm token yields
 * {@link Optional#empty()} — never an exception. Expiry is <em>not</em> evaluated here; the caller
 * applies the active/inactive decision so the token-lifetime policy stays in the application core.
 */
public interface AccessTokenIntrospectorPort {

    /**
     * Verifies a presented JWT access token within {@code realm}.
     *
     * @param realm the caller's realm — the token must verify against a key published for it
     * @param token the presented token (may be {@code null}, blank, or not a JWT — all yield empty)
     * @return the verified claims, or {@link Optional#empty()} if the token is not a valid access
     *         token for this realm
     */
    Uni<Optional<VerifiedAccessToken>> verify(RealmKey realm, String token);

    /**
     * The claims read from a verified access token. {@code issuedAt}/{@code expiresAt} are seconds
     * since the epoch as carried in the JWT ({@code null} if the claim was absent).
     *
     * @param subject   the {@code sub} claim
     * @param clientId  the {@code client_id} claim
     * @param scope     the {@code scope} claim (space-delimited), or {@code null}
     * @param jti       the {@code jti} claim, or {@code null}
     * @param issuedAt  the {@code iat} claim (epoch seconds), or {@code null}
     * @param expiresAt the {@code exp} claim (epoch seconds), or {@code null}
     */
    record VerifiedAccessToken(
            String subject,
            String clientId,
            String scope,
            String jti,
            Long issuedAt,
            Long expiresAt) {
    }
}
