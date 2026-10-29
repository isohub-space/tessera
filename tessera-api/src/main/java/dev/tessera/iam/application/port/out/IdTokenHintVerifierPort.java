package dev.tessera.iam.application.port.out;

import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import java.util.List;
import java.util.Optional;

/**
 * Outbound port that verifies an {@code id_token_hint} (OpenID Connect RP-Initiated Logout 1.0
 * §2): a compact JWS that this server signed as an ID token, under the presenting realm's
 * published keys.
 *
 * <p>The contract mirrors {@link AccessTokenIntrospectorPort}: a token is verified only when its
 * header says {@code alg=EdDSA} and {@code typ=JWT} (so an access token, {@code typ=at+jwt}, is
 * never accepted as a hint), its {@code kid} names one of the realm's published keys, and the
 * signature verifies. Anything else is {@link Optional#empty()}, never an exception. Expiry is
 * <em>not</em> evaluated: RP-Initiated Logout lets a relying party present an ID token that has
 * expired, and the caller decides what else the claims must say.
 */
public interface IdTokenHintVerifierPort {

    /**
     * Verifies {@code token} as an ID token signed under {@code realm}'s published keys.
     *
     * @param realm the realm the request is in (never {@code null})
     * @param token the presented hint (may be {@code null} or malformed)
     * @return the verified claims, or {@link Optional#empty()} if it is not an ID token this
     *         realm signed
     */
    Uni<Optional<VerifiedIdToken>> verify(RealmKey realm, String token);

    /**
     * The claims an end-session request needs from a verified ID token.
     *
     * @param issuer   the {@code iss} claim, or {@code null} if absent
     * @param subject  the {@code sub} claim, or {@code null} if absent
     * @param audience the {@code aud} claim as a list (one element for a string {@code aud});
     *                 empty if absent
     */
    record VerifiedIdToken(String issuer, String subject, List<String> audience) {

        public VerifiedIdToken {
            audience = audience == null ? List.of() : List.copyOf(audience);
        }
    }
}
