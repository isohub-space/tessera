package dev.tessera.iam.adapter.rest.token;

import com.fasterxml.jackson.databind.JsonNode;
import dev.tessera.iam.application.port.out.IdTokenHintVerifierPort;
import dev.tessera.iam.domain.tenancy.RealmKey;
import io.smallrye.mutiny.Uni;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Verifies an {@code id_token_hint} with the same checks the introspection endpoint applies to an
 * access token ({@link JwsAccessTokenIntrospector#verifiedPayload}): {@code alg=EdDSA}, a
 * published {@code kid} of the presenting realm, and an Ed25519 signature that verifies. The one
 * difference is the type: an ID token is signed with {@code typ=JWT}, so an access token
 * ({@code typ=at+jwt}) is never accepted as a hint, nor a hint as an access token.
 */
@ApplicationScoped
public class JwsIdTokenHintVerifier implements IdTokenHintVerifierPort {

    private static final String TYP_ID_TOKEN = "JWT";

    @Inject
    JwsAccessTokenIntrospector jws;

    @Override
    public Uni<Optional<VerifiedIdToken>> verify(RealmKey realm, String token) {
        return jws.verifiedPayload(realm, token, TYP_ID_TOKEN)
                .map(payload -> payload.map(JwsIdTokenHintVerifier::claims));
    }

    private static VerifiedIdToken claims(JsonNode payload) {
        return new VerifiedIdToken(text(payload, "iss"), text(payload, "sub"), audience(payload.get("aud")));
    }

    /** {@code aud} is a string or an array of strings (RFC 7519 §4.1.3); anything else is no audience. */
    private static List<String> audience(JsonNode aud) {
        if (aud == null) {
            return List.of();
        }
        if (aud.isTextual()) {
            return List.of(aud.asText());
        }
        List<String> values = new ArrayList<>();
        if (aud.isArray()) {
            aud.forEach(value -> {
                if (value.isTextual()) {
                    values.add(value.asText());
                }
            });
        }
        return values;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }
}
