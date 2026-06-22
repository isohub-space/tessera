package dev.tessera.iam.adapter.rest.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.out.ActiveKey;
import dev.tessera.iam.application.port.out.KeyProviderPort;
import dev.tessera.iam.application.port.out.SignatureResult;
import dev.tessera.iam.application.port.out.TokenSignerPort;
import dev.tessera.iam.domain.signingkey.SigningAlgorithm;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.token.ClaimSet;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Inbound-adapter implementation of {@link TokenSignerPort}: turns an unsigned domain
 * {@link ClaimSet} into a compact, signed JWS (a JWT string).
 *
 * <p>The functional core produces only the claims; assembling a verifiable JWT — the
 * JOSE header ({@code alg}, {@code kid}, {@code typ}), the canonical base64url
 * serialisation, and stitching the detached signature back on — is an adapter effect and
 * lives here. The private key never crosses into this adapter: the signing bytes are
 * handed to {@link KeyProviderPort#sign} (sign-as-operation), which loads, uses and
 * discards the key entirely inside the provider and returns only the signature.
 *
 * <p>Signing is a CPU-bound asymmetric operation, so it runs <strong>off the reactive
 * event loop</strong>: the JSON serialisation and base64url encoding are wrapped in a
 * {@code Uni} that {@code KeyProviderPort.sign} already executes on a worker thread, and
 * the final concatenation is a pure map. The caller ({@code TokenService}) therefore never
 * blocks the event loop.
 */
@ApplicationScoped
public class JwsTokenSignerAdapter implements TokenSignerPort {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    @Inject
    KeyProviderPort keyProvider;

    @Inject
    ObjectMapper objectMapper;

    @Override
    public Uni<String> sign(RealmKey realm, String typ, ClaimSet claims) {
        if (realm == null) {
            throw new IllegalArgumentException("realm must not be null");
        }
        if (typ == null || typ.isBlank()) {
            throw new IllegalArgumentException("typ must not be null or blank");
        }
        if (claims == null) {
            throw new IllegalArgumentException("claims must not be null");
        }

        // Resolve the realm's current ACTIVE key so its kid/alg stamp the header, then sign
        // the signing-input inside the provider (private key never leaves it).
        return keyProvider.currentSigningKey(realm)
                .flatMap(activeKey -> {
                    String signingInput = signingInput(activeKey, typ, claims);
                    byte[] inputBytes = signingInput.getBytes(StandardCharsets.US_ASCII);
                    return keyProvider.sign(realm, activeKey.keyId(), inputBytes)
                            .map(signature -> compact(signingInput, signature));
                });
    }

    /**
     * Builds the JWS signing-input {@code base64url(header) + "." + base64url(payload)}.
     * The header carries the algorithm, the key id (so a verifier can select the public
     * key from the JWKS) and the {@code typ} ({@code at+jwt} for an RFC 9068 access token,
     * {@code JWT} for an ID token).
     */
    private String signingInput(ActiveKey activeKey, String typ, ClaimSet claims) {
        SigningAlgorithm alg = activeKey.algorithm();
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", alg.algIdentifier());
        header.put("typ", typ);
        header.put("kid", activeKey.keyId().value());
        return encode(header) + "." + encode(claims.claims());
    }

    /** Stitches the detached signature back onto the signing-input as a compact JWS. */
    private static String compact(String signingInput, SignatureResult signature) {
        return signingInput + "." + B64URL.encodeToString(signature.signature());
    }

    /** Serialises a JSON object to its base64url-encoded UTF-8 bytes. */
    private String encode(Map<String, Object> json) {
        return B64URL.encodeToString(toJsonBytes(json));
    }

    private byte[] toJsonBytes(Map<String, Object> json) {
        try {
            return objectMapper.writeValueAsBytes(json);
        } catch (JsonProcessingException e) {
            // The claim/header maps contain only JSON-shaped primitives, strings and
            // lists assembled by the domain; serialisation cannot legitimately fail.
            throw new IllegalStateException("Failed to serialise JWT JSON", e);
        }
    }
}
