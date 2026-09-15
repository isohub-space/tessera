package dev.tessera.iam.adapter.rest.authcode;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import dev.tessera.iam.domain.authcode.AuthorizationGrant;
import dev.tessera.iam.domain.authcode.CodeChallenge;
import dev.tessera.iam.domain.authcode.PkceMethod;
import dev.tessera.iam.domain.client.ClientId;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;

/**
 * The wire form of an {@link AuthorizationGrant} on the shared cache, and the codec between
 * the two.
 *
 * <p>Values are stored as JSON strings. Hot Rod marshals {@link String} natively, so the
 * cache needs no registered schema and the server needs no type knowledge — the alternative,
 * generating a Protostream marshaller, pulls an annotation processor and its generated
 * (raw-typed) sources into a module that compiles with {@code -Werror}, buying schema
 * evolution this entry does not need: an authorization code lives for about two minutes, so
 * no entry ever outlives a rolling upgrade.
 *
 * <p>The domain record is deliberately not the wire type. Keeping serialization concerns out
 * of {@code tessera-domain} is what the architecture test enforces, so the adapter owns this
 * flat projection and the mapping both ways.
 *
 * <p>{@link Instant}s are carried as (epoch-second, nano) pairs rather than millis so the
 * round-trip is lossless: a truncated {@code expiresAt} would move a code's expiry, and
 * moving it later is a (small) extension of the replay window.
 */
record StoredGrant(
        String tenantId,
        String baselineId,
        String clientId,
        String subjectId,
        String redirectUri,
        List<String> scopes,
        String nonce,
        String codeChallengeMethod,
        String codeChallengeValue,
        long issuedAtEpochSecond,
        int issuedAtNano,
        long expiresAtEpochSecond,
        int expiresAtNano) {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static String encode(AuthorizationGrant grant) {
        StoredGrant stored = new StoredGrant(
                grant.realm().tenant().value().toString(),
                grant.realm().baseline().value().toString(),
                grant.clientId().value().toString(),
                grant.subjectId(),
                grant.redirectUri(),
                List.copyOf(grant.scopes()),
                grant.nonce(),
                grant.codeChallenge().method().name(),
                grant.codeChallenge().value(),
                grant.issuedAt().getEpochSecond(),
                grant.issuedAt().getNano(),
                grant.expiresAt().getEpochSecond(),
                grant.expiresAt().getNano());
        try {
            return MAPPER.writeValueAsString(stored);
        } catch (JsonProcessingException e) {
            // Every field is a String, a primitive or a List<String>; this cannot fail for a
            // valid grant, and a grant that cannot be stored must not be handed out as a code.
            throw new IllegalStateException("could not encode authorization grant", e);
        }
    }

    /**
     * Decodes a cached value back into a grant.
     *
     * @param json the cached JSON value (never {@code null})
     * @return the grant, or {@code null} if the value is not a decodable grant — a malformed
     *         or unknown-shaped entry is a miss, never an exception on the token endpoint.
     *         The atomic remove has already taken the entry, so it cannot be retried either.
     */
    static AuthorizationGrant decode(String json) {
        StoredGrant stored;
        try {
            stored = MAPPER.readValue(json, StoredGrant.class);
        } catch (JsonProcessingException e) {
            return null;
        }
        try {
            return new AuthorizationGrant(
                    new RealmKey(
                            new TenantId(UUID.fromString(stored.tenantId)),
                            new BaselineId(UUID.fromString(stored.baselineId))),
                    new ClientId(UUID.fromString(stored.clientId)),
                    stored.subjectId,
                    stored.redirectUri,
                    // LinkedHashSet, not Set.copyOf: the grant's scope order is preserved on
                    // the round-trip exactly as the issuing service recorded it.
                    new LinkedHashSet<>(stored.scopes),
                    stored.nonce,
                    new CodeChallenge(
                            PkceMethod.valueOf(stored.codeChallengeMethod), stored.codeChallengeValue),
                    Instant.ofEpochSecond(stored.issuedAtEpochSecond, stored.issuedAtNano),
                    Instant.ofEpochSecond(stored.expiresAtEpochSecond, stored.expiresAtNano));
        } catch (IllegalArgumentException | NullPointerException e) {
            // A structurally valid JSON object that is not a valid grant (bad UUID, unknown
            // PKCE method, missing field, expiresAt not after issuedAt). Same answer: a miss.
            return null;
        }
    }
}
