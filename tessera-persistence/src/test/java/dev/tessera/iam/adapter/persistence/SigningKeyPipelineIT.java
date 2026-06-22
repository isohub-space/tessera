package dev.tessera.iam.adapter.persistence;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.vertx.RunOnVertxContext;
import io.quarkus.test.vertx.UniAsserter;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.adapter.persistence.crypto.Ed25519Keys;
import dev.tessera.iam.adapter.persistence.signingkey.DbKeyProviderAdapter;
import dev.tessera.iam.adapter.persistence.signingkey.KeyRotationService;
import dev.tessera.iam.application.port.out.ActiveKey;
import dev.tessera.iam.application.port.out.SignatureResult;
import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.signingkey.PublicJwk;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import jakarta.inject.Inject;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.NamedParameterSpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * End-to-end proof of the signing-key pipeline against a real PostgreSQL: mint a
 * PENDING key, promote it to ACTIVE, sign with it, and verify the signature with the
 * published public JWK — and that the provider never returns private material and that
 * row-level security isolates one realm's keys from another's.
 */
@QuarkusTest
@QuarkusTestResource(PostgresIamTestResource.class)
@DisplayName("IAM signing-key pipeline — mint, promote, sign, publish, isolate")
class SigningKeyPipelineIT {

    @Inject
    KeyRotationService rotation;

    @Inject
    DbKeyProviderAdapter provider;

    private static RealmKey realm(UUID tenant) {
        return new RealmKey(new TenantId(tenant), new BaselineId(new UUID(0L, 0L)));
    }

    @Test
    @RunOnVertxContext
    @DisplayName("mint → promote → sign round-trips: the published public JWK verifies the signature")
    void mintPromoteSignVerify(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        RealmKey realm = realm(tenant);
        KeyId kid = KeyId.of("kid-" + tenant);
        byte[] signingInput = "header.payload".getBytes(StandardCharsets.UTF_8);

        asserter.execute(() -> rotation.mintPending(realm, kid));
        asserter.execute(() -> rotation.promoteToActive(realm, kid, Instant.parse("2026-06-22T10:00:00Z")));

        // The current signing key is the one we just promoted.
        asserter.assertThat(
                () -> provider.currentSigningKey(realm),
                (ActiveKey active) ->
                        Assertions.assertThat(active.keyId()).isEqualTo(kid));

        // Sign inside the provider, then verify with the PUBLISHED public JWK.
        asserter.assertThat(
                () -> provider.sign(realm, kid, signingInput)
                        .chain(sig -> provider.publishedJwks(realm)
                                .map(jwks -> verifies(jwks, kid, signingInput, sig))),
                (Boolean ok) -> Assertions.assertThat(ok).isTrue());
    }

    @Test
    @RunOnVertxContext
    @DisplayName("published JWKS contains the ACTIVE key and never any private material")
    void publishedJwksHasNoPrivateMaterial(UniAsserter asserter) {
        UUID tenant = UUID.randomUUID();
        RealmKey realm = realm(tenant);
        KeyId kid = KeyId.of("pub-" + tenant);

        asserter.execute(() -> rotation.mintPending(realm, kid));
        asserter.execute(() -> rotation.promoteToActive(realm, kid, Instant.parse("2026-06-22T10:00:00Z")));

        asserter.assertThat(
                () -> provider.publishedJwks(realm),
                (List<PublicJwk> jwks) -> {
                    Assertions.assertThat(jwks).extracting(j -> j.keyId().value()).contains(kid.value());
                    // PublicJwk is, by construction, public-only — there is no private member.
                    Assertions.assertThat(jwks).allSatisfy(
                            j -> Assertions.assertThat(j.x()).isNotBlank());
                });
    }

    @Test
    @RunOnVertxContext
    @DisplayName("RLS isolates realms: realm B cannot see realm A's published keys")
    void realmsAreIsolated(UniAsserter asserter) {
        UUID tenantA = UUID.randomUUID();
        UUID tenantB = UUID.randomUUID();
        RealmKey realmA = realm(tenantA);
        RealmKey realmB = realm(tenantB);

        asserter.execute(() -> rotation.mintPending(realmA, KeyId.of("a-only")));
        asserter.execute(() -> rotation.promoteToActive(realmA, KeyId.of("a-only"), Instant.now()));

        // B's view is empty — A's key is invisible across the tenant boundary.
        asserter.assertThat(
                () -> provider.publishedJwks(realmB),
                (List<PublicJwk> jwks) -> Assertions.assertThat(jwks).isEmpty());
        // A still sees exactly its own key.
        asserter.assertThat(
                () -> provider.publishedJwks(realmA),
                (List<PublicJwk> jwks) ->
                        Assertions.assertThat(jwks).extracting(j -> j.keyId().value())
                                .containsExactly("a-only"));
    }

    /** Reconstructs the Ed25519 public key from the published JWK and verifies the signature. */
    private static boolean verifies(
            List<PublicJwk> jwks, KeyId kid, byte[] signingInput, SignatureResult sig) {
        PublicJwk jwk = jwks.stream()
                .filter(j -> j.keyId().equals(kid))
                .findFirst()
                .orElseThrow();
        PublicKey publicKey = decodeOkp(jwk.x());
        return Ed25519Keys.verify(publicKey, signingInput, sig.signature());
    }

    /** Rebuilds an Ed25519 PublicKey from the base64url {@code x} member of an OKP JWK. */
    private static PublicKey decodeOkp(String xBase64Url) {
        try {
            byte[] raw = Base64.getUrlDecoder().decode(xBase64Url);
            boolean xOdd = (raw[raw.length - 1] & 0x80) != 0;
            byte[] yBytes = raw.clone();
            yBytes[yBytes.length - 1] &= (byte) 0x7F;
            // Reverse little-endian Y into a BigInteger.
            byte[] be = new byte[yBytes.length];
            for (int i = 0; i < yBytes.length; i++) {
                be[i] = yBytes[yBytes.length - 1 - i];
            }
            java.math.BigInteger y = new java.math.BigInteger(1, be);
            java.security.spec.EdECPoint point = new java.security.spec.EdECPoint(xOdd, y);
            java.security.spec.EdECPublicKeySpec spec =
                    new java.security.spec.EdECPublicKeySpec(NamedParameterSpec.ED25519, point);
            return KeyFactory.getInstance("Ed25519").generatePublic(spec);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decode OKP JWK", e);
        }
    }
}
