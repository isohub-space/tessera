package dev.tessera.iam.adapter.rest.support;

import io.quarkus.test.Mock;
import io.smallrye.mutiny.Uni;
import dev.tessera.iam.application.port.out.ActiveKey;
import dev.tessera.iam.application.port.out.KeyProviderPort;
import dev.tessera.iam.application.port.out.SignatureResult;
import dev.tessera.iam.domain.signingkey.KeyId;
import dev.tessera.iam.domain.signingkey.KeyUse;
import dev.tessera.iam.domain.signingkey.PublicJwk;
import dev.tessera.iam.domain.signingkey.SigningAlgorithm;
import dev.tessera.iam.domain.tenancy.RealmKey;
import jakarta.enterprise.context.ApplicationScoped;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Test double for {@link KeyProviderPort}: mints a distinct, real Ed25519 key pair per
 * {@link RealmKey} lazily, on first use, so the JWTs the flow mints are genuinely verifiable
 * and a {@code kid} minted for one realm never appears in another realm's JWKS — mirroring the
 * RLS-scoped isolation of the production {@code DbKeyProviderAdapter}.
 *
 * <p>This stands in for the persistence-backed provider (owned elsewhere) so the REST
 * adapter can be exercised end-to-end without a database. Private key material never leaves
 * this bean — {@link #sign} produces a raw Ed25519 signature, mirroring the production
 * contract. {@link #publicKey(RealmKey)} exposes a realm's public key so a test can
 * independently verify a signed JWS.
 */
@Mock
@ApplicationScoped
public class FakeKeyProvider implements KeyProviderPort {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final ConcurrentMap<RealmKey, RealmKeyPair> byRealm = new ConcurrentHashMap<>();

    @Override
    public Uni<SignatureResult> sign(RealmKey realm, KeyId keyId, byte[] signingInput) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(keysFor(realm).keyPair().getPrivate());
            signature.update(signingInput);
            return Uni.createFrom().item(
                    new SignatureResult(keyId, SigningAlgorithm.EdDSA, signature.sign()));
        } catch (Exception e) {
            return Uni.createFrom().failure(e);
        }
    }

    @Override
    public Uni<List<PublicJwk>> publishedJwks(RealmKey realm) {
        return Uni.createFrom().item(List.of(keysFor(realm).publicJwk()));
    }

    @Override
    public Uni<ActiveKey> currentSigningKey(RealmKey realm) {
        RealmKeyPair keys = keysFor(realm);
        return Uni.createFrom()
                .item(new ActiveKey(keys.keyId(), SigningAlgorithm.EdDSA, keys.publicJwk()));
    }

    /** The public key minted for {@code realm}, so a test can verify a signed JWS independently. */
    public PublicKey publicKey(RealmKey realm) {
        return keysFor(realm).keyPair().getPublic();
    }

    private RealmKeyPair keysFor(RealmKey realm) {
        return byRealm.computeIfAbsent(realm, ignored -> RealmKeyPair.generate());
    }

    /** Extracts the 32-byte little-endian public point from the JDK EdEC public key. */
    private static byte[] rawPublicKey(PublicKey publicKey) {
        EdECPublicKey edKey = (EdECPublicKey) publicKey;
        byte[] le = edKey.getPoint().getY().toByteArray();
        // BigInteger is big-endian; reverse to little-endian and right-pad to 32 bytes.
        byte[] reversed = new byte[le.length];
        for (int i = 0; i < le.length; i++) {
            reversed[i] = le[le.length - 1 - i];
        }
        byte[] out = new byte[32];
        System.arraycopy(reversed, 0, out, 0, Math.min(reversed.length, 32));
        if (edKey.getPoint().isXOdd()) {
            out[31] |= (byte) 0x80;
        }
        return out;
    }

    /** One realm's lazily-minted key material: a realm-unique {@code kid}, key pair and JWK. */
    private record RealmKeyPair(KeyId keyId, KeyPair keyPair, PublicJwk publicJwk) {

        static RealmKeyPair generate() {
            KeyId keyId = KeyId.of("test-key-" + UUID.randomUUID());
            KeyPair keyPair = generateKeyPair();
            String x = B64URL.encodeToString(rawPublicKey(keyPair.getPublic()));
            PublicJwk publicJwk =
                    new PublicJwk(keyId, SigningAlgorithm.EdDSA, KeyUse.SIGNATURE, x, null);
            return new RealmKeyPair(keyId, keyPair, publicJwk);
        }

        private static KeyPair generateKeyPair() {
            try {
                return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
            } catch (Exception e) {
                throw new IllegalStateException("Ed25519 unavailable", e);
            }
        }
    }
}
