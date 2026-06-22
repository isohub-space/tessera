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

/**
 * Test double for {@link KeyProviderPort}: generates one real Ed25519 key pair in-process
 * and signs with it, so the JWTs the flow mints are genuinely verifiable by the test.
 *
 * <p>This stands in for the persistence-backed provider (owned elsewhere) so the REST
 * adapter can be exercised end-to-end without a database. The private key never leaves this
 * bean — {@link #sign} produces a raw Ed25519 signature, mirroring the production contract.
 * The public key is exposed via {@link #publicKey()} so a test can independently verify a
 * signed JWS.
 */
@Mock
@ApplicationScoped
public class FakeKeyProvider implements KeyProviderPort {

    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private final KeyId keyId = KeyId.of("test-key-1");
    private final KeyPair keyPair = generate();
    private final PublicJwk publicJwk;

    public FakeKeyProvider() {
        String x = B64URL.encodeToString(rawPublicKey(keyPair.getPublic()));
        this.publicJwk = new PublicJwk(keyId, SigningAlgorithm.EdDSA, KeyUse.SIGNATURE, x, null);
    }

    @Override
    public Uni<SignatureResult> sign(RealmKey realm, KeyId keyId, byte[] signingInput) {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(keyPair.getPrivate());
            signature.update(signingInput);
            return Uni.createFrom().item(
                    new SignatureResult(keyId, SigningAlgorithm.EdDSA, signature.sign()));
        } catch (Exception e) {
            return Uni.createFrom().failure(e);
        }
    }

    @Override
    public Uni<List<PublicJwk>> publishedJwks(RealmKey realm) {
        return Uni.createFrom().item(List.of(publicJwk));
    }

    @Override
    public Uni<ActiveKey> currentSigningKey(RealmKey realm) {
        return Uni.createFrom().item(new ActiveKey(keyId, SigningAlgorithm.EdDSA, publicJwk));
    }

    /** The public key, so a test can verify a signed JWS independently. */
    public PublicKey publicKey() {
        return keyPair.getPublic();
    }

    private static KeyPair generate() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Ed25519 unavailable", e);
        }
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
}
