package dev.tessera.iam.adapter.rest;

import static io.restassured.RestAssured.given;
import static org.assertj.core.api.Assertions.assertThat;

import dev.tessera.iam.adapter.rest.support.FakeClientRepository;
import dev.tessera.iam.adapter.rest.support.FakeClientSecretVerifier;
import dev.tessera.iam.domain.tenancy.BaselineId;
import dev.tessera.iam.domain.tenancy.RealmKey;
import dev.tessera.iam.domain.tenancy.TenantId;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Forged and confused JWTs presented to {@code POST /introspect} (RFC 7662). Every forgery must be
 * answered {@code 200} with exactly {@code {"active":false}}, the non-oracle response, and nothing
 * else.
 *
 * <p>Each forgery changes one thing against {@link #controlTokenIsActive() a control token} that
 * the server accepts, and where it matters the forgery still carries a valid EdDSA signature by the
 * realm's own key. That isolates the header check under test: without it the signature would
 * verify and the token would be reported active. The threat rows and the defence each case pins are
 * listed in {@code docs/security/threat-model.md}.
 */
@QuarkusTest
@DisplayName("POST /introspect: forged, downgraded and confused JWTs are inactive, never an oracle")
class IntrospectForgedTokenTest extends AuthorizationCodeFlowSupport {

    private static final String CALLER = FakeClientRepository.CONFIDENTIAL_CLIENT_ID;
    private static final String CALLER_SECRET = FakeClientSecretVerifier.CORRECT_SECRET;
    private static final Map<String, Object> INACTIVE = Map.of("active", false);

    @Test
    @DisplayName("control: a well-formed EdDSA at+jwt signed by the realm key is active")
    void controlTokenIsActive() {
        introspect(forge("EdDSA", "at+jwt", kid(), payload(ISSUER, ISSUER), Sig.REALM_EDDSA))
                .then().statusCode(200)
                .body("active", org.hamcrest.Matchers.is(true));
    }

    @Test
    @DisplayName("alg:none with an empty signature is inactive")
    void algNoneUnsigned() {
        assertInactive(forge("none", "at+jwt", kid(), payload(ISSUER, ISSUER), Sig.EMPTY));
    }

    @Test
    @DisplayName("alg:none carrying a valid realm-key signature is still inactive (alg allow-list)")
    void algNoneOverValidSignature() {
        assertInactive(forge("none", "at+jwt", kid(), payload(ISSUER, ISSUER), Sig.REALM_EDDSA));
    }

    @Test
    @DisplayName("HS256 keyed with the realm's public key, in any encoding (key confusion), is inactive")
    void hs256KeyedWithPublicKey() {
        // Whichever encoding a verifier that picks the algorithm from the header would feed to HMAC.
        for (Sig keyEncoding : new Sig[] {
                Sig.HMAC_WITH_JWK_X, Sig.HMAC_WITH_RAW_KEY, Sig.HMAC_WITH_DER_KEY, Sig.HMAC_WITH_PEM_KEY}) {
            assertInactive(forge("HS256", "at+jwt", kid(), payload(ISSUER, ISSUER), keyEncoding));
        }
    }

    @Test
    @DisplayName("HS256 header over a valid realm-key signature is inactive (alg allow-list)")
    void hs256HeaderOverValidSignature() {
        assertInactive(forge("HS256", "at+jwt", kid(), payload(ISSUER, ISSUER), Sig.REALM_EDDSA));
    }

    @Test
    @DisplayName("RS256 signed by an attacker RSA key under the realm kid is inactive")
    void rs256AttackerKey() {
        assertInactive(forge("RS256", "at+jwt", kid(), payload(ISSUER, ISSUER), Sig.ATTACKER_RSA));
    }

    @Test
    @DisplayName("RS256 header over a valid realm-key signature is inactive (alg allow-list)")
    void rs256HeaderOverValidSignature() {
        assertInactive(forge("RS256", "at+jwt", kid(), payload(ISSUER, ISSUER), Sig.REALM_EDDSA));
    }

    @Test
    @DisplayName("typ JWT, or no typ, over a valid realm-key signature is inactive (RFC 9068 typ)")
    void typOtherThanAccessToken() {
        assertInactive(forge("EdDSA", "JWT", kid(), payload(ISSUER, ISSUER), Sig.REALM_EDDSA));
        assertInactive(forge("EdDSA", null, kid(), payload(ISSUER, ISSUER), Sig.REALM_EDDSA));
    }

    @Test
    @DisplayName("an unknown kid over a valid realm-key signature is inactive (no key fallback)")
    void unknownKid() {
        assertInactive(forge("EdDSA", "at+jwt", "kid-" + UUID.randomUUID(),
                payload(ISSUER, ISSUER), Sig.REALM_EDDSA));
        assertInactive(forge("EdDSA", "at+jwt", null, payload(ISSUER, ISSUER), Sig.REALM_EDDSA));
    }

    @Test
    @DisplayName("an attacker key embedded as a jwk header, under the realm kid, is never used: inactive")
    void embeddedJwkIsIgnored() {
        KeyPair attacker = ed25519();
        String jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\""
                + B64URL.encodeToString(raw(attacker.getPublic())) + "\"}";
        assertInactive(signedBy(attacker, "\"jwk\":" + jwk));
    }

    @Test
    @DisplayName("a jku header pointing at an attacker's key set, under the realm kid, is never fetched: inactive")
    void jkuIsIgnored() {
        assertInactive(signedBy(ed25519(), "\"jku\":\"https://attacker.example/jwks.json\""));
    }

    @Test
    @DisplayName("an attacker certificate in an x5c header, under the realm kid, is never used: inactive")
    void x5cIsIgnored() throws Exception {
        KeyPair attacker = ed25519();
        byte[] certificate = selfSignedCertificate(attacker);
        // The forgery is genuine: the chain parses, and its key is the one that signed the token.
        X509Certificate parsed = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate));
        parsed.verify(attacker.getPublic());
        assertThat(parsed.getPublicKey().getEncoded()).isEqualTo(attacker.getPublic().getEncoded());

        assertInactive(signedBy(attacker,
                "\"x5c\":[\"" + Base64.getEncoder().encodeToString(certificate) + "\"]"));
    }

    @Test
    @DisplayName("a token signed by another realm's key under that realm's kid is inactive here")
    void otherRealmsKid() {
        RealmKey other = new RealmKey(new TenantId(UUID.randomUUID()), new BaselineId(new UUID(0L, 0L)));
        String header = header("EdDSA", "at+jwt", keyProvider.keyId(other));
        String signingInput = header + "." + payload(ISSUER, ISSUER);
        String token = signingInput + "."
                + B64URL.encodeToString(keyProvider.signRaw(other, ascii(signingInput)));

        assertInactive(token);
    }

    /**
     * Pins today's behaviour while the introspection {@code iss}/{@code aud} decision is open (see
     * the decision section of {@code docs/security/threat-model.md}): a token signed by the realm's
     * key is reported active whatever its {@code iss} and {@code aud}, and the response echoes
     * neither. Deciding to compare {@code iss} at introspection flips this test on purpose.
     */
    @Test
    @DisplayName("today introspection asserts neither iss nor aud and echoes neither")
    void issAndAudAreNotAssertedByIntrospection() {
        String token = forge("EdDSA", "at+jwt", kid(),
                payload("https://other-issuer.example", "https://other-resource.example"),
                Sig.REALM_EDDSA);

        Map<String, Object> body = introspect(token).then().statusCode(200)
                .extract().jsonPath().getMap("$");
        assertThat(body).containsEntry("active", true).doesNotContainKeys("iss", "aud");
    }

    // --------------------------------------------------------------------- helpers

    /** How the third JWS segment is produced. */
    private enum Sig {
        EMPTY, REALM_EDDSA, ATTACKER_RSA,
        HMAC_WITH_JWK_X, HMAC_WITH_RAW_KEY, HMAC_WITH_DER_KEY, HMAC_WITH_PEM_KEY
    }

    private String kid() {
        return keyProvider.keyId(REALM);
    }

    private String forge(String alg, String typ, String kid, String payloadB64, Sig sig) {
        String signingInput = header(alg, typ, kid) + "." + payloadB64;
        byte[] input = ascii(signingInput);
        byte[] signature = switch (sig) {
            case EMPTY -> new byte[0];
            case REALM_EDDSA -> keyProvider.signRaw(REALM, input);
            case HMAC_WITH_JWK_X -> hmac(publishedX().getBytes(StandardCharsets.US_ASCII), input);
            case HMAC_WITH_RAW_KEY -> hmac(raw(realmPublicKey()), input);
            case HMAC_WITH_DER_KEY -> hmac(realmPublicKey().getEncoded(), input);
            case HMAC_WITH_PEM_KEY -> hmac(pem(realmPublicKey()).getBytes(StandardCharsets.US_ASCII), input);
            case ATTACKER_RSA -> rsa(input);
        };
        return signingInput + "." + B64URL.encodeToString(signature);
    }

    /** An EdDSA at+jwt under the realm kid, signed by {@code signer}, with extra header members. */
    private String signedBy(KeyPair signer, String extraHeaderMembers) {
        String header = B64URL.encodeToString(("{\"alg\":\"EdDSA\",\"typ\":\"at+jwt\",\"kid\":\"" + kid()
                + "\"," + extraHeaderMembers + "}").getBytes(StandardCharsets.UTF_8));
        String signingInput = header + "." + payload(ISSUER, ISSUER);
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(signer.getPrivate());
            signature.update(ascii(signingInput));
            return signingInput + "." + B64URL.encodeToString(signature.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String header(String alg, String typ, String kid) {
        StringBuilder json = new StringBuilder("{\"alg\":\"").append(alg).append('"');
        if (typ != null) {
            json.append(",\"typ\":\"").append(typ).append('"');
        }
        if (kid != null) {
            json.append(",\"kid\":\"").append(kid).append('"');
        }
        return B64URL.encodeToString(json.append('}').toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String payload(String iss, String aud) {
        long now = Instant.now().getEpochSecond();
        String json = "{\"iss\":\"" + iss + "\",\"sub\":\"forged-subject\",\"aud\":\"" + aud
                + "\",\"client_id\":\"" + FakeClientRepository.PUBLIC_CLIENT_ID
                + "\",\"iat\":" + now + ",\"exp\":" + (now + 300)
                + ",\"jti\":\"" + UUID.randomUUID() + "\",\"scope\":\"openid\"}";
        return B64URL.encodeToString(json.getBytes(StandardCharsets.UTF_8));
    }

    /** The realm key's published {@code x}, as an attacker reads it from the JWKS. */
    private String publishedX() {
        return keyProvider.publishedJwks(REALM).await().indefinitely().getFirst().x();
    }

    private PublicKey realmPublicKey() {
        return keyProvider.publicKey(REALM);
    }

    /** The 32-byte RFC 8032 public key: the tail of the X.509 SubjectPublicKeyInfo encoding. */
    private static byte[] raw(PublicKey key) {
        byte[] spki = key.getEncoded();
        return java.util.Arrays.copyOfRange(spki, spki.length - 32, spki.length);
    }

    private static String pem(PublicKey key) {
        return "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(key.getEncoded())
                + "\n-----END PUBLIC KEY-----\n";
    }

    private static KeyPair ed25519() {
        try {
            return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A minimal self-signed X.509 (v1) certificate for an Ed25519 key, DER-encoded. */
    private static byte[] selfSignedCertificate(KeyPair keys) throws Exception {
        byte[] ed25519 = der(0x30, der(0x06, new byte[] {0x2B, 0x65, 0x70})); // id-Ed25519
        byte[] name = der(0x30, der(0x31, der(0x30, concat(
                der(0x06, new byte[] {0x55, 0x04, 0x03}), der(0x0C, ascii("attacker"))))));
        byte[] validity = der(0x30, concat(der(0x17, ascii("250101000000Z")), der(0x17, ascii("350101000000Z"))));
        byte[] tbs = der(0x30, concat(der(0x02, new byte[] {0x01}), ed25519, name, validity, name,
                keys.getPublic().getEncoded()));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(keys.getPrivate());
        signer.update(tbs);
        return der(0x30, concat(tbs, ed25519, der(0x03, concat(new byte[] {0x00}, signer.sign()))));
    }

    private static byte[] der(int tag, byte[] content) {
        int length = content.length;
        byte[] encodedLength = length < 0x80 ? new byte[] {(byte) length}
                : length < 0x100 ? new byte[] {(byte) 0x81, (byte) length}
                : new byte[] {(byte) 0x82, (byte) (length >> 8), (byte) length};
        return concat(new byte[] {(byte) tag}, encodedLength, content);
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            out.writeBytes(part);
        }
        return out.toByteArray();
    }

    private static byte[] hmac(byte[] secret, byte[] input) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return mac.doFinal(input);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] rsa(byte[] input) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(generator.generateKeyPair().getPrivate());
            signer.update(input);
            return signer.sign();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] ascii(String value) {
        return value.getBytes(StandardCharsets.US_ASCII);
    }

    private void assertInactive(String token) {
        Response response = introspect(token);
        response.then().statusCode(200).header("Cache-Control", "no-store");
        assertThat(response.jsonPath().getMap("$")).as("RFC 7662 non-oracle body").isEqualTo(INACTIVE);
    }

    private Response introspect(String token) {
        return given().config(noFollow())
                .header("X-Tenant-Id", TENANT)
                .contentType("application/x-www-form-urlencoded")
                .formParam("token", token)
                .formParam("client_id", CALLER)
                .formParam("client_secret", CALLER_SECRET)
                .when().post("/introspect");
    }
}
