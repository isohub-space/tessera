// DPoP proof minting (RFC 9449) for the load driver.
//
// This is not optional decoration: a PUBLIC client cannot obtain a token from this server
// without one. `/token` refuses a public client that presents no proof, and there is no
// configuration that relaxes it — sender-constraining is enforced by construction. So a
// harness that skipped DPoP would be measuring a flow the server does not actually offer.
//
// What the server validates, and therefore what this must get right:
//   typ  = "dpop+jwt"
//   alg  = ES256 (ECDSA P-256) — the ONLY algorithm this build accepts
//   jwk  = the public key, embedded in the header, non-private
//   htm  = "POST"
//   htu  = the CONFIGURED token endpoint, not the URL the driver happened to dial. The
//          server derives it from its issuer so a proof cannot be bound to a foreign
//          authority, so the driver must use that same configured value.
//   iat  = fresh, within the proof max-age (1 minute) plus clock skew
//   jti  = SINGLE USE. The server keeps spent jtis for the freshness window, so proofs
//          cannot be pre-generated in bulk and replayed — every request mints a new one.
//
// The key pair is generated once per virtual user and reused across that VU's iterations,
// which is what a real client does: one key, many proofs. Generating a key per iteration
// would measure ECDSA keygen in the driver rather than the login flow in the server.
//
import { crypto } from 'k6/experimental/webcrypto';
import encoding from 'k6/encoding';

// Module scope is per-VU in k6, so this cache is naturally per virtual user.
let keyPair = null;
let publicJwk = null;
let jtiCounter = 0;

/** Generates this VU's ECDSA P-256 key pair once, and caches its public JWK. */
async function ensureKey() {
  if (keyPair !== null) {
    return;
  }
  keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  );
  const exported = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
  // Only the public members, and in the shape Nimbus parses as an ECKey. An exported
  // private member here would be rejected outright (the server refuses a private jwk).
  publicJwk = { kty: exported.kty, crv: exported.crv, x: exported.x, y: exported.y };
}

/**
 * Mints one fresh DPoP proof.
 *
 * @param htm the HTTP method the proof is bound to
 * @param htu the CONFIGURED token endpoint URL
 * @returns {Promise<string>} the compact JWS
 */
export async function dpopProof(htm, htu) {
  await ensureKey();

  const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: publicJwk };
  const payload = {
    jti: newJti(),
    htm: htm,
    htu: htu,
    iat: Math.floor(Date.now() / 1000),
  };

  const signingInput =
    encoding.b64encode(JSON.stringify(header), 'rawurl') +
    '.' +
    encoding.b64encode(JSON.stringify(payload), 'rawurl');

  // ECDSA sign returns the raw r||s pair (64 bytes for P-256), which is exactly the JWS
  // ES256 signature encoding — no DER unwrapping needed.
  const signature = await crypto.subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    keyPair.privateKey,
    toBuffer(signingInput),
  );

  return signingInput + '.' + encoding.b64encode(signature, 'rawurl');
}

/**
 * A jti unique across VUs and iterations. The server rejects a repeat within the freshness
 * window, so a collision would show up as a spurious token failure and be misread as
 * server saturation.
 */
function newJti() {
  jtiCounter += 1;
  return `${__VU}-${__ITER}-${jtiCounter}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function toBuffer(text) {
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    bytes[i] = text.charCodeAt(i);
  }
  return bytes.buffer;
}
