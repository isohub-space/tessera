// Cross-instance correctness of the authorization-code store.
//
// This is the security property the whole store choice exists to protect, so it is asserted
// rather than observed: a code issued by instance A must be redeemable EXACTLY ONCE, and
// must be redeemable VIA INSTANCE B. Three distinct facts, because they fail differently:
//
//   1. cross_instance_redeemable  — issue at A, redeem once at B. A shared store makes this
//      succeed; a per-JVM in-memory store makes it fail. This is the property that makes
//      more than one instance possible at all, and it is the ONLY one of the three that
//      distinguishes a distributed store from the in-memory one.
//
//   2. exactly_once_under_race    — issue at A, then fire redemptions at A and B in the same
//      batch. Exactly one must return 200. Two 200s is DOUBLE ISSUANCE: two access tokens
//      minted from one authorization code (RFC 6749 §10.5), and a hard failure.
//      Note this check passes trivially on the in-memory store — there, B can never succeed,
//      so "exactly one" holds for the wrong reason. It only becomes meaningful once (1) passes.
//
//   3. replay_rejected            — redeem at B, then redeem the same code again at A.
//      The second attempt must be refused.
//
// Instances are addressed DIRECTLY, not through the balancer: the experiment has to choose
// which instance issues and which redeems, and a round-robin balancer takes that choice away.
//
import http from 'k6/http';
import crypto from 'k6/crypto';
import { Counter } from 'k6/metrics';
import { dpopProof } from './dpop.js';

// See login-flow.js: the proof is bound to the server's configured token endpoint, not to
// the address dialled, so every instance validates against this same value.
const DPOP_HTU = __ENV.DPOP_HTU || 'http://localhost:8080/token';

const INSTANCE_URLS = (__ENV.INSTANCE_URLS || '').split(',').map((s) => s.trim()).filter(Boolean);
const TENANT_ID = __ENV.TENANT_ID;
const CLIENT_ID = __ENV.CLIENT_ID || 'perf-client';
const REDIRECT_URI = __ENV.REDIRECT_URI || 'http://perf.invalid/callback';
const ITERATIONS = parseInt(__ENV.CORRECTNESS_ITERATIONS || '200', 10);
const VUS = parseInt(__ENV.CORRECTNESS_VUS || '20', 10);

if (!TENANT_ID) {
  throw new Error('TENANT_ID is required');
}
if (INSTANCE_URLS.length < 2) {
  throw new Error(
    `INSTANCE_URLS needs at least 2 instances to say anything about cross-instance behaviour; got ${INSTANCE_URLS.length}`,
  );
}

const crossInstanceOk = new Counter('cross_instance_redeemable_ok');
const crossInstanceFail = new Counter('cross_instance_redeemable_failed');
const doubleIssuance = new Counter('double_issuance');
const zeroIssuance = new Counter('zero_issuance');
const exactlyOnce = new Counter('exactly_once_ok');
const replayRejected = new Counter('replay_rejected_ok');
const replayAccepted = new Counter('replay_accepted');

export const options = {
  scenarios: {
    cross_instance: {
      executor: 'shared-iterations',
      vus: VUS,
      iterations: ITERATIONS,
      exec: 'crossInstance',
      maxDuration: '5m',
    },
    race: {
      executor: 'shared-iterations',
      vus: VUS,
      iterations: ITERATIONS,
      exec: 'race',
      startTime: '0s',
      maxDuration: '5m',
    },
    replay: {
      executor: 'shared-iterations',
      vus: Math.max(1, Math.floor(VUS / 2)),
      iterations: Math.max(1, Math.floor(ITERATIONS / 2)),
      exec: 'replay',
      maxDuration: '5m',
    },
  },
  thresholds: {
    // The security property. Not a budget, not a percentage — zero.
    double_issuance: [{ threshold: 'count==0', abortOnFail: true }],
    replay_accepted: [{ threshold: 'count==0', abortOnFail: true }],
  },
  maxRedirects: 0,
};

// ---------------------------------------------------------------- the three checks

export async function crossInstance() {
  const issuer = pick(0);
  const redeemer = pick(1);
  const grant = issueCode(issuer);
  if (!grant) {
    return;
  }
  const response = await redeem(redeemer, grant);
  if (response.status === 200) {
    crossInstanceOk.add(1);
  } else {
    crossInstanceFail.add(1);
  }
}

export async function race() {
  const issuer = pick(0);
  const redeemer = pick(1);
  const grant = issueCode(issuer);
  if (!grant) {
    return;
  }

  // Same batch, so both redemptions are in flight together — the closest this harness can
  // get to a genuine simultaneous double redemption across two instances.
  // Both proofs are minted BEFORE the batch so the two redemptions leave together; doing
  // the async work inside the batch would stagger them and weaken the race.
  const first = await redeemRequest(issuer, grant);
  const second = await redeemRequest(redeemer, grant);
  const responses = http.batch([first, second]);

  const successes = responses.filter((r) => r.status === 200).length;
  if (successes > 1) {
    doubleIssuance.add(1);
  } else if (successes === 1) {
    exactlyOnce.add(1);
  } else {
    zeroIssuance.add(1);
  }
}

export async function replay() {
  const issuer = pick(0);
  const redeemer = pick(1);
  const grant = issueCode(issuer);
  if (!grant) {
    return;
  }
  const first = await redeem(redeemer, grant);
  const second = await redeem(issuer, grant);
  // A code that was never redeemable at all (the in-memory case) says nothing about replay,
  // so only count the replay verdict when the first redemption actually succeeded.
  if (first.status !== 200) {
    return;
  }
  if (second.status === 200) {
    replayAccepted.add(1);
  } else {
    replayRejected.add(1);
  }
}

// ---------------------------------------------------------------- flow primitives

function issueCode(baseUrl) {
  const verifier = randomFrom(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~', 64);
  const challenge = crypto.sha256(verifier, 'base64rawurl');
  const state = randomFrom('abcdefghijklmnopqrstuvwxyz0123456789', 16);
  const nonce = randomFrom('abcdefghijklmnopqrstuvwxyz0123456789', 16);

  const url =
    `${baseUrl}/authorize?response_type=code` +
    `&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=openid&state=${state}&nonce=${nonce}` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;

  const response = http.get(url, { headers: authHeaders(), redirects: 0 });
  if (response.status !== 302) {
    return null;
  }
  const location = response.headers['Location'] || response.headers['location'];
  const match = location ? /[?&]code=([^&]+)/.exec(location) : null;
  return match ? { code: decodeURIComponent(match[1]), verifier: verifier } : null;
}

/**
 * Builds one redemption request, carrying its OWN freshly minted DPoP proof.
 *
 * The separate proof per request is load-bearing for the race check. The server treats a
 * DPoP `jti` as single-use, so if both redemptions in a race shared one proof the second
 * would be refused for REPLAYED PROOF rather than for an already-consumed code — and
 * "exactly one succeeded" would pass for entirely the wrong reason, telling us nothing
 * about the authorization-code store. Distinct proofs make the code the only thing the two
 * requests contend over.
 */
async function redeemRequest(baseUrl, grant) {
  return {
    method: 'POST',
    url: `${baseUrl}/token`,
    body: {
      grant_type: 'authorization_code',
      code: grant.code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: grant.verifier,
    },
    params: {
      headers: Object.assign({}, authHeaders(), { DPoP: await dpopProof('POST', DPOP_HTU) }),
    },
  };
}

async function redeem(baseUrl, grant) {
  const request = await redeemRequest(baseUrl, grant);
  return http.post(request.url, request.body, request.params);
}

function authHeaders() {
  return {
    'X-Tenant-Id': TENANT_ID,
    'X-Subject-Id': `perf-correctness-${__VU}-${__ITER}`,
  };
}

/** Rotates which instance plays which role, so no single pairing dominates the result. */
function pick(offset) {
  return INSTANCE_URLS[(__VU + offset) % INSTANCE_URLS.length];
}

function randomFrom(alphabet, length) {
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
  }
  return out;
}

// ---------------------------------------------------------------- reporting

export function handleSummary(data) {
  const name = __ENV.RUN_NAME || 'correctness';
  const count = (metric) => (data.metrics[metric] ? data.metrics[metric].values.count || 0 : 0);

  const ok = count('cross_instance_redeemable_ok');
  const failed = count('cross_instance_redeemable_failed');
  const doubles = count('double_issuance');
  const once = count('exactly_once_ok');
  const zero = count('zero_issuance');
  const rejected = count('replay_rejected_ok');
  const accepted = count('replay_accepted');

  const lines = [];
  lines.push(`# ${name}`);
  lines.push(`instances: ${INSTANCE_URLS.join(', ')}`);
  lines.push('');
  lines.push('1. cross-instance redeemable (issue at A, redeem at B)');
  lines.push(`     redeemed: ${ok}   refused: ${failed}`);
  lines.push(
    failed === 0 && ok > 0
      ? '     => SHARED STORE: a code issued on one instance is redeemable on another.'
      : ok === 0
        ? '     => NOT SHARED: no code issued on one instance was redeemable on another.'
        : '     => PARTIAL: some cross-instance redemptions failed — investigate before trusting HA.',
  );
  lines.push('');
  lines.push('2. exactly once under concurrent cross-instance redemption');
  lines.push(`     exactly one 200: ${once}   DOUBLE ISSUANCE: ${doubles}   neither: ${zero}`);
  lines.push(
    doubles === 0
      ? '     => PASS: no code ever produced two tokens.'
      : `     => FAIL: ${doubles} codes were redeemed twice. This is a security defect.`,
  );
  if (failed > 0 && doubles === 0) {
    lines.push(
      '     NOTE: this passes trivially while check 1 is failing — with a per-JVM store the',
    );
    lines.push(
      '     second instance can never succeed, so "exactly one" holds for the wrong reason.',
    );
  }
  lines.push('');
  lines.push('3. replay rejected (redeem at B, then replay at A)');
  lines.push(`     rejected: ${rejected}   ACCEPTED: ${accepted}`);
  lines.push(accepted === 0 ? '     => PASS.' : `     => FAIL: ${accepted} replays were accepted.`);
  lines.push('');

  const text = lines.join('\n') + '\n';
  const out = {};
  out.stdout = text;
  out[`/results/${name}.txt`] = text;
  out[`/results/${name}.json`] = JSON.stringify(data, null, 2);
  return out;
}
