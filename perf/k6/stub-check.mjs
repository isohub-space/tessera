// Offline checks for the driver's REQUEST CONSTRUCTION and VERDICT LOGIC.
//
// k6 scripts cannot be unit-tested by k6 itself, and the parts most likely to be quietly
// wrong are not the ones a syntax check sees: whether the authorize URL carries a legal PKCE
// challenge, whether the code is actually pulled out of the 302, whether the token form
// carries the verifier that matches it — and, most of all, whether the double-issuance
// assertion FIRES when two instances both return a token. An assertion that cannot fail is
// worse than no assertion, so this proves it fails on a synthetic double issuance.
//
// Run via perf/scripts/dry-run.sh, or directly:  node perf/k6/stub-check.mjs perf/k6
//
import { mkdtempSync, writeFileSync, copyFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

const SRC = process.argv[2] || new URL('.', import.meta.url).pathname;

// ---------------------------------------------------------------- stub k6 runtime

const dir = mkdtempSync(join(tmpdir(), 'k6-stub-'));
mkdirSync(join(dir, 'node_modules', 'k6'), { recursive: true });
const mod = (name, body) => writeFileSync(join(dir, 'node_modules', 'k6', name), body);

writeFileSync(join(dir, 'package.json'), '{"type":"module"}');
mod('package.json', JSON.stringify({
  name: 'k6', version: '0.0.0', type: 'module',
  exports: { '.': './index.js', './crypto': './crypto.js', './metrics': './metrics.js', './http': './http.js' },
}));
mod('index.js', 'export function check(){return true} export function sleep(){} export default {}');
mod('crypto.js', `
import { createHash } from 'node:crypto';
export default {
  sha256(input, encoding) {
    const h = createHash('sha256').update(input);
    return encoding === 'base64rawurl' ? h.digest('base64url') : h.digest('hex');
  },
};
`);
mod('metrics.js', `
function bump(name, value) {
  globalThis.__m[name] = (globalThis.__m[name] || 0) + value;
}
export class Trend   { constructor(n){this.n=n} add(v){ bump(this.n + ':sum', v); bump(this.n + ':n', 1); } }
export class Counter { constructor(n){this.n=n} add(v){ bump(this.n, v); } }
export class Rate    { constructor(n){this.n=n} add(v){ bump(this.n + (v ? ':true' : ':false'), 1); } }
`);
mod('http.js', `
export default {
  get(url, params)        { return globalThis.__stub.get(url, params); },
  post(url, body, params) { return globalThis.__stub.post(url, body, params); },
  batch(requests)         { return globalThis.__stub.batch(requests); },
};
`);

for (const file of ['login-flow.js', 'correctness.js']) {
  copyFileSync(join(SRC, file), join(dir, file));
}

globalThis.__m = {};
globalThis.__VU = 1;
globalThis.__ITER = 0;
globalThis.__ENV = {
  TENANT_ID: '0de00000-0000-4000-a000-00000000d3f0',
  CLIENT_ID: 'perf-client',
  REDIRECT_URI: 'http://perf.invalid/callback',
  INSTANCE_URLS: 'http://app1:8090,http://app2:8090',
  BASE_URL: 'http://lb:8080',
};

const loginFlow = await import(pathToFileURL(join(dir, 'login-flow.js')).href);
const correctness = await import(pathToFileURL(join(dir, 'correctness.js')).href);

// ---------------------------------------------------------------- harness

let failures = 0;
const results = [];
function check(name, condition, detail) {
  results.push({ name, ok: !!condition, detail });
  if (!condition) failures++;
}
/** Counter delta across one call, so module-scoped metric state does not leak between cases. */
function delta(name, before) {
  return (globalThis.__m[name] || 0) - (before[name] || 0);
}
function snapshot() {
  return { ...globalThis.__m };
}

const ok302 = (code) => ({
  status: 302,
  headers: { Location: `http://perf.invalid/callback?code=${code}&state=x&iss=y` },
  timings: { duration: 4 },
});
const okToken = { status: 200, body: '{"access_token":"eyJ...","token_type":"Bearer"}', timings: { duration: 7 } };

// ---------------------------------------------------------------- 1. happy-path login

let authorizeUrl = null;
let tokenCall = null;
globalThis.__stub = {
  get(url) { authorizeUrl = url; return ok302('CODE-ABC'); },
  post(url, body, params) { tokenCall = { url, body, params }; return okToken; },
  batch() { return []; },
};

let before = snapshot();
loginFlow.login();

const params = new URL(authorizeUrl).searchParams;
check('authorize requests response_type=code', params.get('response_type') === 'code');
check('authorize sends S256', params.get('code_challenge_method') === 'S256');
check('authorize sends state and nonce', !!params.get('state') && !!params.get('nonce'));
check('authorize sends the registered redirect_uri',
  params.get('redirect_uri') === 'http://perf.invalid/callback');

const challenge = params.get('code_challenge');
check('challenge is 43 unpadded base64url chars (domain: CodeChallenge)',
  /^[A-Za-z0-9_-]{43}$/.test(challenge), `got '${challenge}'`);

check('token redeems the code from the 302', tokenCall && tokenCall.body.code === 'CODE-ABC');
check('token sends grant_type=authorization_code',
  tokenCall.body.grant_type === 'authorization_code');
check('token sends client_id and redirect_uri',
  tokenCall.body.client_id === 'perf-client'
  && tokenCall.body.redirect_uri === 'http://perf.invalid/callback');

// The verifier the token step sends must be the one the challenge was derived from, or the
// server rejects every redemption and the run measures a broken flow at full speed.
const verifier = tokenCall.body.code_verifier;
check('verifier is 43-128 unreserved chars (RFC 7636 §4.1)',
  /^[A-Za-z0-9\-._~]{43,128}$/.test(verifier), `length ${verifier ? verifier.length : 0}`);
check('challenge is SHA-256 of the verifier actually sent',
  createHash('sha256').update(verifier).digest('base64url') === challenge);

check('tenant header is sent on authorize and token',
  tokenCall.params.headers['X-Tenant-Id'] === globalThis.__ENV.TENANT_ID);
check('subject header is sent', !!tokenCall.params.headers['X-Subject-Id']);
check('a successful login is counted as a success', delta('login_success:true', before) === 1);

// ---------------------------------------------------------------- 2. failure paths

before = snapshot();
globalThis.__stub = {
  get() { return { status: 429, headers: {}, timings: { duration: 1 } }; },
  post() { throw new Error('token must not be called when authorize failed'); },
  batch() { return []; },
};
loginFlow.login();
check('a throttled authorize is a failed login', delta('login_success:false', before) === 1);
check('a throttled authorize is counted against authorize', delta('login_authorize_failed', before) === 1);

before = snapshot();
globalThis.__stub = {
  get() { return { status: 302, headers: { Location: 'http://perf.invalid/callback?error=access_denied' }, timings: { duration: 1 } }; },
  post() { throw new Error('token must not be called without a code'); },
  batch() { return []; },
};
loginFlow.login();
check('a 302 carrying an error, not a code, is a failed login',
  delta('login_success:false', before) === 1);

before = snapshot();
globalThis.__stub = {
  get() { return ok302('CODE-XYZ'); },
  post() { return { status: 400, body: '{"error":"invalid_grant"}', timings: { duration: 3 } }; },
  batch() { return []; },
};
loginFlow.login();
check('a refused token redemption is a failed login', delta('login_success:false', before) === 1);
check('a refused token redemption is counted against token', delta('login_token_failed', before) === 1);

// ---------------------------------------------------------------- 3. the security assertion

// The check that matters: if two instances both mint a token from one code, does the harness
// actually notice? Synthesise exactly that and require the counter to fire.
before = snapshot();
globalThis.__stub = {
  get() { return ok302('CODE-RACE'); },
  post() { return okToken; },
  batch(requests) {
    check('race redeems at two DIFFERENT instances',
      requests.length === 2 && requests[0].url !== requests[1].url,
      requests.map((r) => r.url).join(' vs '));
    check('both redemptions carry the same code',
      requests[0].body.code === 'CODE-RACE' && requests[1].body.code === 'CODE-RACE');
    return [{ status: 200, body: 'a' }, { status: 200, body: 'b' }];
  },
};
correctness.race();
check('DOUBLE ISSUANCE is detected when two instances both issue a token',
  delta('double_issuance', before) === 1);

before = snapshot();
globalThis.__stub.batch = () => [{ status: 200, body: 'a' }, { status: 400, body: 'b' }];
correctness.race();
check('exactly-one redemption is recorded as correct', delta('exactly_once_ok', before) === 1);
check('exactly-one redemption raises no double-issuance alarm',
  delta('double_issuance', before) === 0);

before = snapshot();
globalThis.__stub.batch = () => [{ status: 400, body: 'a' }, { status: 400, body: 'b' }];
correctness.race();
check('a code redeemed nowhere is recorded, not silently dropped',
  delta('zero_issuance', before) === 1);

// ---------------------------------------------------------------- 4. cross-instance verdicts

before = snapshot();
globalThis.__stub = {
  get() { return ok302('CODE-CROSS'); },
  post() { return okToken; },
  batch() { return []; },
};
correctness.crossInstance();
check('a code redeemable on another instance counts as shared-store evidence',
  delta('cross_instance_redeemable_ok', before) === 1);

before = snapshot();
globalThis.__stub.post = () => ({ status: 400, body: '{"error":"invalid_grant"}' });
correctness.crossInstance();
check('a code refused by another instance counts as NOT shared',
  delta('cross_instance_redeemable_failed', before) === 1);

// A replay accepted after a successful first redemption must be flagged.
before = snapshot();
let redemption = 0;
globalThis.__stub.post = () => (++redemption === 1
  ? okToken
  : { status: 200, body: '{"access_token":"second"}' });
correctness.replay();
check('an accepted replay is flagged', delta('replay_accepted', before) === 1);

before = snapshot();
redemption = 0;
globalThis.__stub.post = () => (++redemption === 1 ? okToken : { status: 400, body: 'no' });
correctness.replay();
check('a rejected replay is recorded as correct', delta('replay_rejected_ok', before) === 1);

// ---------------------------------------------------------------- report

for (const r of results) {
  process.stdout.write(`    ${r.ok ? 'ok  ' : 'FAIL'}  ${r.name}${r.detail && !r.ok ? ` — ${r.detail}` : ''}\n`);
}
process.stdout.write(`    ${results.length - failures}/${results.length} driver checks passed\n`);
process.exit(failures === 0 ? 0 : 1);
