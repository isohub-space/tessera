// Exploratory load profile for the Authorization Code + PKCE login flow.
//
// One iteration is ONE complete login: GET /authorize -> read the code out of the 302
// Location -> POST /token -> assert an access token came back. Nothing is mocked and no
// production code is touched; the service is driven over HTTP exactly as a client would.
//
// The executors are ARRIVAL-RATE (open model), not a fixed pool of virtual users. That is
// the whole point of the experiment: the question is "how many logins per minute can the
// system absorb", which is a property of offered arrival rate. A closed VU model cannot
// answer it — when the system slows down a closed model slows its own offered load with it
// and politely hides the saturation we are trying to find.
//
// Profiles:
//   steps  (default) a staircase of constant arrival rates, each held for STEP_DURATION,
//          each tagged with its level, so latency is reported PER LOAD LEVEL rather than
//          smeared into one meaningless aggregate.
//   steady a single constant arrival rate — for confirming a candidate ceiling.
//   ramp   a continuous ramp from 0 to RAMP_TO — this measures RATE OF CLIMB, which is a
//          different and usually lower limit than the steady-state ceiling.
//
import http from 'k6/http';
import crypto from 'k6/crypto';
import { Trend, Rate, Counter } from 'k6/metrics';

// ---------------------------------------------------------------- configuration

const BASE_URL = __ENV.BASE_URL || 'http://lb:8080';
const TENANT_ID = __ENV.TENANT_ID;
const CLIENT_ID = __ENV.CLIENT_ID || 'perf-client';
const REDIRECT_URI = __ENV.REDIRECT_URI || 'http://perf.invalid/callback';

const PROFILE = __ENV.PROFILE || 'steps';
const STEP_DURATION = __ENV.STEP_DURATION || '60s';
const STEP_GAP_S = parseInt(__ENV.STEP_GAP_S || '15', 10);
const STEPS = (__ENV.STEPS || '10,25,50,100,200,400')
  .split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => n > 0);

const RATE = parseInt(__ENV.RATE || '50', 10);
const DURATION = __ENV.DURATION || '120s';
const RAMP_TO = parseInt(__ENV.RAMP_TO || '400', 10);
const RAMP_DURATION = __ENV.RAMP_DURATION || '300s';

// The degradation criterion, named UP FRONT so the ceiling is a measurement and not an
// opinion formed after looking at the graph. A level "holds" only if BOTH hold.
const ERROR_BUDGET = parseFloat(__ENV.ERROR_BUDGET || '0.01');   // >1% failed logins = degraded
const P99_BUDGET_MS = parseInt(__ENV.P99_BUDGET_MS || '1000', 10); // p99 of the full exchange

if (!TENANT_ID) {
  throw new Error('TENANT_ID is required (the gateway-asserted X-Tenant-Id header)');
}

// ---------------------------------------------------------------- metrics

const loginTotal = new Trend('login_total', true);      // authorize + token, end to end
const authorizeDuration = new Trend('login_authorize', true);
const tokenDuration = new Trend('login_token', true);
const loginSuccess = new Rate('login_success');
const authorizeFailures = new Counter('login_authorize_failed');
const tokenFailures = new Counter('login_token_failed');

// ---------------------------------------------------------------- scenarios

const scenarios = {};
const thresholds = {};

// Thresholds are built programmatically so each load level gets its own tagged sub-metric.
// k6 only breaks a metric down by tag in the summary when a threshold names that tag, so
// this is also what makes the per-level latency table possible at all.
function levelThresholds(level) {
  thresholds[`login_success{level:${level}}`] = [
    { threshold: `rate>=${1 - ERROR_BUDGET}`, abortOnFail: false },
  ];
  thresholds[`login_total{level:${level}}`] = [
    { threshold: `p(99)<${P99_BUDGET_MS}`, abortOnFail: false },
  ];
}

// An open model must be allowed enough VUs to actually deliver the offered rate; if k6 runs
// out of VUs it silently under-delivers and the run measures k6 rather than the server.
// Dropped iterations are reported in the summary so that failure mode is visible, not silent.
function vusFor(rate) {
  return { preAllocatedVUs: Math.max(rate, 50), maxVUs: Math.max(rate * 20, 200) };
}

if (PROFILE === 'steps') {
  const stepSeconds = parseDurationSeconds(STEP_DURATION);
  STEPS.forEach((rate, i) => {
    scenarios[`level_${rate}`] = {
      executor: 'constant-arrival-rate',
      rate: rate,
      timeUnit: '1s',
      duration: STEP_DURATION,
      startTime: `${i * (stepSeconds + STEP_GAP_S)}s`,
      tags: { level: String(rate) },
      exec: 'login',
      ...vusFor(rate),
    };
    levelThresholds(rate);
  });
} else if (PROFILE === 'steady') {
  scenarios[`steady_${RATE}`] = {
    executor: 'constant-arrival-rate',
    rate: RATE,
    timeUnit: '1s',
    duration: DURATION,
    tags: { level: String(RATE) },
    exec: 'login',
    ...vusFor(RATE),
  };
  levelThresholds(RATE);
} else if (PROFILE === 'ramp') {
  // Rate of climb: a continuous ramp. Where this sheds errors is generally BELOW the
  // steady-state ceiling, because the JVM, the connection pools and the JIT have not had
  // time to settle at each rate — that gap is exactly what the experiment is after.
  scenarios.ramp = {
    executor: 'ramping-arrival-rate',
    startRate: 1,
    timeUnit: '1s',
    stages: [{ target: RAMP_TO, duration: RAMP_DURATION }],
    tags: { level: 'ramp' },
    exec: 'login',
    ...vusFor(RAMP_TO),
  };
  levelThresholds('ramp');
} else {
  throw new Error(`unknown PROFILE '${PROFILE}' (expected steps|steady|ramp)`);
}

export const options = {
  scenarios: scenarios,
  thresholds: thresholds,
  // The authorization response IS the 302; following it would chase an unroutable
  // callback host and throw the code away.
  maxRedirects: 0,
  noConnectionReuse: false,
  summaryTrendStats: ['avg', 'min', 'med', 'p(95)', 'p(99)', 'max'],
};

// ---------------------------------------------------------------- the login flow

export function login() {
  const verifier = pkceVerifier();
  const challenge = crypto.sha256(verifier, 'base64rawurl');
  const state = randomToken(16);
  const nonce = randomToken(16);
  const subject = `perf-user-${__VU}-${__ITER}`;

  const headers = {
    'X-Tenant-Id': TENANT_ID,
    // The login/consent front-end is not part of this flow — /authorize takes the
    // established identity from this header, which is where an authenticating proxy
    // injects it. So this harness measures the authorization exchange, NOT credential
    // verification; see the README, it is a real limit on what these numbers mean.
    'X-Subject-Id': subject,
  };

  const started = Date.now();

  const authorizeUrl =
    `${BASE_URL}/authorize?response_type=code` +
    `&client_id=${encodeURIComponent(CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&scope=openid` +
    `&state=${state}` +
    `&nonce=${nonce}` +
    `&code_challenge=${challenge}` +
    `&code_challenge_method=S256`;

  const authorizeResponse = http.get(authorizeUrl, {
    headers: headers,
    redirects: 0,
    tags: { step: 'authorize' },
  });
  authorizeDuration.add(authorizeResponse.timings.duration);

  const code = extractCode(authorizeResponse);
  if (!code) {
    authorizeFailures.add(1);
    loginSuccess.add(false);
    loginTotal.add(Date.now() - started);
    return;
  }

  const tokenResponse = http.post(
    `${BASE_URL}/token`,
    {
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: REDIRECT_URI,
      client_id: CLIENT_ID,
      code_verifier: verifier,
    },
    { headers: headers, tags: { step: 'token' } },
  );
  tokenDuration.add(tokenResponse.timings.duration);

  const issued = tokenResponse.status === 200 && tokenResponse.body.indexOf('access_token') >= 0;
  if (!issued) {
    tokenFailures.add(1);
  }
  loginSuccess.add(issued);
  loginTotal.add(Date.now() - started);
}

export default function () {
  login();
}

// ---------------------------------------------------------------- helpers

/** Pulls `code` out of the 302 Location header; anything else is a failed login. */
function extractCode(response) {
  if (response.status !== 302) {
    return null;
  }
  const location = response.headers['Location'] || response.headers['location'];
  if (!location) {
    return null;
  }
  const match = /[?&]code=([^&]+)/.exec(location);
  return match ? decodeURIComponent(match[1]) : null;
}

const PKCE_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

/** An RFC 7636 §4.1 code verifier: 43-128 characters of the unreserved set. */
function pkceVerifier() {
  return randomFrom(PKCE_ALPHABET, 64);
}

function randomToken(length) {
  return randomFrom('abcdefghijklmnopqrstuvwxyz0123456789', length);
}

function randomFrom(alphabet, length) {
  let out = '';
  for (let i = 0; i < length; i++) {
    out += alphabet.charAt(Math.floor(Math.random() * alphabet.length));
  }
  return out;
}

function parseDurationSeconds(duration) {
  const match = /^(\d+)(s|m)$/.exec(duration);
  if (!match) {
    throw new Error(`STEP_DURATION must look like '60s' or '2m'; got '${duration}'`);
  }
  const value = parseInt(match[1], 10);
  return match[2] === 'm' ? value * 60 : value;
}

// ---------------------------------------------------------------- reporting

export function handleSummary(data) {
  const name = __ENV.RUN_NAME || 'run';
  const lines = [];

  lines.push(`# ${name}`);
  lines.push(`profile=${PROFILE} target=${BASE_URL}`);
  lines.push(`criterion: a level HOLDS iff error rate <= ${(ERROR_BUDGET * 100).toFixed(1)}% AND p99 < ${P99_BUDGET_MS}ms`);
  lines.push('');
  lines.push('level(req/s) | logins | err%   | p50(ms) | p95(ms) | p99(ms) | holds');
  lines.push('-------------|--------|--------|---------|---------|---------|------');

  const levels = PROFILE === 'steps' ? STEPS : PROFILE === 'steady' ? [RATE] : ['ramp'];
  let ceiling = null;
  for (const level of levels) {
    const success = data.metrics[`login_success{level:${level}}`];
    const total = data.metrics[`login_total{level:${level}}`];
    if (!success || !total) {
      continue;
    }
    const passed = success.values.passes || 0;
    const failed = success.values.fails || 0;
    const count = passed + failed;
    const errPct = count > 0 ? (failed / count) * 100 : 0;
    const p99 = total.values['p(99)'];
    const holds = errPct <= ERROR_BUDGET * 100 && p99 < P99_BUDGET_MS;
    if (holds && PROFILE === 'steps') {
      ceiling = level;
    }
    lines.push(
      [
        String(level).padEnd(12),
        String(count).padStart(6),
        errPct.toFixed(2).padStart(6),
        fmt(total.values.med).padStart(7),
        fmt(total.values['p(95)']).padStart(7),
        fmt(p99).padStart(7),
        holds ? ' yes' : ' NO',
      ].join(' | '),
    );
  }

  lines.push('');
  if (PROFILE === 'steps') {
    lines.push(
      ceiling === null
        ? 'SATURATION: the lowest level offered already breached the criterion.'
        : `HIGHEST LEVEL HELD: ${ceiling} logins/s (${ceiling * 60} logins/min) sustained.`,
    );
  }

  // Dropped iterations mean k6 could not deliver the offered rate — the run then measures
  // the driver, not the server, and the numbers above must not be read as a server ceiling.
  const dropped = data.metrics.dropped_iterations;
  if (dropped && dropped.values.count > 0) {
    lines.push(
      `WARNING: k6 dropped ${dropped.values.count} iterations — offered rate was not delivered. ` +
        'Raise maxVUs or lower the step; do not read the top levels as a server limit.',
    );
  }

  const text = lines.join('\n') + '\n';
  const out = {};
  out.stdout = text;
  out[`/results/${name}.txt`] = text;
  out[`/results/${name}.json`] = JSON.stringify(data, null, 2);
  return out;
}

function fmt(value) {
  return value === undefined || value === null ? '-' : value.toFixed(1);
}
