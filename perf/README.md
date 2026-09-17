# Login-flow saturation harness

An **exploratory** load harness for the Authorization Code + PKCE login flow. Its job is to
find where the system breaks, not to assert that it passes. It produces numbers with a
saturation point attached, and it is designed so that a run which could not actually happen
reports a blocker instead of a number.

## The questions it answers

1. **Throughput ceiling** — sustained successful logins per minute before the system
   degrades, against a degradation criterion named before the run.
2. **Rate of climb** — how fast the arrival rate can be raised before the system sheds
   errors. This is a different limit from the steady-state ceiling and is usually lower.
3. **Latency distribution** — p50 / p95 / p99 of the full `authorize → code → token`
   exchange, reported **per load level**, never as one aggregate.
4. **Cross-instance correctness** — with N instances behind one store, a code issued by
   instance A must be redeemable exactly once, and must be redeemable via instance B.

## The degradation criterion

A load level **holds** if and only if both are true:

| | |
|---|---|
| error rate | ≤ **1%** of logins fail (`ERROR_BUDGET=0.01`) |
| tail latency | **p99 < 1000 ms** for the full exchange (`P99_BUDGET_MS=1000`) |

The ceiling is the highest offered level that holds. Stating it up front is the point: it
makes the ceiling a measurement rather than an opinion formed after looking at the graph.
Both numbers are parameters — change them deliberately and the manifest records what was used.

## The three arms

| Arm | Instances | Store | What it can show |
|---|---|---|---|
| **0 — control** | 1 | in-memory | Today's behaviour. The baseline everything else is compared against. |
| **1** | 1 | Redis | The cost of moving the store off-heap, isolated from the cost of clustering. |
| **2** | 2 | Redis | The only arm that can demonstrate the distributed property. |

Arms 0 and 1 **cannot** demonstrate cross-instance correctness, by construction — there is no
second instance for a code to cross to. The harness skips that check for them and says so
rather than printing a pass.

Arm 0 runs against `origin/main` today. Arms 1 and 2 need the Redis authorization-code store,
which is being built in a separate lane; see *Pending* below.

```bash
perf/scripts/run-arm.sh arm0      # 1 instance, in-memory  (control)
perf/scripts/run-arm.sh arm1      # 1 instance, Redis
perf/scripts/run-arm.sh arm2      # 2 instances, Redis

# every parameter is overridable
INSTANCES=4 STORE=redis STEPS=10,50,100,200 perf/scripts/run-arm.sh arm2
PROFILE=ramp RAMP_TO=600 RAMP_DURATION=300s perf/scripts/run-arm.sh arm0
```

The instance count is a **parameter**, not a hard-coded assumption: the compose file and the
balancer config are generated from `INSTANCES`, so comparing 1 against 2 against N never means
maintaining two topologies that can drift apart.

## Verifying the harness without a daemon

```bash
perf/scripts/dry-run.sh
```

Checks everything that does not need a container runtime, so the harness does not fail on
its third step after a ten-minute build:

1. shell syntax of every script;
2. topology generation at 1, 2 and 4 instances — each compose file parsed by the compose CLI
   (which validates client-side), and the balancer asserted to name *every* instance, because
   an arm that silently runs narrower than it claims is worse than one that fails;
3. the seeder runs, emits both inserts, and binds `app.tenant_id` — without which the RLS
   `WITH CHECK` policy rejects the rows;
4. the seeded private key is opened, decoded and used to sign **by the server's own
   `EnvelopeCipher`**. This is the failure that no syntax check catches: a mismatched envelope
   format means every token request 500s at full speed;
5. the PKCE challenge is 43 unpadded base64url characters by both routes that produce one
   (the shell smoke test and the driver), matching the domain's `CodeChallenge` rule;
6. the driver's request construction and verdict logic against stubbed HTTP —
   including the one that matters most: a **synthetic double issuance**, to prove the
   zero-double-issuance assertion actually fires. An assertion that cannot fail is worse
   than no assertion.

Step 4 is skipped until `mvn -DskipTests package` has been run, and says so.

## Design decisions

**Driver: k6.** It is containerised, so no local install and no version skew; it scripts the
OIDC redirect flow and PKCE S256 directly in JS with no JVM in the load path — which matters,
because a JVM-based driver would contend with the application JVMs for cores on the same
laptop and confound the measurement it is taking. A JBang/Java harness would have kept the work
in-stack, which is a real advantage, but not enough of one to outweigh putting a second JVM
on the critical path of a saturation study.

**Open-model executors, not a VU pool.** Every profile uses `constant-arrival-rate` or
`ramping-arrival-rate`. The question is "how many logins per minute can the system absorb",
which is a property of *offered arrival rate*. A closed VU model cannot answer it: when the
system slows down, a closed model slows its own offered load to match and hides the very
saturation being looked for. When k6 cannot deliver the offered rate it records dropped
iterations, and the report warns that the run measured the driver rather than the server.

**Siting: `perf/` at the repository root, not a Maven module.** It is deliberately absent
from `<modules>` in the root `pom.xml`, so `mvn verify` and `mvn package` never see it, it
adds no dependency to any shipped artifact, and it cannot affect the production build. The
only production-tree file it touches is none: the harness drives the service over HTTP only.

**Per-instance CPU is pinned** (`APP_CPUS`, default 2). Without a fixed budget, a 2-instance
arm simply takes more of the host than a 1-instance arm and the comparison measures the
laptop rather than the architecture. With it pinned, arm 2 tests whether a second node adds
throughput. Note the host still has finite cores: once `INSTANCES × APP_CPUS` approaches the
core count the arms stop being comparable, and the manifest records both numbers so that is
checkable after the fact.

**Postgres runs on tmpfs.** The database is a fixture here, not the subject; keeping it off
the host disk removes APFS fsync behaviour from a measurement about the login flow.

## What the harness sets up, and why it has to

Two things a fresh database does not have, and no production code creates at startup:

- **An ACTIVE signing key with real private material.** `KeyRotationService` can mint one,
  but nothing calls it outside tests, and the `%dev` seed inserts only a placeholder public
  JWK — so a fresh instance cannot sign a token. `tools/SeedPerfRealm.java` generates a real
  Ed25519 key and envelope-encrypts the private half in the exact format
  `EnvelopeCipher` expects, then emits it as SQL. It is a single-file source program run on
  the JDK the build already requires, with no dependencies and no JDBC driver — it writes SQL
  to stdout and pipes into `psql` in the container.
- **A registered client.** One `PUBLIC`, PKCE-only client with the callback pre-registered.
  Public and PKCE-only on purpose: a confidential client would pay an Argon2id verification
  on every login, which is a different experiment (the credential path) and would dominate
  the numbers this one is trying to take.

The master key is generated fresh per run and never committed — the server refuses to boot
outside dev/test on the well-known development default, and a real key does not belong in a
public repository.

### Every override the perf environment applies, and why

Each of these was discovered by a run failing, not by reading configuration, and each is
recorded because a reader has to know what was changed before trusting a number.

- `QUARKUS_HTTP_INSECURE_REQUESTS=enabled` — under `%prod` the server redirects plain HTTP to
  HTTPS. Without this override every request in the run is answered with a 301 and nothing is
  measured at all.
- `IAM_SUBJECT_TRUST_HEADER=true` — `SessionCookieFilter` is default-closed and **strips** any
  caller-supplied `X-Subject-Id` unless the deployment declares its ingress trustworthy.
  That default is right: trusting the header without an edge that overwrites it is a complete
  authentication bypass. The harness is the shape the flag describes — the balancer is the
  sole ingress and the driver stands in for the authenticating proxy — so it is set here, and
  **must never be copied into a deployment whose ingress does not strip the header.**
- `IAM_READINESS_SIGNING_KEY_ENABLED=false` — see the defect note below. The harness gates on
  liveness plus one real end-to-end login instead, which is a stronger readiness signal than
  the probe was.

### A defect this work surfaced

`/q/health/ready` **cannot report UP in a packaged production run.** `SigningKeyReadinessCheck`
performs a blocking `UniAwait.atMost` from a health-check worker thread, and Hibernate
Reactive rejects that outright:

```
HR000068: This method should exclusively be invoked from a Vert.x EventLoop thread;
          currently running on thread 'executor-thread-2'
```

Independently of the threading problem, the check counts ACTIVE keys for a **hard-coded dev
tenant** only, so any other tenant reports DOWN even with a valid key of its own. Neither
problem affects the signing path — the token endpoint signs from the event loop and works —
but a platform readiness probe pointed at `/q/health/ready` would never pass. That is an
application defect, reported rather than papered over.

### DPoP is mandatory, so the driver mints proofs

A public client cannot obtain a token from this server without a DPoP proof (RFC 9449), and
there is no configuration that relaxes it — sender-constraining is enforced by construction.
So `k6/dpop.js` mints a real ES256 proof per token request: `typ=dpop+jwt`, the public JWK
embedded in the header, `htm`/`htu` bound to the server's *configured* token endpoint, and a
fresh `jti` every time, because the server treats a spent `jti` as single-use and will refuse
a replayed proof.

That last detail is load-bearing for the correctness check: if both redemptions in a race
shared one proof, the second would be refused for a replayed *proof* rather than an
already-consumed *code*, and "exactly one succeeded" would pass for entirely the wrong
reason. Each request therefore carries its own proof, so the code is the only thing the two
redemptions contend over.
- **Rate limiting is raised** (`RATELIMIT=high`) for the load arms. The shipped default is
  **20 token requests and 60 authorize requests per minute per (tenant, client_id)**, which
  is far below any interesting load — left alone, the "ceiling" would be a measurement of the
  rate limiter's configuration and nothing else. That default is itself a deployment fact
  worth stating plainly: **as configured today, one client is capped at 20 logins per minute
  regardless of how much capacity the server has.** Run with `RATELIMIT=default` to measure
  that limit instead of the system's.

## What a local run cannot tell you

These numbers establish **relative** behaviour between arms on one machine. They are not
production figures, and nothing here should be extrapolated into one.

- **Cloud Run's scaling behaviour** — cold starts, per-instance concurrency limits, the
  autoscaler's reaction time, and request queueing at the edge. None of it exists locally.
- **Memorystore network latency.** Redis over a container bridge is a sub-millisecond hop.
  Managed Redis across a VPC is not, and the store is on the critical path of every login.
- **Real HA failover.** Killing a container is not a zone outage, a failover election, or a
  partition. This harness never tests what happens *during* a failure.
- **Anything about the credential path.** The harness asserts the subject at the edge, so it
  measures the **authorization exchange** — not end-user authentication. A real login also
  pays an Argon2id credential verification, which these numbers do not include and which is
  deliberately expensive: at roughly 19 MiB per hash on a pool of 4 threads it would dominate
  every figure above and hide the store behaviour the arms exist to compare.

  A session/login endpoint now exists on `main`, so driving the flow through it — seeding
  users and credentials, and paying the Argon2id cost — is a viable follow-up experiment. It
  is a *different* experiment, and it would answer "how many real end-user logins per minute"
  rather than "how does the authorization-code store behave across instances". Worth running
  before any capacity commitment is made to anyone.

The first cloud deployment is what would answer those, and it does not exist yet.

## Output

Each run writes to `perf/.run/results/` (git-ignored):

- `<run>.manifest.txt` — commit, whether the tree was dirty, host CPU/memory, Docker version,
  CPU and heap per instance, rate-limit setting, profile, and the criterion. A laptop number
  is legitimate and useful; a laptop number that does not say it is one is not.
- `<run>.txt` — the per-level table and the saturation verdict.
- `<run>.json` — the full k6 summary.
- `<run>-correctness.txt` — the three cross-instance verdicts (2+ instances only).

The load run exits non-zero when a threshold is breached. That is a **result**, not an error —
finding the breaking point is the job.

## Pending

**Arms 1 and 2 need the Redis authorization-code store**, which is not on `origin/main` yet
(it is being built in a separate lane). The property that selects it is owned by that lane;
`gen-topology.sh` currently passes through both `TESSERA_AUTHCODE_STORE=redis` and
`QUARKUS_REDIS_HOSTS`, and whichever the adapter reads will bind. **Reconcile that to the real
property name once the adapter lands** — it is one line in `gen-topology.sh`.

## Recorded runs

### Arm 0 (control) — 1 instance, in-memory store — 2026-09-12

Host: Darwin arm64, 11 cores, 18 GiB. One instance pinned to 2 CPUs, 512 MiB heap.
Postgres on tmpfs. k6 in-network against the balancer. **These are laptop numbers**;
they establish relative behaviour, not production capacity.

**Throughput ceiling** (60s per level, preceded by an uncounted 60s warmup at 200/s):

```
level(req/s) | logins | deliv% | err%   | p50(ms) | p95(ms) | p99(ms) | holds
-------------|--------|--------|--------|---------|---------|---------|------
300          |  18001 |    100 |   0.34 |     5.0 |   226.0 |   517.0 |  yes
350          |  21000 |    100 |   0.27 |     4.0 |   105.0 |   345.0 |  yes
400          |  24001 |    100 |   0.35 |     5.0 |   112.0 |   184.0 |  yes
450          |  26076 |     97 |   1.09 |   140.0 |  2440.0 |  2907.2 |  NO
```

**Ceiling: 400 logins/s — 24,000 logins/minute.** The knee is immediately above it: 450/s
breaches both halves of the criterion at once and p99 jumps 16-fold.

Treat 400 as **marginal rather than comfortable**. Across runs it measured between 0.35% and
1.30% error — straddling the 1% budget — so the durable statement is: *comfortable at 350,
marginal at 400, broken by 450*. Past the knee the system does not degrade smoothly; repeat
ladders gave 9% error at 500/s and 1.3% at 550/s in the same run, which is what erratic
overload looks like rather than a measurement mistake.

**Rate of climb** (same ladder, 15s per level, no warmup, no gaps):

```
level(req/s) | logins | deliv% | err%   | p50(ms) | p95(ms) | p99(ms) | holds
-------------|--------|--------|--------|---------|---------|---------|------
100          |   1501 |    100 |   0.33 |     5.0 |   491.0 |   586.0 |  yes
200          |   3001 |    100 |   0.00 |     4.0 |     6.0 |    27.0 |  yes
300          |   4500 |    100 |   0.40 |     4.0 |   130.0 |   179.0 |  yes
400          |   6001 |    100 |   1.20 |    10.0 |   205.0 |   246.0 |  NO
500          |   7377 |     98 |   2.06 |   993.0 |  1225.0 |  1338.0 |  NO
```

**Climbing fast costs a quarter of the ceiling: 300/s against 400/s steady-state.** Arrival
rate can be raised to 18,000 logins/min quickly; getting the last 6,000 needs dwell time.

Note the cold-start cost visible in the first row: at 100/s on a cold JVM, p95 was 491ms and
p99 586ms, against 6ms and 27ms one level later at *twice* the rate. The first seconds of an
instance's life are materially slower — which is exactly the regime a scale-from-zero
platform spends its time in.

**The shipped rate limiter, measured** (`RATELIMIT=default`, one client):

| offered | attempted | succeeded | error rate |
|---|---|---|---|
| 1/s (60/min) | 61 | **39** | 36.1% |
| 5/s (300/min) | 301 | **23** | 92.4% |

39 successes in the first minute is the configured bucket exactly: burst 20, refill 20/min.
So **a single client is capped near 20 logins/minute in the steady state, against a measured
capacity of 24,000** — the shipped default sits about three orders of magnitude below what
the server can do. That is a deployment decision to make deliberately, not a capacity finding.

**Cross-instance correctness: not run, by design.** One instance cannot demonstrate a
distributed property; a pass would have been trivially true and worse than no result.

### Arms 1 and 2 — not yet run

Both need the distributed authorization-code store, which is not on `main` yet.
