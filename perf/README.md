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

### Two configuration overrides worth knowing about

- `QUARKUS_HTTP_INSECURE_REQUESTS=enabled` — under `%prod` the server redirects plain HTTP to
  HTTPS. Without this override every request in the run is answered with a 301 and nothing is
  measured at all.
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
- **Anything about the credential path.** `/authorize` takes the authenticated subject from
  the `X-Subject-Id` header, which is where a login front-end or authenticating proxy injects
  it; that front-end does not exist yet. So this measures the **authorization exchange**, not
  end-user authentication. A real login includes a password verification that this harness
  does not perform.

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

_None yet._ As of 2026-09-12 the local Docker daemon is unresponsive (the client answers, the
server does not), so no arm has been executed. Every arm needs Postgres and the Redis arms
need Redis, so the harness reports this as a blocker rather than producing numbers from a run
that did not happen.
