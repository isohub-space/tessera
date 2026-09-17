#!/usr/bin/env bash
#
# Runs one arm of the login saturation experiment end to end and writes its results and a
# run manifest under perf/.run/results/.
#
#   perf/scripts/run-arm.sh arm0     # 1 instance, in-memory store  (the control)
#   perf/scripts/run-arm.sh arm1     # 1 instance, Redis store
#   perf/scripts/run-arm.sh arm2     # 2 instances, Redis store
#
# Any parameter can be overridden from the environment, e.g.
#   INSTANCES=4 STORE=redis STEPS=10,50,100 perf/scripts/run-arm.sh arm2
#
# The script refuses to report a run it could not actually perform: if the daemon is down,
# if the service never becomes ready, or if a single hand-driven login does not succeed
# before the load starts, it exits non-zero with the reason instead of producing numbers.
#
set -euo pipefail

ARM="${1:-arm0}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(dirname "$HERE")"
REPO_ROOT="$(dirname "$PERF_DIR")"
OUT_DIR="$PERF_DIR/.run"
RESULTS="$OUT_DIR/results"

# --- arm defaults ---------------------------------------------------------------------------
case "$ARM" in
  arm0) INSTANCES="${INSTANCES:-1}"; STORE="${STORE:-memory}" ;;
  arm1) INSTANCES="${INSTANCES:-1}"; STORE="${STORE:-redis}"  ;;
  arm2) INSTANCES="${INSTANCES:-2}"; STORE="${STORE:-redis}"  ;;
  *)    INSTANCES="${INSTANCES:-1}"; STORE="${STORE:-memory}" ;;
esac

export ARM INSTANCES STORE
export APP_CPUS="${APP_CPUS:-2}"
export APP_MEM="${APP_MEM:-1g}"
export HEAP="${HEAP:-512m}"
export RATELIMIT="${RATELIMIT:-high}"
export OUT_DIR

PROFILE="${PROFILE:-steps}"
STEPS="${STEPS:-10,25,50,100,200,400}"
STEP_DURATION="${STEP_DURATION:-60s}"
ERROR_BUDGET="${ERROR_BUDGET:-0.01}"
P99_BUDGET_MS="${P99_BUDGET_MS:-1000}"
RUN_NAME="${RUN_NAME:-${ARM}-${PROFILE}}"

COMPOSE_FILE="$OUT_DIR/compose.yaml"
dc() { docker compose -f "$COMPOSE_FILE" "$@"; }

log() { printf '\n=== %s\n' "$*"; }
fail() { printf '\nBLOCKED: %s\n' "$*" >&2; exit 1; }

# --- preflight: is there a daemon at all? ---------------------------------------------------
log "preflight"
if ! timeout 20 docker version --format '{{.Server.Version}}' >/dev/null 2>&1; then
  fail "the Docker daemon is not responding (the client works; the server does not).
       Every arm needs Postgres, and the Redis arms need Redis, so no arm can run.
       Report this as a blocker rather than reporting a run that did not happen."
fi
echo "docker server: $(docker version --format '{{.Server.Version}}')"

# --- build the artifact under test ----------------------------------------------------------
if [[ ! -d "$REPO_ROOT/tessera-server/target/quarkus-app" || "${REBUILD:-0}" == "1" ]]; then
  log "building tessera-server (mvn -DskipTests package)"
  (cd "$REPO_ROOT" && ./mvnw -q -DskipTests package 2>/dev/null || mvn -q -DskipTests package)
fi
[[ -f "$REPO_ROOT/tessera-server/target/quarkus-app/quarkus-run.jar" ]] \
  || fail "no quarkus-app build under tessera-server/target — the package step did not produce one."

# --- a fresh master key per run (never committed) -------------------------------------------
export MASTER_KEY="${MASTER_KEY:-$(openssl rand -base64 32)}"

# --- topology ---------------------------------------------------------------------------------
log "generating topology"
"$HERE/gen-topology.sh"

log "tearing down any previous run"
dc down -v --remove-orphans >/dev/null 2>&1 || true

# --- infrastructure ----------------------------------------------------------------------------
log "starting infrastructure"
if [[ "$STORE" == "redis" ]]; then
  dc up -d postgres redis
else
  dc up -d postgres
fi

# --- first instance: it runs the Flyway migrations that create the schema ----------------------
log "starting app1 (runs migrations)"
dc up -d app1

wait_for() {
  local url="$1" what="$2" tries="${3:-90}"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS --max-time 3 "$url" >/dev/null 2>&1; then
      echo "  up: $what"
      return 0
    fi
    sleep 2
  done
  return 1
}

wait_for "http://localhost:8091/q/health/live" "app1 liveness" \
  || { dc logs --tail 60 app1; fail "app1 never became live."; }

# --- seed ---------------------------------------------------------------------------------------
# The schema exists now, so the perf realm can be seeded: an ACTIVE signing key with real
# envelope-encrypted private material (nothing in production code mints one at startup) and
# one PUBLIC, PKCE-only OAuth client.
log "seeding the perf realm"
SEED_SQL="$OUT_DIR/seed.sql"
SEED_ENV="$OUT_DIR/seed.env"
java "$PERF_DIR/tools/SeedPerfRealm.java" \
  --master-key "$MASTER_KEY" \
  --client-key "${CLIENT_ID:-perf-client}" \
  --redirect-uri "${REDIRECT_URI:-http://perf.invalid/callback}" \
  > "$SEED_SQL" 2> "$SEED_ENV"

dc exec -T postgres psql -v ON_ERROR_STOP=1 -U tessera -d tessera < "$SEED_SQL" >/dev/null \
  || fail "seeding failed — see $SEED_SQL"

# shellcheck disable=SC1090
set -a; . "$SEED_ENV"; set +a
echo "  tenant=$TENANT_ID client=$CLIENT_ID"

# Readiness is NOT taken from /q/health/ready: that probe cannot pass in a packaged run
# (see the note in gen-topology.sh) and is disabled for perf runs. The real gate is the
# smoke login below — a complete authorize->code->token exchange is a stronger statement
# about readiness than any probe, because it is the thing being measured.
echo "  seeded; readiness is gated on the smoke login below"

# --- remaining instances ------------------------------------------------------------------------
if [[ "$INSTANCES" -gt 1 ]]; then
  log "starting app2..app$INSTANCES"
  for i in $(seq 2 "$INSTANCES"); do
    dc up -d "app$i"
    wait_for "http://localhost:$((8090 + i))/q/health/live" "app$i liveness" \
      || { dc logs --tail 60 "app$i"; fail "app$i never became live."; }
  done
fi

log "starting the load balancer"
dc up -d lb
wait_for "http://localhost:8080/q/health/live" "balancer" || fail "the balancer never answered."

# --- smoke: one real login, through the driver itself, before any load ------------------
# Driven by k6 rather than curl, deliberately: it exercises the SAME code path the load run
# uses — including the DPoP proof, which a public client cannot get a token without and
# which is not something to reimplement in shell. If one complete exchange does not produce
# a token, every number a load run would print is a number about a broken flow.
log "smoke test: one complete login through the driver"
dc run --rm \
  -e "BASE_URL=http://lb:8080" \
  -e "TENANT_ID=$TENANT_ID" -e "CLIENT_ID=$CLIENT_ID" -e "REDIRECT_URI=$REDIRECT_URI" \
  -e "DPOP_HTU=${DPOP_HTU:-http://localhost:8080/token}" \
  -e "PROFILE=smoke" -e "RUN_NAME=$RUN_NAME-smoke" \
  k6 run /scripts/login-flow.js \
  || { dc logs --tail 40 app1; fail "the smoke login did not produce a token."; }
echo "  smoke login OK — a token was issued."

# --- the run manifest -----------------------------------------------------------------------------
# What was measured, on what, with what configuration. A laptop number is useful only if it
# says it is a laptop number.
mkdir -p "$RESULTS"
MANIFEST="$RESULTS/$RUN_NAME.manifest.txt"
{
  echo "run:            $RUN_NAME"
  echo "date:           $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo "arm:            $ARM (instances=$INSTANCES store=$STORE)"
  echo "commit:         $(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
  echo "dirty:          $(if [[ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]]; then echo yes; else echo no; fi)"
  echo "host:           $(uname -srm)"
  echo "host cpus:      $(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo unknown)"
  echo "host memory:    $(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1073741824 )) GiB"
  echo "docker server:  $(docker version --format '{{.Server.Version}}')"
  echo "cpus/instance:  $APP_CPUS"
  echo "mem/instance:   $APP_MEM"
  echo "heap/instance:  $HEAP"
  echo "rate limiting:  $RATELIMIT"
  echo "profile:        $PROFILE (steps=$STEPS step=$STEP_DURATION)"
  echo "criterion:      error rate > ${ERROR_BUDGET} OR p99 >= ${P99_BUDGET_MS}ms => degraded"
  echo "driver:         k6 in-network against the balancer"
} > "$MANIFEST"
cat "$MANIFEST"

# --- cross-instance correctness ---------------------------------------------------------------------
if [[ "$INSTANCES" -ge 2 ]]; then
  log "cross-instance correctness"
  URLS=""
  for i in $(seq 1 "$INSTANCES"); do
    URLS="${URLS:+$URLS,}http://app$i:8090"
  done
  dc run --rm \
    -e "TENANT_ID=$TENANT_ID" -e "CLIENT_ID=$CLIENT_ID" -e "REDIRECT_URI=$REDIRECT_URI" \
    -e "INSTANCE_URLS=$URLS" -e "RUN_NAME=$RUN_NAME-correctness" \
    -e "DPOP_HTU=${DPOP_HTU:-http://localhost:8080/token}" \
    -e "CORRECTNESS_ITERATIONS=${CORRECTNESS_ITERATIONS:-200}" \
    -e "CORRECTNESS_VUS=${CORRECTNESS_VUS:-20}" \
    k6 run /scripts/correctness.js || echo "  (correctness thresholds breached — see the report above)"
else
  log "cross-instance correctness: SKIPPED"
  echo "  $INSTANCES instance(s). A single instance cannot demonstrate a distributed"
  echo "  property by construction — this check is only meaningful from 2 instances up."
fi

# --- the load run --------------------------------------------------------------------------------------
log "load: profile=$PROFILE"
dc run --rm \
  -e "BASE_URL=http://lb:8080" \
  -e "TENANT_ID=$TENANT_ID" -e "CLIENT_ID=$CLIENT_ID" -e "REDIRECT_URI=$REDIRECT_URI" \
  -e "DPOP_HTU=${DPOP_HTU:-http://localhost:8080/token}" \
  -e "PROFILE=$PROFILE" -e "STEPS=$STEPS" -e "STEP_DURATION=$STEP_DURATION" \
  -e "WARMUP_RATE=${WARMUP_RATE:-0}" -e "WARMUP_DURATION=${WARMUP_DURATION:-30s}" \
  -e "STEP_GAP_S=${STEP_GAP_S:-15}" \
  -e "RATE=${RATE:-50}" -e "DURATION=${DURATION:-120s}" \
  -e "RAMP_TO=${RAMP_TO:-400}" -e "RAMP_DURATION=${RAMP_DURATION:-300s}" \
  -e "ERROR_BUDGET=$ERROR_BUDGET" -e "P99_BUDGET_MS=$P99_BUDGET_MS" \
  -e "RUN_NAME=$RUN_NAME" \
  k6 run /scripts/login-flow.js || echo "  (load thresholds breached — that is a result, not an error)"

log "done"
echo "results:  $RESULTS"
echo "manifest: $MANIFEST"
echo
echo "Leave the stack up to inspect it, or tear it down with:"
echo "  docker compose -f $COMPOSE_FILE down -v"
