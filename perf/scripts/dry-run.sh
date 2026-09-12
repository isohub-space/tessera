#!/usr/bin/env bash
#
# Everything the harness can verify about itself WITHOUT a container runtime.
#
# The point is that the harness should run end to end the moment a daemon is available,
# rather than failing on its third step after a ten-minute build. So this checks the parts
# that do not need Docker: shell syntax, compose validity (the compose CLI parses
# client-side), the seeder's envelope format against the server's own cipher, the PKCE
# challenge encoding against the domain's rule, and the driver's request construction and
# verdict logic against stubbed HTTP.
#
# It does NOT prove the arms will pass — only that nothing here is broken before they start.
#
#   perf/scripts/dry-run.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PERF_DIR="$(dirname "$HERE")"
REPO_ROOT="$(dirname "$PERF_DIR")"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass() { printf '  ok    %s\n' "$1"; }
fail() { printf '  FAIL  %s\n' "$1" >&2; FAILED=1; }
FAILED=0

echo "== 1. shell syntax"
for script in "$HERE"/*.sh; do
  if bash -n "$script"; then pass "$(basename "$script")"; else fail "$(basename "$script")"; fi
done

echo "== 2. topology generation and compose validity"
export MASTER_KEY="$(openssl rand -base64 32)"
for spec in "1 memory" "2 redis" "4 redis"; do
  set -- $spec
  instances="$1"; store="$2"
  out="$TMP/run-$instances-$store"
  if ARM="dry" INSTANCES="$instances" STORE="$store" OUT_DIR="$out" \
       "$HERE/gen-topology.sh" >/dev/null 2>&1; then
    if docker compose -f "$out/compose.yaml" config --quiet >/dev/null 2>&1; then
      # The balancer must actually name every instance, or an arm silently runs narrower
      # than it claims to.
      found="$(grep -c 'server app[0-9]*:8090;' "$out/nginx.conf" || true)"
      if [[ "$found" == "$instances" ]]; then
        pass "instances=$instances store=$store (compose valid, $found upstreams)"
      else
        fail "instances=$instances store=$store — balancer names $found upstreams, expected $instances"
      fi
    else
      fail "instances=$instances store=$store — compose file is not valid"
    fi
  else
    fail "instances=$instances store=$store — generation failed"
  fi
done

echo "== 3. seeder"
if java "$PERF_DIR/tools/SeedPerfRealm.java" --master-key "$MASTER_KEY" \
      > "$TMP/seed.sql" 2> "$TMP/seed.env"; then
  pass "runs and emits SQL"
  for key in TENANT_ID CLIENT_ID REDIRECT_URI SIGNING_KID; do
    grep -q "^$key=" "$TMP/seed.env" && pass "emits $key" || fail "does not emit $key"
  done
  grep -q "INSERT INTO signing_key" "$TMP/seed.sql" && pass "seeds a signing key" \
    || fail "no signing_key insert"
  grep -q "INSERT INTO oauth_client" "$TMP/seed.sql" && pass "seeds a client" \
    || fail "no oauth_client insert"
  grep -q "set_config('app.tenant_id'" "$TMP/seed.sql" && pass "binds the tenant for RLS" \
    || fail "does not bind app.tenant_id — the RLS WITH CHECK policy would reject the rows"
else
  fail "seeder failed: $(cat "$TMP/seed.env")"
fi

echo "== 4. envelope format against the server's own cipher"
# The one piece that would fail at runtime in a way no syntax check catches: if the seeded
# private key cannot be opened by EnvelopeCipher, every token request 500s.
CLASSES="$REPO_ROOT/tessera-persistence/target/classes"
if [[ -d "$CLASSES" ]]; then
  cat > "$TMP/VerifyEnvelope.java" <<'JAVA'
import dev.tessera.iam.adapter.persistence.crypto.EnvelopeCipher;
import dev.tessera.iam.adapter.persistence.crypto.Ed25519Keys;
import java.util.Base64;
import java.util.HexFormat;
public class VerifyEnvelope {
    public static void main(String[] a) throws Exception {
        HexFormat hex = HexFormat.of();
        EnvelopeCipher cipher = new EnvelopeCipher(Base64.getDecoder().decode(a[0]));
        byte[] pkcs8 = cipher.open(new EnvelopeCipher.Envelope(
                hex.parseHex(a[1]), hex.parseHex(a[2]), hex.parseHex(a[3])));
        Ed25519Keys.sign(Ed25519Keys.decodePrivate(pkcs8), "probe".getBytes());
        System.out.println("ok");
    }
}
JAVA
  blob() { grep -o "decode('[0-9a-f]*', 'hex')" "$TMP/seed.sql" | sed -n "$1p" \
             | sed "s/decode('//;s/', 'hex')//"; }
  if java -cp "$CLASSES" "$TMP/VerifyEnvelope.java" \
        "$MASTER_KEY" "$(blob 1)" "$(blob 2)" "$(blob 3)" >/dev/null 2>&1; then
    pass "seeded private key opens, decodes and signs"
  else
    fail "seeded private key cannot be opened by EnvelopeCipher — tokens would fail at runtime"
  fi
else
  echo "  skip  no compiled persistence classes (run: mvn -DskipTests package)"
fi

echo "== 5. PKCE challenge encoding"
# The domain requires exactly 43 unpadded base64url characters (CodeChallenge, RFC 7636 §4.2).
# Both the k6 driver and the shell smoke test must produce that, by different routes.
VERIFIER="perf-smoke-verifier-0123456789012345678901234567890123456789"
SHELL_CHALLENGE="$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 \
  | tr '+/' '-_' | tr -d '=\n')"
NODE_CHALLENGE="$(node -e "
  const c=require('node:crypto');
  process.stdout.write(c.createHash('sha256').update('$VERIFIER').digest('base64url'));
")"
[[ ${#SHELL_CHALLENGE} -eq 43 ]] \
  && pass "smoke-test challenge is 43 chars" \
  || fail "smoke-test challenge is ${#SHELL_CHALLENGE} chars, domain requires 43"
[[ "$SHELL_CHALLENGE" == "$NODE_CHALLENGE" ]] \
  && pass "shell and base64url agree on the challenge" \
  || fail "challenge encodings disagree: '$SHELL_CHALLENGE' vs '$NODE_CHALLENGE'"
[[ "$SHELL_CHALLENGE" =~ ^[A-Za-z0-9_-]{43}$ ]] \
  && pass "challenge is base64url with no padding" \
  || fail "challenge is not clean base64url"

echo "== 6. driver logic against stubbed HTTP"
node "$HERE/../k6/stub-check.mjs" "$PERF_DIR/k6" && pass "driver checks passed" \
  || fail "driver checks failed"

echo
if [[ "$FAILED" == "1" ]]; then
  echo "dry-run: FAILURES above — fix before spending a daemon on a run." >&2
  exit 1
fi
echo "dry-run: all offline checks passed. The harness is ready to run when a daemon is."
