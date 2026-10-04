#!/usr/bin/env bash
# Regression cases for the neutral-public-metadata rule (bash 3.2 / macOS compatible).
#
# Runs the REAL consumers, not a copy of their patterns:
#   - .githooks/pre-push                       (commit messages + added diff lines)
#   - commit-lint.yml  "Validate PR commits"   (commit messages, server side)
#   - pr-hygiene.yml   job "hygiene"           (PR title/body + added diff lines)
#   - pr-hygiene.yml   job "comment"           (PR/issue comment bodies; gh is stubbed)
# against throwaway git repos, and asserts that every seeded leak is refused and every clean
# input passes. A gate that cannot fail is the defect this exists to catch.
#
# The seeded keys are synthetic (ABC-12, …): the rule matches internal keys by shape, so no
# real project code needs to appear here. To check the actual project codes of a private
# tracker locally, without committing them, pass them in the environment:
#   NEUTRAL_METADATA_CODES="ABC DEF" scripts/test-neutral-metadata.sh
#
# Needs python3 with PyYAML (preinstalled on GitHub-hosted Ubuntu runners).
set -uo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
hook="$root/.githooks/pre-push"
commit_lint="$root/.github/workflows/commit-lint.yml"
pr_hygiene="$root/.github/workflows/pr-hygiene.yml"
zero='0000000000000000000000000000000000000000'
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0
fail=0

# extract <workflow> <job> <step-name> <run|env:NAME> — print a step's run script or one env value.
extract() {
  python3 - "$@" <<'PY'
import sys, yaml
wf, job, step, what = sys.argv[1:5]
for s in yaml.safe_load(open(wf))["jobs"][job]["steps"]:
    if s.get("name") == step:
        print(s["run"] if what == "run" else s["env"][what[4:]], end="")
        sys.exit(0)
sys.exit("step not found: " + step)
PY
}

lint_run="$(extract "$commit_lint" lint 'Validate PR commits' run)" || exit 2
lint_own="$(extract "$commit_lint" lint 'Validate PR commits' env:OWN_PROJECT)" || exit 2
hyg_step='PR text and diff must be neutral (no AI attribution, no internal keys)'
hyg_run="$(extract "$pr_hygiene" hygiene "$hyg_step" run)" || exit 2
com_run="$(extract "$pr_hygiene" comment 'Hide a comment carrying an AI-attribution marker or internal key' run)" || exit 2
own="$(python3 -c 'import sys,yaml; print(yaml.safe_load(open(sys.argv[1]))["env"]["OWN_PROJECT"], end="")' "$pr_hygiene")" || exit 2

# A throwaway repo whose origin/main is one clean commit; prints its path.
new_repo() {
  local d
  d="$(mktemp -d "$work/repo.XXXXXX")"
  git -C "$d" init -q -b main
  git -C "$d" config user.email dev@example.com
  git -C "$d" config user.name Dev
  echo base > "$d/README"
  git -C "$d" add README
  git -C "$d" commit -q -m 'chore: base'
  git -C "$d" update-ref refs/remotes/origin/main HEAD
  printf '%s' "$d"
}

# commit_on <repo> <message> [<added line>] — one commit on top of main.
commit_on() {
  printf '%s\n' "${3:-clean change}" >> "$1/change.txt"
  git -C "$1" add change.txt
  git -C "$1" commit -q --no-verify -m "$2"
}

# expect <block|pass> <label> <command...> — exit 0 is pass, exit 1 is block, anything else
# (syntax error, missing command) is an error and never counts as a block.
expect() {
  local want="$1" label="$2" got rc
  shift 2
  "$@" >/dev/null 2>&1
  rc=$?
  case "$rc" in 0) got=pass ;; 1) got=block ;; *) got="error($rc)" ;; esac
  if [ "$got" = "$want" ]; then
    pass=$((pass + 1))
  else
    fail=$((fail + 1))
    echo "FAIL: $label — expected $want, got $got" >&2
  fi
}

run_pre_push() {
  local head
  head="$(git -C "$1" rev-parse HEAD)"
  (cd "$1" && printf 'refs/heads/topic %s refs/heads/topic %s\n' "$head" "$zero" | bash "$hook")
}
run_commit_lint() {
  (cd "$1" && BASE="$(git rev-parse origin/main)" HEAD="$(git rev-parse HEAD)" \
    OWN_PROJECT="$lint_own" bash -c "$lint_run")
}
run_hygiene() {  # <repo> <title> <body>
  (cd "$1" && TITLE="$2" BODY="$3" BASE="$(git rev-parse origin/main)" HEAD="$(git rev-parse HEAD)" \
    OWN_PROJECT="$own" bash -c "$hyg_run")
}
# The comment job never fails the build: it hides the comment through gh. A stub gh records
# the call, so "block" here means "the comment would have been hidden".
run_comment() {
  local stub="$work/stub" log="$work/gh.log"
  mkdir -p "$stub"
  printf '#!/bin/sh\necho "$@" >> "%s"\n' "$log" > "$stub/gh"
  chmod +x "$stub/gh"
  rm -f "$log"
  PATH="$stub:$PATH" BODY="$1" NODE_ID=n HTML_URL=u ISSUE=1 REPO=o/r GH_TOKEN=t \
    OWN_PROJECT="$own" bash -c "$com_run" || return 3
  [ -s "$log" ] && return 1
  return 0
}

# Message-surface case: pre-push and commit-lint must agree.
msg_case() {  # <block|pass> <label> <message>
  local r
  r="$(new_repo)"
  commit_on "$r" "$3"
  expect "$1" "pre-push message: $2" run_pre_push "$r"
  expect "$1" "commit-lint message: $2" run_commit_lint "$r"
}
# Text-surface case: PR body, PR title, comment body, and an added diff line.
text_case() {  # <block|pass> <label> <text>
  local r
  r="$(new_repo)"
  commit_on "$r" 'docs: neutral subject' "$3"
  expect "$1" "pr body: $2" run_hygiene "$r" 'docs: neutral title' "$3"
  expect "$1" "pr title: $2" run_hygiene "$(new_repo)" "$3" 'neutral body'
  expect "$1" "comment: $2" run_comment "$3"
  expect "$1" "pre-push diff: $2" run_pre_push "$r"
}

# --- leaks: every surface must refuse ---
for t in \
  'deliver ABC-12 decision record' \
  'closes XYZ9-7' \
  'planned for ABC-S4' \
  'see raw/abc-12.md' \
  'branch chore/abc-12 has it' \
  'abc-12.md was updated' \
  'note at file:///home/dev/notes/raw/ABC-12.md' \
  'app link obsidian://open?file=ABC-12' \
  'per ADR-ABC-003' \
  'tracked at example.atlassian.net' \
  "own code is no exemption: $own-57"; do
  msg_case block "$t" "docs: $t"
  text_case block "$t" "$t"
done
# a revert/merge subject is skipped by the prefix rule but not by the key rule
msg_case block 'revert quoting a key' 'Revert "feat: deliver ABC-12"'

# --- clean: every surface must pass ---
for t in \
  'neutral wording only' \
  "own decision record ADR-$own-004" \
  'numbered record ADR-0001' \
  'SHA-256 thumbprint, UTF-8, RFC-7636, CVE-2024-12345' \
  'bump surefire-3.5.6 and maven-compiler-plugin-3.15.0' \
  'see https://issues.apache.org/jira/browse/SUREFIRE-2000' \
  'non-404 responses, top-10 list, the 429/not-429 split' \
  'base image ubi9/openjdk-21' \
  'PKCE-S256 is the only code challenge method' \
  'see https://tracker.example.org/browse/ABC-12' \
  'character class [A-Z0-9]-[0-9]'; do
  msg_case pass "$t" "docs: $t"
  text_case pass "$t" "$t"
done

# --- a marker early in a large input: the case that exposes a pipe into grep -q under
# pipefail (grep exits on the first match, the writer dies of SIGPIPE, the pipeline reports
# 141 and the match reads as a pass). Small inputs never exercise it.
filler="$work/filler.txt"
i=0
while [ $i -lt 6000 ]; do
  echo "ordinary line $i of a large but neutral change, nothing to see in it"
  i=$((i + 1))
done > "$filler"                                    # ~400 KB on disk
big_body="$(head -c 100000 "$filler")"            # one env string must stay under 128 KiB
for marker in 'Co-Authored-By: Claude <noreply@example.com>' 'deliver ABC-12 first'; do
  r="$(new_repo)"
  { echo "$marker"; cat "$filler"; } > "$r/big.txt"
  git -C "$r" add big.txt
  git -C "$r" commit -q --no-verify -m 'docs: neutral subject'
  expect block "large diff, marker first: $marker" run_hygiene "$r" 'docs: neutral title' 'neutral body'
  expect block "pre-push large diff, marker first: $marker" run_pre_push "$r"
  expect block "large pr body, marker first: $marker" run_hygiene "$(new_repo)" 'docs: neutral title' "$marker"$'\n'"$big_body"
  expect block "large comment, marker first: $marker" run_comment "$marker"$'\n'"$big_body"
done
r="$(new_repo)"
cat "$filler" > "$r/big.txt"
git -C "$r" add big.txt
git -C "$r" commit -q --no-verify -m 'docs: neutral subject'
expect pass 'large neutral diff' run_hygiene "$r" 'docs: neutral title' "$big_body"
expect pass 'pre-push large neutral diff' run_pre_push "$r"

# --- the inline copies of has_internal_leak must stay byte-identical (after indentation)
# until they are single-sourced; behaviour drift outside this corpus would otherwise go unseen.
copies="$(python3 - "$hook" "$commit_lint" "$pr_hygiene" <<'PY'
import re, sys, textwrap, hashlib
found = []
for p in sys.argv[1:]:
    for m in re.finditer(r"^( *)# Internal tracker keys are matched by SHAPE.*?^\1\}\n", open(p).read(), re.S | re.M):
        found.append(hashlib.sha256(textwrap.dedent(m.group(0)).encode()).hexdigest())
print(len(found), len(set(found)))
PY
)"
expect pass "four identical copies of the key clause (count, distinct: $copies)" test "$copies" = '4 1'

# --- optional: the real project codes of a private tracker, never committed ---
for code in ${NEUTRAL_METADATA_CODES:-}; do
  lower="$(printf '%s' "$code" | tr 'A-Z' 'a-z')"
  msg_case block "code #$((pass + fail)) upper" "docs: deliver $code-1"
  msg_case block "code #$((pass + fail)) lower path" "docs: see raw/$lower-1.md"
  text_case block "code #$((pass + fail)) upper" "deliver $code-1"
done

echo "neutral-metadata: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
