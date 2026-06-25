# Contributing to Tessera

Thank you for considering a contribution to Tessera. This guide covers
everything you need to get started: the CLA, development setup, the PR
process, and the code conventions we enforce.

---

## Before your first pull request — sign the CLA

Tessera uses an automated Contributor License Agreement check. When
you open your first pull request, the CLA bot will post a comment with
a one-click sign link. The CLA:

- lets you keep your copyright — you grant a license, not ownership,
- gives the project the right to distribute your code under
  Apache-2.0 and any future OSI-approved license, and
- takes about 30 seconds to sign.

The full agreement text is in [`CLA.md`](CLA.md). If you contribute on
behalf of an employer, check whether your employer needs to sign a
Corporate CLA before you do.

The CLA check is a required status check — pull requests from
unsigned contributors cannot be merged.

---

## Security vulnerabilities

**Do not open a public issue for a security vulnerability.** Report it
privately via GitHub's [Report a vulnerability][advisory] feature
(Security › Advisories › *Report a vulnerability*). See
[`SECURITY.md`](SECURITY.md) for full details.

[advisory]: https://github.com/isohub-space/tessera/security/advisories/new

---

## Development setup

**Requirements**

| Tool | Minimum version | Notes |
|------|----------------|-------|
| JDK | 25 | Recommended: [SDKMAN](https://sdkman.io/) — `sdk install java 25.0.x-tem` |
| Maven | 3.9+ | Bundled wrapper (`./mvnw`) also works |
| Docker | any recent | Required for the Testcontainers integration tests |
| PostgreSQL | — | Provided by Testcontainers; no local install needed |

**Build and test**

```bash
# Unit + integration tests (Docker required for persistence ITs)
mvn verify

# Skip integration tests for a faster local loop
mvn -DskipITs verify

# Single module
mvn -pl tessera-domain -am verify
```

The `tessera-domain` and `tessera-api` modules are framework-free —
they run without Docker. Only `tessera-persistence` and the server
launcher need a container.

---

## Opening an issue

- **Bug**: use the [bug report template][bug].
- **Feature / RFC**: use the [feature request template][feature].
- **Question**: open a blank issue — the templates have a direct link.

[bug]: https://github.com/isohub-space/tessera/issues/new?template=bug_report.yml
[feature]: https://github.com/isohub-space/tessera/issues/new?template=feature_request.yml

---

## Pull request process

1. **Fork and branch.** Branch names follow the pattern `<type>/<slug>`:

   | Prefix | When |
   |--------|------|
   | `feat/` | New protocol feature or endpoint |
   | `fix/` | Bug fix |
   | `sec/` | Security hardening |
   | `refactor/` | Refactor without behaviour change |
   | `ci/` | CI / tooling |
   | `docs/` | Documentation, ADRs |
   | `deps/` | Manual dependency updates |
   | `test/` | Tests only |

2. **Keep one concern per PR.** A PR that fixes a bug and adds a
   feature is two PRs.

3. **Write or update tests.** New behaviour needs tests. Changed
   behaviour needs updated tests. The CI gate (`mvn verify`) runs the
   full test suite including integration tests.

4. **CI must be green.** The required checks are:
   - `build & verify` — the full Maven test suite, including
     Testcontainers integration tests
   - `CodeQL analyze` — static security analysis
   - `dependency-review` — licence and vulnerability scan on dependency
     changes
   - `cla-signed` — your CLA signature

5. **One commit is not required, but keep history meaningful.** Fixup
   commits are fine during review; the project uses squash merges so
   the final commit message is what lands on `main`.

6. **Commit message format.** Follow
   [Conventional Commits](https://www.conventionalcommits.org/):
   `<type>(<scope>): <short summary>`. The scope is optional but
   helpful (`domain`, `persistence`, `rest`, `ci`, etc.).

---

## Code conventions

### Architecture

Tessera is a strict hexagonal architecture:

```
tessera-domain       framework-free; no Quarkus, no Hibernate
tessera-api          ports (interfaces); depends on domain only
tessera-persistence  Hibernate Reactive + Flyway adapters
tessera-rest         Quarkus REST adapters
tessera-observability metrics, audit log
tessera-statemachine  pure typed FSM library (no deps)
tessera-server       Quarkus assembly / launcher
```

- `domain` and `api` have **zero framework imports**.
- `persistence` and `rest` depend on `api`, never on each other.
- Do not add a Quarkus or Jakarta import to `domain` or `api`.

### Multi-tenancy

Every persisted entity is tenant-scoped. All database access goes
through `TenantScopedSession`, which sets the PostgreSQL `app.tenant_id`
session variable before each statement, activating the row-level
security policy. Never bypass `TenantScopedSession` to query the
database directly.

### Comments

Write comments only when the **why** is non-obvious. Do not comment
what the code does — use well-named types and methods for that. Do not
add TODO comments to submitted code; file an issue instead.

### SPDX headers

New source files must carry a licence identifier on the first line
(after the `package` statement or shebang for scripts):

```java
// SPDX-License-Identifier: Apache-2.0
```

---

## Code of Conduct

Be kind, assume good faith, and keep discussions focused on the
technical merits. Harassment, personal attacks, or discriminatory
language are not tolerated. Maintainers may close issues or PRs that
violate this expectation without further explanation.

---

## Questions?

Open an issue — the templates include a free-form option for questions.
