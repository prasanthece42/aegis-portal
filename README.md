# Aegis developer portal

A separate FastAPI application for authorized registration and delivery requests.
The portal is the front door; reusable CI builds releases, GitOps records the approved
configuration, and Argo deploys it. PROD still requires independent human approval and
an authorized operator sync.

## Current integration

Real GitHub App sign-in, reviewed catalog enrollment and two signed DEV requests have
completed against the public Aegis repositories. The second request created an
App-authored GitOps PR, ran native CI without execution approval, merged and reached
Argo Synced/Healthy. The sample application's three environments retained their existing
pods and images. The generic managed `aegis-portal-dev` deployment validates application
releases; it receives no portal credentials.

The configured front door runs in `aegis-portal-system` behind a local HTTPS gateway.
The separately registered `hello-aegis` application has also completed DEV onboarding,
release publication, signed delivery, GitOps checks and Argo rollout. Publishing new
portal source does not update the configured runtime: its immutable release and exact
system plan require independent review. Legacy sample catalog enrollment,
protected-target integration and rollback remain separate work.

## Platform owner console

Version 0.3.0 adds **Platform owner** navigation and `/#platform`, with Overview,
Reviews, Applications, Clusters & policy, and Activity views. The console is read-only;
review links open GitHub. Catalog and configuration changes follow protected PR review.
PROD retains independent human approval and authorized operator sync.

Owner access is a separate grant in the platform repository's reviewed main branch:

```json
{
  "schema_version": 1,
  "platform_repository_id": "900",
  "mode": "read_only",
  "owner_user_ids": ["123"]
}
```

Save this policy as `policies/portal-owner.json` with the actual numeric repository and
GitHub user IDs. Application owner/deployer grants do not confer platform access.
An absent policy or empty owner list disables access; each owner request rechecks the
current policy, so revocation does not depend on signing out. Invalid/unavailable policy
denies owner access while preserving an otherwise valid developer session.

`GET /api/v1/platform/overview` uses permission-reduced, repository-scoped App tokens.
Catalog files share one platform revision; desired state uses resolved GitOps revisions.
Cluster enrollment is inventory, not node readiness. Healthy environments require a
matching trusted observer measurement within five minutes; stale/invalid evidence is
labelled accordingly. Review CI summaries report provider results, not branch-protection
approval. Historical request activity verifies signatures and authorship, including
inactive issuers; it does not establish fresh admission or current deployment health.
Review/activity rows are capped at 20 per source with totals shown. Demo owner access
is explicitly synthetic and loads no live GitHub or Kubernetes data.

## Run a local walkthrough

Requires Python 3.12 and uv:

```sh
uv sync --locked
AEGIS_MODE=demo uv run --locked uvicorn app.main:app --host 127.0.0.1 --port 8010 --no-access-log
```

Open <http://127.0.0.1:8010>. Demo mode is labelled, loopback-only and synthetic. It
creates no GitHub PR, workflow or deployment. Records persist in ignored
`.local/demo-registrations.json`; sessions do not survive restart. Use a fresh
`AEGIS_DEMO_DATA` file for repeatable walkthroughs. Never trust the demo signing issuer
in a live environment.

Without `AEGIS_MODE`, browser assets and `/health` work while `/ready` and business APIs
fail closed. There is no fallback to demo authentication.

## Live configuration

`examples/live-config.json` is illustrative. An operator supplies reviewed real repository,
App/installation, cluster, workflow, profile and issuer bindings. Shared public contracts
come from the hash-pinned `aegis-platform==0.4.5` wheel in `vendor/`; this repository builds
without a sibling checkout. The source manifest describes a local snapshot, not a signed
package release.

| Environment variable | Value |
| --- | --- |
| `AEGIS_MODE` | `live` |
| `AEGIS_CONFIG` | Reviewed public JSON configuration path |
| `AEGIS_APP_PRIVATE_KEY_FILE` | Protected GitHub App RSA key path |
| `AEGIS_GITHUB_CLIENT_SECRET` | Server-side injected App OAuth secret |
| `AEGIS_SIGNING_KEY_FILE` | Separate protected Ed25519 request key path |
| `AEGIS_SIGNING_PUBLIC_KEY_B64` | Expected reviewed public key; required by the system plan |

Use TLS at the approved origin, callback `<public_origin>/auth/github/callback`, one
process and no access logs. Enable expiring GitHub user tokens. OAuth uses browser-bound
one-time state and PKCE. Opaque live cookies use the `__Host-` prefix; no provider tokens
are stored in browser storage. Sessions have a 30-minute idle/eight-hour maximum lifetime,
bounded by provider expiry. A restart requires sign-in again.

The App capability ceiling includes Contents, Pull requests, Issues and Actions write,
with Checks/Statuses read. Each operation mints a repository-scoped, permission-reduced
installation token. The portal uses no personal CLI token, Kubernetes access,
Administration permission, Workflows write or branch bypass. Source selection requires
public repositories, current user push access and an approved App installation.

For independent operator recovery, `tooling/run_live.py` reads protected local key files
and starts the configured host service without printing credentials. The one-time
`tooling/setup_github_app.py` manifest flow creates protected files under ignored
`.local/github-app/`; it omits unsupported localhost webhook configuration. It never
overwrites existing keys. Do not recreate the already-installed App for routine startup.

## Registration and delivery

Registration detects bounded source files at an immutable commit without executing them,
previews a signed configuration and creates a catalog PR. The portal never approves or
merges catalog PRs. Registration does not deploy an application.

Deployment preview binds app, environment, immutable release, current grant, source
lineage, expected app-specific state and fresh cache/prior-health evidence. Confirmation
persists an Ed25519-signed Git journal, binds a signed issue and dispatches only the
reviewed GitOps workflow bytes. The worker independently revalidates the request.
The browser displays the actual delivery PR and trusted measured health; accepted
requests are never labelled healthy merely because submission succeeded.

Interrupted submissions retain non-secret fields and the original idempotency key in
session storage. Recovery requires fresh authorization and resumes the same operation.
Changed source/policy, abandoned reservations and closed proposals fail visibly rather
than silently overwriting journal history. Request IDs are not access grants.

## Kubernetes front door

The platform's independently reviewed system plan mounts public configuration and
operator-injected private credentials. No Secret values enter Git or hosted CI. Live
startup checks the mounted signing key against the expected public binding. `/ready`
checks configured registration/delivery capability; `/health` remains a liveness endpoint.

After the operator bootstraps the reviewed system branch and verifies pod readiness,
replace the host entry point with the gateway using the existing HTTPS origin/certificate:

```sh
.venv/bin/python tooling/run_gateway.py \
  --agent-config '../aegis-platform/.local/agent.json'
```

The gateway uses only the explicit enrolled loopback cluster and fixed portal Service.
It reconnects after pod replacement, preserves OAuth redirects and separate cookies,
uses isolated upstream clients and suppresses access logs. It never loads App/signing
keys. Its kubeconfig stays on the operator host. Argo's UI uses a separate local port.
Keep the host startup tool available for recovery; do not run both listeners on the same
port. Credential rotation and durable service supervision still require operator work.

## Validate

```sh
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
node --check app/static/app.js
uv run --locked python -m app.export_schemas
```

Tests cover authorization/CSRF, bounded strict JSON, signatures, preview expiry, current
grants, source/cache admission, idempotence/concurrency/restart recovery, trusted status
readback, readiness key binding and gateway cookie/origin/failure behavior. CI builds a
non-root read-only image using hash-locked requirements. The pinned reusable release
workflow publishes tested amd64/arm64 images and complete retained OCI evidence.

Optional `tests/browser-smoke.cjs` uses separately installed Playwright against a fresh
local demo, checks desktop/mobile registration and lost-response recovery, and writes
ignored screenshots under `.local/qa/`. It never uses live OAuth credentials.
`tests/owner-browser-smoke.cjs` checks all owner views, desktop/mobile layouts, deep links,
escaped review titles and logout against an isolated demo with labelled illustrative rows.
It writes ignored screenshots under `.local/owner-qa/`. Design
references are in the sibling sample repository's `DOCS/22`–`28` documents.
