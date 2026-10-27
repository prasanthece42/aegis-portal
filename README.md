# Aegis developer portal

First implementation increment: a separate FastAPI application for authorized repository
registration. The existing `aegis-cicd` sample remains a consumer of the delivery platform.

Contracts, canonical JSON and desired-state fingerprints now come from the shared
`aegis-platform==0.3.0` package. A hash-pinned local wheel and source manifest in `vendor/`
keep this project independently buildable before a remote platform release exists.
The sibling platform source owns those definitions; `app/contracts.py` and
`app/fingerprint.py` preserve existing import paths. This does not activate deployment
or switch the sample app's caller workflow.

New registration proposals now bind a separate Argo project for DEV (`<app-id>-dev`),
matching the platform's per-environment project scope. Existing running bindings are
not migrated by changing this proposal generator.

Implemented: GitHub App user sign-in with state/PKCE, opaque server sessions, CSRF/origin
checks, strict registration contracts, source-file detection, signed review snapshots,
reviewed catalog PR proposals, Git-backed registration reservation and PR binding,
duplicate/restart recovery, registration status, and responsive browser screens.

**Deployment requests are disabled.** Release admission, the shared multi-app delivery
engine, image preparation, observations and protected sync are later increments. Registering
an app does not enable its namespace or deploy it. This service has no cluster credential.

## Run the local walkthrough

Requires Python 3.12 and uv. From this directory:

```sh
uv sync --locked
AEGIS_MODE=demo uv run --locked uvicorn app.main:app --host 127.0.0.1 --port 8010 --no-access-log
```

Open <http://127.0.0.1:8010>, choose **Enter local demo**, select a synthetic repository,
validate configuration and submit registration. Demo records persist under
`.local/demo-registrations.json`; sessions do not survive restart. Override the demo file
with `AEGIS_DEMO_DATA`. To reset the walkthrough, stop the service and remove only that
demo data file. Demo mode accepts loopback clients and local Host values only.

The banner always identifies demo mode. It creates no GitHub PR, workflow, namespace or
deployment, and displays no invented deployment success. The demo signer is a public test
fixture under a demo issuer; it must never be included in live trusted keys.

Without `AEGIS_MODE`, the portal starts **unconfigured**: browser assets and `/health`
work, `/ready` and business APIs fail closed. There is no fallback to demo authentication.

## Configure live registration

Live integration code is tested with mocked GitHub HTTP responses; it has not been
validated against a configured GitHub App. The repositories are published separately; GitHub App installation remains an account-owner setup action.
Before live use, an operator must supply an existing approved platform repository with
required catalog PR checks and branch protections, App installations, template pins,
cluster enrollment values, and TLS/callback configuration. The initial resource profile
in `examples/live-config.json` is illustrative and needs an approved capacity decision.

Copy the example to an operator-managed configuration path and replace all example IDs,
pins and targets. Do not commit secrets. Configure through the service's secret injection:

| Environment variable | Value |
| --- | --- |
| `AEGIS_MODE` | `live` |
| `AEGIS_CONFIG` | Path to validated non-secret JSON configuration |
| `AEGIS_APP_PRIVATE_KEY_FILE` | Protected PEM RSA GitHub App private-key path |
| `AEGIS_GITHUB_CLIENT_SECRET` | GitHub App client secret; injected server-side |
| `AEGIS_SIGNING_KEY_FILE` | Protected PEM Ed25519 request-signing key, separate from App key |

Run one process with `--no-access-log`, TLS at the approved local entry point, and
callback `<public_origin>/auth/github/callback`. Suppress callback query strings at the
TLS proxy too. Enable expiring user tokens on the GitHub App. Cookie names use the
`__Host-` prefix in live mode. No browser token storage, PAT reuse, GitHub webhook ingress
or remote team access is assumed. Session lifetime: 30-minute idle / eight-hour maximum,
bounded by provider expiry. OAuth state is browser-bound, one-time and expires in five minutes.

Registration currently permits the signed-in allowed individual to own their registration.
Multi-owner/team grants and viewer-only catalog browsing are not enabled yet. Initial
source detection checks bounded files at an exact commit, without executing source code;
file presence does not establish dependency locking, test success or workflow compliance.

Initial App capability ceiling: Metadata read, Contents write and Pull requests write.
Source-operation tokens are downscoped to selected source repositories with Contents read;
platform tokens are downscoped to the selected platform repository. The App permission
ceiling is repository-wide; use distinct Apps if source owners cannot accept that ceiling.
Actions/Checks/Statuses/Issues permissions from the LLD are not used until those increments
are implemented. Workflows write, Administration and branch bypass are not requested.

Live registration creates only `portal-registrations/<id>` journal branches,
`portal-onboarding/<id>` catalog branches and PRs. It never merges them. Journal records
are Ed25519-signed with issuer, repository audience and principal bindings. Ref creation
reserves a deterministic operation ID; non-force ref updates resolve concurrent binding.
Human review and final-base uniqueness/path checks must protect the approved catalog.
Operational journal refs must be excluded from platform release triggers. Initial history
is bounded to 100 registrations; exceeding that budget fails visibly rather than hiding
incomplete discovery. Key rotation/revocation and journal retirement need operator tooling
before unattended use; the first increment verifies the configured signing key only.

Interrupted submissions retain their idempotency key and non-secret form fields in browser
session storage. **Recover registration** resumes the same operation after reauthorization.
If persistence never occurred, a new validation is required. If source/policy changed
after reservation, recovery blocks for operator reconciliation. Closed registrations and
abandoned reservations are not silently overwritten or reused; reviewed cleanup tooling
is a follow-up. Request IDs are never access grants.

## Validate

```sh
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
node --check app/static/app.js
uv run --locked python -m app.export_schemas
```

The generated JSON schemas live in `schemas/`. API validation also enforces semantic
checks such as safe health paths and promotion evidence; consumers must not infer
authorization or health merely from successful schema validation. The DeploymentIntent
contract is used by the delivery preview and signed request endpoints described below.

An optional browser walkthrough is available as `node tests/browser-smoke.cjs` with
Playwright installed separately (`PLAYWRIGHT_MODULE` can select an existing installation).
Run it against a fresh local demo data file. It checks desktop/mobile layouts, field
errors, a persisted-but-lost submission response, recovery, and disabled deployment.
Screenshots and results go to ignored `.local/qa/`. This check never runs against live mode.

Tests cover access forgery, CSRF/origin checks, ambiguous/oversized JSON, signature
tampering, preview expiry/configuration changes, duplicate and concurrent requests,
partial persistence, restart recovery and session expiry. GitHub transport tests exercise
token scoping, OAuth exchange and non-force journal updates with mocked responses.
The app-scoped fingerprint has a published deterministic fixture and tests for relevant
configuration changes and independence from another app's state.

The lockfile pins exact dependencies. `requirements-prod.txt` is exported with hashes
for the separate non-root container. Local CI preparation in `.github/workflows/ci.yml`
checks contracts, code and the container; it has not run on GitHub. This standalone
bootstrap CI should adopt the approved reusable workflow when that platform increment
exists. No release workflow is connected to live delivery until reusable platform
contracts and required checks are implemented and reviewed.

Design references remain in the sibling sample repository's `DOCS/22`–`25` documents.

## Delivery request integration

`POST /api/v1/deployment-validations` previews an immutable source-bound release.
`POST /api/v1/deployment-requests` confirms it with a UUID-v4 idempotency key, persists
an Ed25519-signed journal under `portal-requests/`, binds a bot-authored signed issue,
and dispatches the approved GitOps request workflow. The request ID supports authorized
readback and retries after response loss. The browser has release selection, review
and request tracking screens; an accepted request is never labelled healthy.

Live delivery remains disabled by default. Enabling it requires an approved
`policies/delivery.json`, real app/cluster catalog entries, GitOps installation bindings,
a deployed `delivery-request.yml` pinned by `delivery_workflow_commit`, and a trusted
local cache/health observer. These are integration prerequisites, not configuration
placeholders to bypass. The workflow adapter rechecks the installed workflow bytes
before dispatch. Protected targets retain human review and operator sync.

## One-time GitHub App setup

```sh
.venv/bin/python tooling/setup_github_app.py --origin https://localhost:8443
```

Open the printed loopback setup URL in the account-owner browser. Create the private
App and install it on selected Aegis repositories. The single-use manifest handshake
saves RSA App credentials and a separate generated Ed25519 signing key under ignored
`.local/github-app/`, with directory mode 0700 and file mode 0600. Existing keys are
never overwritten, callback queries are not logged, and credentials are never printed.
No personal CLI token is reused by the portal. Enable expiring user tokens in GitHub
App settings and configure the HTTPS portal callback before live sign-in.

The expanded capability ceiling includes Contents, Pull requests, Issues and Actions
write, with Checks and Statuses read. Every operation requests a repository-scoped,
permission-reduced installation token. No Administration, Workflows write, branch
bypass or Kubernetes access is requested. Earlier registration-only permission notes
above describe the original increment; this setup manifest is the current ceiling.
