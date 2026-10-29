# Multi-service registration candidate

Portal 0.8.0 adds an application-type selector and automatic ZIP detection for
`aegis-stack.json`. Review each service's replicas, port, readiness path, internal
URLs and Secret references. Edit the declared public environment values before
reviewing registration; settings carry across upload preparation and registration.
Use **Load services from selected repository** for an existing source repository.

The backend fetches the source definition at its immutable commit and rechecks it
on submission. Unsupported manifests do not silently fall back to single-service
deployment. Public environment overrides are reviewed catalog configuration. Secret
values are supplied independently by an operator, under `{app_id}-runtime` in the
application namespace. Never place credential values in the public fields.

Preparation proposes `python-stack-ci.yml` / `python-stack-release.yml` callers pinned
to the configured immutable platform version. The portal still cannot install
workflow files with its App credentials. Source publication produces one validated
multi-image release. Deployment review shows all service digests, public overrides
and the credential reference. Progress shows fresh trusted component observations
after the GitOps request is processed.

This source does not update the installed front door. A reviewed public
`multiservice_versions` configuration and GitOps worker/observer upgrade are required
before enabling the selector in live mode. The field is optional: existing configured
single-service installations continue without it. For the complete activation order,
see the platform's `docs/multiservice.md`.

The existing combined single-service registration/DEV-preparation consent flow is
preserved. Multi-service registration uses a separate operator target review and
does not authorize the single-service setup worker.

Local checks:

```sh
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
node --check app/static/app.js
node --check app/static/uploads.js
.venv/bin/python -m app.export_schemas
```

`tests/multiservice-browser-smoke.cjs` uses an isolated labelled demo and the actual
commerce ZIP. It checks six detected services, environment changes, Secret-reference
review, correct workflow proposals, registration handoff and desktop/mobile layout.
It creates no live repository, catalog registration or deployment.
