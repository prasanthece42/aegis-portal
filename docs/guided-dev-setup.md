> New supported registrations can authorize preparation in their initial combined review.
> [Guided onboarding](guided-onboarding.md) carries that signed plan through owner approval,
> automatic preparation and release selection. This document also describes the explicit
> setup path retained for older registrations.

# Guided DEV preparation

After catalog approval, application owners choose **Prepare for DEV** in the portal.
They review the pipeline files and target configuration, then confirm preparation.
The platform queues one signed, recoverable setup request. An enrolled operator service
proposes the exact source workflows and GitOps bootstrap files. The portal displays each
proposal, its approval state and CI progress. Application owners can approve source changes;
the DEV target also needs the enrolled platform owner's review. A user with both grants
can approve the two scopes together. GitHub branch protection and current-head reviews remain
in force. The worker merges successful approved proposals and prepares the target.

Preparation creates the namespace, quota, limits and app-scoped Argo project. It **does not
install the Argo Application or create deployment values**. CI publishes a validated release,
and the operator prepares verified OCI bytes in the enrolled node cache. The user then selects
a release and confirms DEV deployment through the existing signed request flow. Only after
that request is admitted and its exact GitOps bytes are merged can the worker install the
first Argo Application. Subsequent releases use the existing Argo reconciliation path.

## Authority and execution

The portal retains its current GitHub App permission ceiling. It has neither Workflows write
nor Kubernetes credentials. The host service uses the already-enrolled operator's explicitly
selected GitHub CLI identity, which must have workflow authorization. That identity writes the
source workflow branch and performs the reviewed namespace bootstrap. Repository-scoped App
tokens author the pull requests so actual human reviews remain independent. No personal token,
private key or kubeconfig enters the browser, signed journal, repository or portal pod.

The separate reviewed platform file `policies/portal-setup.json` binds one source owner,
platform/GitOps IDs, portal App ID, operator IDs and the enrolled DEV cluster UID. Operators
must also be current delivery observers. The worker verifies the loopback API, actual cluster
UID, node and operator identity before any operation. Python web apps and DEV are the only
supported runtime/environment in this version. The bundled immutable chart is checked against
the approved catalog hash. Existing custom workflow or target files are reported as conflicts;
they are never silently replaced.

Signed journals live on deterministic `portal-setups/setup-<hash>` branches. The signed payload
binds principal, app, immutable source commit, exact file maps, catalog entry and policy hashes,
cluster UID and namespace. The operator independently recomputes the plan using current reviewed
catalog/policy and verifies Ed25519 signatures, active issuers, age and fresh source push/owner
grants. It refuses moved source, changed proposals, unrelated files, closed proposals, wrong-head
reviews, failed CI and foreign-owned Kubernetes objects. It does not execute application code.
All application tests and builds run in the existing hosted pipeline.

Duplicate confirmations reuse their original operation key. Equivalent recent plans from another
tab reuse the same journal. A lost branch/PR response is recovered from its deterministic ref and
verified bytes. Requests expire under the reviewed request-trust policy; completed setup records
can continue to be measured under current policy/grants. Local completion state is private and
atomic. A moved source/policy requires a fresh review rather than overwriting the previous plan.

## Operator service

Run from the reviewed portal source, with the existing protected public configuration and key:

```sh
PYTHONPATH=. .venv/bin/python -m tooling.setup_worker \
  --agent-config /absolute/path/to/aegis-platform/.local/agent.json \
  --portal-config /absolute/path/to/aegis-portal/.local/live-config.json \
  --app-key-file /absolute/path/to/aegis-portal/.local/github-app/github-app.pem \
  --state-directory /absolute/path/to/aegis-portal/.local/dev-setup-worker \
  --operator-from-gh
```

This is an operator-managed host process alongside the existing gateway and observer in the
local DEV pilot. The service polls once a minute. Missing or revoked credentials, an unavailable
service or an invalid policy fail visibly; requests remain queued and never claim completion.
Restart it using the same state directory. The portal reports a fresh operator-authored heartbeat
and per-request status, and marks readiness only when workflows, target configuration, fresh
operator evidence, an admitted release and its cache evidence all match.

The current first-version discovery budget is 100 setup journals and one enrolled local worker.
Do not run independent workers with separate state directories. Operator boot/login supervision
and distributed queue execution are not included in this local DEV pilot.

## Verification

`tests/test_dev_setup.py` exercises the actual GitHub adapter and route/service integration,
lost-confirmation recovery, duplicate-plan handling, stale source, scoped human reviews, changed
heads/files, signature tampering/revocation/expiry, deterministic branch recovery and failed CI.
Worker tests prove that preparation applies only namespace/quota/limits/project resources and
that a desired-state pointer cannot replace an independently signed deployment request.
Existing upload/registration/delivery tests remain enabled.

`tests/setup-browser-smoke.cjs` uses isolated labelled demo responses to check the guided UI,
file-content escaping, lost-response recovery, real user approval controls, release gating and
mobile layout. It creates no live GitHub changes or workloads. Native CI and a separately reviewed
portal runtime release are required before activation in the live portal.
