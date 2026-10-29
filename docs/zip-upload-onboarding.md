# ZIP upload onboarding candidate

The registration screen offers **Upload a new app** alongside existing GitHub repository
selection. This is a local source candidate; it does not update the configured live portal.
Existing work in this checkout is preserved.

## Walkthrough

Run an isolated local demo:

```sh
AEGIS_MODE=demo AEGIS_DEMO_DATA=.local/upload-qa/demo.json \
  uv run --locked uvicorn app.main:app --host 127.0.0.1 --port 8028 --no-access-log
```

Open http://127.0.0.1:8028, enter the demo, choose Register application, then Upload a new
app. Inspect `hello-portal.zip` from the workspace root. Review the public destination,
confirm creation, confirm the port/health/resource settings, review the proposed CI and
release files, and continue registration. The newly created synthetic repository is
preselected. Registration still needs its separate review and submission.

Demo repositories persist alongside demo registration state. They are explicitly synthetic;
no release, GitHub change or cluster deployment occurs. The sample's application code lacks
hash-locked development/production requirements and health tests required by platform CI.
The preparation screen reports these requirements; file presence never establishes CI success.

## Live configuration and authorization

Live inspection uses the existing onboarding grant. The independently reviewed portal system
policy configures one public destination account. For the first live version it is the personal
account `prasanthece42`; a fresh GitHub identity check requires that account owner to create
repositories. Organization destinations can require current organization-owner membership.

The system plan injects `AEGIS_UPLOAD_OWNER`, `AEGIS_UPLOAD_OWNER_TYPE` (`User` or
`Organization`) and `AEGIS_UPLOAD_DATA`. Personal creation uses `POST /user/repos` and
organization creation uses `POST /orgs/{owner}/repos`. Both require an approved source App
installation covering all repositories in the configured account. The portal checks the
installation's explicit `repository_creation: write` permission before offering creation.

The current App needs the narrow Repository creation permission enabled and approved by
its owner, followed by a fresh portal sign-in. No Administration or Workflows permission is
required or requested. See GitHub's [creation API](https://docs.github.com/en/rest/repos/repos#create-a-repository-for-the-authenticated-user)
and [permission description](https://github.blog/changelog/2026-10-13-github-app-improvements-for-least-privilege-and-management/).
Source writes use a separate repository-scoped installation token with Contents write only.
There is no CLI/PAT fallback or automatic App permission expansion.

The reviewed runtime adds a 1 GiB ReadWriteOnce PVC named `aegis-portal-uploads`, mounted at
`/var/lib/aegis/uploads`, with database `uploads.sqlite3`. The container root filesystem stays
read-only, UID/fsGroup stay 10001, and no cluster credentials enter the pod. PVC pruning is
disabled to retain recovery data across workload replacement or rollback. The AppProject and
namespace storage quota are updated through the reviewed operator bootstrap. This uses the
enrolled DEV cluster's `standard` StorageClass. All portal processes must share the same volume
and adjacent lock file; independent multi-host replicas are not supported.

The loopback HTTPS gateway allows up to 5 MiB only on the binary ZIP upload route. Other
requests retain the 32 KiB JSON limit. Deploying new portal source does not update that host
process; the operator must restart the gateway from the reviewed new source after rollout.

Workflow installation deliberately uses **manual reviewed commit**: the portal displays and
downloads proposals pinned to the configured platform workflow commit. A maintainer commits
them via GitHub or their own workflow-authorized Git client. The portal never writes workflow
files and keeps its current workflow-write restriction. Installing release workflows can
start CI; deployment still requires catalog approval, target setup, a validated immutable
release and the existing separate signed DEV deployment request.

## Inspection and recovery

ZIP upload has a separate bounded binary endpoint; other API requests retain their 32 KiB
strict JSON boundary. Limits are 5 MiB ZIP, 10 MiB expanded, 1 MiB per file, 500 entries and
200:1 compression ratio. Absolute, traversal, drive, backslash, duplicate/case-colliding,
conflicting file/folder, encrypted and special-file/symlink paths are rejected. No source
is extracted or executed. A single enclosing folder is stripped.

Dependencies, Git history, local environment/credential files and uploaded workflows are
excluded. Common private keys, GitHub tokens, AWS access IDs and credential assignments in
retained files block creation. Blocked file bytes are never persisted or echoed. This is a
bounded heuristic scan; it cannot detect every secret format. Users must review the final
file list and source before confirming a public upload.

Only inspected, filtered source is persisted, in a mode-0600 SQLite file. Unconfirmed uploads
are pruned after 24 hours when another inspection starts. There is a 20-record limit per user.
`DELETE /api/v1/uploads/{id}` removes inspected or completed local records; it never deletes a
GitHub repository. In-progress recovery records cannot be deleted through this API. Operators
should include the database in retention and storage-capacity procedures.

The browser stores only the upload ID and user binding for recovery. A signed, five-minute
review binds the destination before creation. A durable creation-attempt reservation is saved
before GitHub's create request. Lost/ambiguous responses are recovered by destination and a
random operation marker; an ambiguous attempt is never issued a second create request. If no
repository is visible, recovery waits for operator investigation rather than risking a duplicate.
If access fails after creation, the portal shows the existing repository and offers recovery.

The import uses blobs, one exact reviewed tree, a commit and a non-forced branch update.
Retries recover an already-updated ref; concurrent branch changes stop the import. New source
is uploaded only after current user and approved App access pass. Registration, workflow
installation, catalog approval, release validation and deployment remain separate operations.

## Verification

```sh
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
node --check app/static/app.js
node --check app/static/uploads.js
PLAYWRIGHT_MODULE=/path/to/playwright node tests/upload-browser-smoke.cjs
```

The browser walkthrough uploads the actual sample ZIP, loses the creation response,
recovers the same synthetic repository after reload, reviews pipeline proposals, carries
runtime settings into registration, submits a demo catalog proposal and checks that deployment
is unavailable. It checks desktop/mobile layouts and saves screenshots under `.local/upload-qa`.
Provider-adapter tests cover lost creation/ref responses, current App access failures and
recovery without another create call. A live validated release and healthy DEV rollout still
require the operator configuration and independent reviews above; demo results do not prove them.
