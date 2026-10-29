# Guided Python onboarding

Upload a ZIP or select an eligible repository, confirm the runtime settings, and review the
registration together with the exact proposed pipeline and DEV target files. Submit once.
The application journey follows ownership review, preparation, build, release review and
measured DEV health without requiring a developer to coordinate separate screens.

The initial review authorizes **proposals**, never their approval or deployment. Its signed
registration journal contains an explicit setup intent bound to the original principal,
source commit, catalog entry, workflow/chart files, policy, cluster and operation identity.
The enrolled worker independently verifies that signature and the current public policy,
source identity, push access, catalog uniqueness and exact proposal scope. It merges the
catalog proposal only after a current independent owner review and protected GitHub checks.
Preparation then resumes automatically from the same signed intent. No mutation is triggered
by a progress GET or browser polling.

The generated pipeline and DEV target proposals still require real independent reviews.
Application owners can approve the pipeline; platform owners approve the DEV target. A user
with both grants can review both together in the journey. The worker never generates an
approval. Workflow installation continues to use the enrolled operator authorization;
the portal App has no workflow-write permission or Kubernetes credentials.

After successful installation, CI publishes a validated release and the enrolled worker
prepares its image cache. Progress refreshes automatically, names the next responsible actor,
and opens release selection once ready. Release labels use GitHub's actual workflow run
number, such as **Build #1**, plus source revision, publication time and retry attempt. The
original tag and numeric IDs remain available under Release identifiers. They remain the
immutable values submitted to the deployment API; display labels never authorize delivery.

The developer reviews the build and destination and separately confirms DEV deployment.
Existing signed request admission, protected GitOps merge, Argo rollout, HTTP health and
fresh runtime-security evidence determine completion. Setup and upload do not deploy.

## Default workflow

The companion reviewed portal-system configuration pins new registrations to the already
reviewed nine-stage Python workflow/helper revision
`5ea1b7e414b2e1f23fad849127e1bb72ded84b45`. It includes source SAST and secret scanning.
Existing catalog entries and historical releases retain their approved versions and evidence.
An existing application's workflow migration is a separate reviewed change.

## Recovery and limits

Reloading the journey recovers server-side registration, setup and delivery journals without
resubmitting them. Client metadata contains only identity-scoped operation references and
form settings. Expired review tokens, changed source/settings/policy, revoked access,
conflicting files, wrong proposal heads and unverified health remain blockers. Interrupted
mutations retain the original recovery keys. Read-only polling stops on logout or navigation
and pauses while the document is hidden or an explicit action is in progress.

The original Prepare for DEV path remains for registrations without combined authorization.
This increment supports public Python web applications and the configured DEV cluster.

## Validation

The backend tests exercise signed combined authorization, journal recovery, tampering,
source/policy changes, independent catalog reviews, unrelated changes, revoked source access,
journey authorization, release numbering and measured health. The isolated labelled browser
walkthrough covers combined review, no extra setup confirmation, automatic transitions,
reload recovery, explicit deployment, safe file rendering and mobile layout. The existing
ZIP/recovery and explicit-setup walkthroughs also remain covered. Live rollout and the fresh
live application walkthrough are recorded separately; synthetic UI checks do not claim a live
release or deployment.
