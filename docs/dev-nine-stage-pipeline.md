# DEV pipeline progress

The Applications screen exposes a DEV pipeline action for current DEV deployers.
It reads the latest default-branch release workflow run, including failed runs that
never created a release. The deployment-request screen exposes the same nine-stage
view bound to its admitted release and exact run attempt.

Every read rechecks the current DEV grant and source access. Run repository, branch,
workflow path, commit and pinned reusable release workflow are verified. Jobs are
read from the exact attempt, not mixed across reruns. Both architecture jobs and
final release verification are required before an aggregated stage passes. Missing
legacy stages show Not verified; skipped/cancelled/failed jobs never become Passed.

The ninth stage requires fresh trusted health and DEV runtime-security observations
bound to the current app-specific intent. Missing security evidence is Not verified.
The latest pipeline view does not infer deployment success from CI; use the bound
deployment request to view its measured rollout. Unavailable providers clear displayed
data. Identity changes and navigation discard delayed responses; logout clears data.

This change adds observation only. It does not submit deployments automatically,
merge proposals, change approval policy or expose raw scanner findings or credentials.
The portal uses hash-pinned platform 0.4.7. Existing app caller/catalog pins must be
reviewed and upgraded before new runs emit the nine-stage evidence.

## Validation

Python tests cover current grants, source/pin/run binding, exact attempts, failed
pre-release runs and trusted runtime evidence. The isolated Playwright test covers
nine stages, failed/skipped states, escaping, mobile layout, unavailable-data clearing
and logout clearing, using synthetic responses only.

Publish the portal's immutable release and review its exact system GitOps plan before
updating the configured front door. A local source change does not update the running
portal. See the platform docs/dev-nine-stage-pipeline.md for pilot activation order.
