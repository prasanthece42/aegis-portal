# Monitoring verification — 2026-10-27

The monitoring work remains a local source candidate. No deployed application, live
approval, branch protection or configured runtime was changed during this verification.

## Verified locally

- Portal: 146 tests passed; lint and formatting passed; JavaScript syntax checks passed.
- Platform: 232 tests passed; lint and formatting passed; active and example catalog
  validation passed. The recorded legacy source/workflow/GitOps baseline is unchanged.
- hello-aegis 1.1.0 candidate: 9 tests passed; lint and formatting passed. Tests exercise
  sanitized request metrics/logs/spans and trace propagation through an instrumented
  in-process portal fixture. This fixture is not the deployed portal.
- Monitoring browser smoke passed with synthetic hello-aegis telemetry: metrics, logs,
  alerts, traces, log-to-trace navigation, stale/unavailable states, slow-response
  environment switching, DEV-only target selection, HTML escaping, mobile layout and
  logout cleanup. No JavaScript errors. The live API still independently enforces grants.
- Existing in-portal review browser smoke passed with isolated provider fixtures:
  acknowledgement, human decision payload, blocked merge, escaping and mobile layout.
- Twelve pinned-image checks passed with networking disabled: five backend validators,
  five proxy validators, query authentication and alert firing/clearing. Anonymous and
  invalid query credentials are denied; authenticated writes and unknown paths are denied.
  Authentication success is checked against an absent upstream (502 after authentication).

The checks found and fixed stale browser responses overwriting newer environment data,
malformed provider payloads causing unhandled errors, serial chart/trace reads, incomplete
proxy temporary-path configuration for read-only filesystems, container-log credential
scrubbing gaps and collection stopping when an application namespace is unavailable.

## Evidence and reproduction

- Browser: `tests/monitoring-browser-smoke.cjs`; ignored results and mobile screenshot
  under `.local/monitoring-qa/`.
- Shared stack: sibling `aegis-platform/tooling/check_observability.py`; run
  `.venv/bin/python -m tooling.check_observability` from that repository with pinned images
  cached in Docker. Ignored results are `.local/observability-validation/results.json`.
- Current rendered public candidate: sibling platform directory
  `.local/observability-plan-monitoring-qa-v2/`. This uses the local source tree, with an
  existing commit as its revision placeholder. Regenerate against the final reviewed
  platform source revision before admission; the candidate is not an approved plan.
- Package: refreshed local platform 0.4.6 wheel, source manifest, lock and hashed
  requirements. This is a local source snapshot, not a published signed release.

## Remaining live work

Trusted exact-plan GitOps admission and scoped operator bootstrap tooling remain to be
implemented and reviewed. Then review/activate the shared stack and immutable portal and
hello-aegis releases through the existing approval controls. Finally verify actual deployed
request ingestion, container logs, alert transitions and cross-service traces. Offline
validation and synthetic browser fixtures do not establish these live results.

OAuth secret rotation requires a reviewed query-capability fingerprint and corresponding
private query credential update. Keep raw telemetry and all private credential values out
of the public GitOps ledger. Container-log scrubbing covers common credential patterns;
applications must avoid logging private payloads.
