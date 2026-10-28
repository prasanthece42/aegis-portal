"""Authorized DEV pipeline discovery; provider job names never authorize delivery."""

import re

from aegis_platform.pipeline import dev_pipeline

from app.errors import PortalError


def discover(backend, session, app_id, *, release_id=None, delivery=None):
    entry, _revision, policy = backend.delivery_authorize(session, app_id, "dev")
    source = entry.source.owner + "/" + entry.source.name
    token = backend.delivery_source_token(entry)
    if release_id:
        evidence, _, _ = backend.admitted_release(entry, release_id, policy)
        run = backend.api(
            "GET",
            f"/repos/{source}/actions/runs/{evidence.workflow_run_id}"
            f"/attempts/{evidence.run_attempt}",
            token,
        ).json()
    else:
        result = backend.api(
            "GET",
            f"/repos/{source}/actions/workflows/release.yml/runs",
            token,
            params={"branch": entry.source.default_branch, "per_page": 10},
        ).json()
        runs = [
            r
            for r in result.get("workflow_runs", [])
            if r.get("event") in {"push", "workflow_dispatch"}
        ]
        if not runs:
            result = dev_pipeline([], complete=True)
            result["message"] = "No supported release pipeline run has been observed"
            return result
        latest = runs[0]
        if (
            not str(latest.get("id", "")).isdecimal()
            or not str(latest.get("run_attempt", "")).isdecimal()
        ):
            raise PortalError(503, "PIPELINE_UNVERIFIED", "Pipeline identity is unavailable.")
        run = backend.api(
            "GET",
            f"/repos/{source}/actions/runs/{latest['id']}/attempts/{latest['run_attempt']}",
            token,
        ).json()
    pin = entry.versions.workflow_commit
    expected = f"{policy.platform_repository}/.github/workflows/python-web-release.yml@{pin}"
    if (
        str(run.get("repository", {}).get("id")) != entry.source.repository_id
        or run.get("head_branch") != entry.source.default_branch
        or run.get("event") not in {"push", "workflow_dispatch"}
        or run.get("path") != ".github/workflows/release.yml"
        or not re.fullmatch(r"[0-9a-f]{40}", run.get("head_sha", ""))
        or not str(run.get("id", "")).isdecimal()
        or not str(run.get("run_attempt", "")).isdecimal()
        or not any(
            w.get("path") == expected and w.get("sha") == pin
            for w in run.get("referenced_workflows", [])
        )
    ):
        raise PortalError(
            409, "PIPELINE_UNVERIFIED", "Pipeline source or approved version differs."
        )
    jobs = backend.paginate(
        f"/repos/{source}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs",
        token,
        "jobs",
    )
    if any(str(j.get("run_id")) != str(run["id"]) for j in jobs):
        raise PortalError(503, "PIPELINE_UNVERIFIED", "Pipeline job identity differs.")
    result = dev_pipeline(jobs, delivery=delivery, complete=run.get("status") == "completed")
    result.update(
        source_commit=run["head_sha"],
        run_id=str(run["id"]),
        run_attempt=run["run_attempt"],
        run_status=run.get("status"),
        run_conclusion=run.get("conclusion"),
    )
    return result
