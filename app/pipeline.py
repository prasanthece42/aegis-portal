"""Authorized DEV pipeline discovery; provider job names never authorize delivery."""

import re

from aegis_platform.pipeline import dev_pipeline, job_state

from app.errors import PortalError


def discover(backend, session, app_id, *, release_id=None, delivery=None, delivery_lookup=None):
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
    family = (
        "python-stack"
        if getattr(getattr(entry, "runtime", None), "profile_id", "python312-web")
        == "python312-multiservice"
        else "python-web"
    )
    expected = f"{policy.platform_repository}/.github/workflows/{family}-release.yml@{pin}"
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
    if delivery is None and delivery_lookup is not None:
        delivery = delivery_lookup(run)
    complete = run.get("status") == "completed"
    result = dev_pipeline(
        jobs, delivery=delivery, complete=complete, stack=family == "python-stack"
    )
    if pin == LEGACY_PIN:
        legacy_stages(result, jobs, complete)
    result.update(
        source_commit=run["head_sha"],
        run_id=str(run["id"]),
        run_attempt=run["run_attempt"],
        run_status=run.get("status"),
        run_conclusion=run.get("conclusion"),
    )
    return result


# This immutable workflow bundles lint/tests and predates the separate source scan.
LEGACY_PIN = "b4f46baa41dc250a88c86f63ecb0949d5f14af02"


def legacy_stages(result, jobs, complete):
    def step(job_name, names):
        matches = [j for j in jobs if j.get("name", "").rsplit(" / ", 1)[-1] == job_name]
        if len(matches) != 1:
            return "unknown" if complete or matches else "queued"
        selected = []
        for name in names:
            values = [s for s in matches[0].get("steps", []) if s.get("name") == name]
            if len(values) != 1:
                return (
                    "unknown"
                    if complete or matches[0].get("status") == "completed" or values
                    else "queued"
                )
            selected.append(job_state(values[0]))
        for state in ("failed", "cancelled", "unknown", "running", "queued", "skipped"):
            if state in selected:
                return state
        return "passed"

    def combine(states):
        for state in ("failed", "cancelled", "unknown", "running", "queued", "skipped"):
            if state in states:
                return state
        return "passed"

    checks = step("checks", ["Validate source in its own Python environment"])
    for stage in result["stages"][:3]:
        stage.update(
            state=checks if checks in {"passed", "queued", "running"} else "unknown",
            message="Source, lint, format and tests share one step in this approved workflow.",
        )
    result["stages"][3].update(
        state="unknown",
        message="This approved workflow version does not run a separate source-security scan.",
    )
    result["stages"][4].update(state=step("checks", ["Scan source dependency lock"]), message="")
    for number, names in (
        (
            5,
            [
                "Build source-labelled candidate",
                "Verify candidate runtime through the trusted helper",
                "Preserve exact tested candidate",
            ],
        ),
        (
            6,
            [
                "Scan candidate and generate SBOM",
                "Bind candidate identity and exact scan/archive evidence",
            ],
        ),
    ):
        result["stages"][number].update(
            state=combine([step(f"container ({arch})", names) for arch in ("amd64", "arm64")]),
            message="",
        )
    states = [
        step(
            f"publish ({arch})",
            [
                "Publish OCI platform manifest preserving tested config/layers",
                "Verify exact digest runtime then record platform publication",
            ],
        )
        for arch in ("amd64", "arm64")
    ]
    states.append(
        step(
            "release-index",
            [
                "Combine only verified immutable platform references",
                "Publish multi-platform index without rebuilding",
                "Export exact OCI root and all referenced content",
                "Verify draft asset bytes before publishing the source release",
            ],
        )
    )
    result["stages"][7].update(state=combine(states), message="")
    for stage in result["stages"][:8]:
        if stage["state"] == "unknown" and not stage["message"]:
            stage["message"] = "Exact job or step evidence is missing or ambiguous."
