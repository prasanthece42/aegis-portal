from types import SimpleNamespace

import pytest

from app.errors import PortalError
from app.pipeline import discover


@pytest.fixture
def pipeline_reader():
    pin = "a" * 40
    entry = SimpleNamespace(
        source=SimpleNamespace(
            owner="demo", name="orders", repository_id="101", default_branch="main"
        ),
        versions=SimpleNamespace(workflow_commit=pin),
    )
    run = {
        "id": 42,
        "run_attempt": 2,
        "repository": {"id": 101},
        "head_branch": "main",
        "head_sha": "b" * 40,
        "event": "push",
        "path": ".github/workflows/release.yml",
        "status": "completed",
        "conclusion": "failure",
        "referenced_workflows": [
            {"path": f"demo/platform/.github/workflows/python-web-release.yml@{pin}", "sha": pin}
        ],
    }
    jobs = [
        {
            "run_id": 42,
            "name": "validate / 04 Source security",
            "status": "completed",
            "conclusion": "failure",
        }
    ]
    calls = []

    class Backend:
        def delivery_authorize(self, session, app_id, environment):
            calls.append((session.user_id, app_id, environment))
            if session.user_id != "1":
                raise PortalError(403, "FORBIDDEN", "Current DEV grant required")
            return entry, "c" * 40, SimpleNamespace(platform_repository="demo/platform")

        def delivery_source_token(self, _entry):
            return "synthetic-read-token"

        def admitted_release(self, *_):
            return SimpleNamespace(workflow_run_id="42", run_attempt="2"), None, None

        def api(self, method, path, *_args, **_kwargs):
            assert method == "GET"
            calls.append(path)
            return SimpleNamespace(
                json=lambda: {"workflow_runs": [run]} if path.endswith("/runs") else run
            )

        def paginate(self, path, _token, collection):
            assert path.endswith("/runs/42/attempts/2/jobs")
            assert collection == "jobs"
            return jobs

    return Backend(), run, jobs, calls


def test_failed_source_security_is_visible_before_any_release_exists(pipeline_reader):
    backend, _, _, calls = pipeline_reader
    result = discover(backend, SimpleNamespace(user_id="1"), "orders")
    assert calls[0] == ("1", "orders", "dev")
    assert result["run_attempt"] == 2
    assert result["stages"][3]["state"] == "failed"
    assert result["stages"][8]["state"] == "queued"
    assert result["stages"][0]["state"] == "unknown"


def test_pipeline_rechecks_current_dev_grant_before_reading_runs(pipeline_reader):
    backend, _, _, calls = pipeline_reader
    with pytest.raises(PortalError, match="DEV grant"):
        discover(backend, SimpleNamespace(user_id="2"), "orders")
    assert len(calls) == 1


@pytest.mark.parametrize("mutation", ["repository", "branch", "pin", "attempt_job"])
def test_wrong_source_or_workflow_evidence_is_rejected(pipeline_reader, mutation):
    backend, run, jobs, _ = pipeline_reader
    if mutation == "repository":
        run["repository"]["id"] = 999
    elif mutation == "branch":
        run["head_branch"] = "feature"
    elif mutation == "pin":
        run["referenced_workflows"][0]["sha"] = "d" * 40
    else:
        jobs[0]["run_id"] = 99
    with pytest.raises(PortalError):
        discover(backend, SimpleNamespace(user_id="1"), "orders")


def test_selected_release_does_not_use_newest_run(pipeline_reader):
    backend, _, _, calls = pipeline_reader
    discover(backend, SimpleNamespace(user_id="1"), "orders", release_id="7")
    assert calls[1].endswith("/runs/42/attempts/2")
