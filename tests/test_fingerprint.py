import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.contracts import DesiredState
from app.fingerprint import desired_fingerprint

FIXTURE = json.loads((Path(__file__).parent / "fixtures/fingerprint-v1.json").read_text())


def test_canonical_fingerprint_matches_published_fixture():
    state = DesiredState.model_validate(FIXTURE["input"])
    assert desired_fingerprint(state) == FIXTURE["expected_fingerprint"]
    reversed_keys = dict(reversed(list(FIXTURE["input"].items())))
    assert (
        desired_fingerprint(DesiredState.model_validate(reversed_keys))
        == FIXTURE["expected_fingerprint"]
    )


@pytest.mark.parametrize("change", ["cluster", "image", "values", "profile", "controller"])
def test_relevant_app_changes_invalidate_health_identity(change):
    data = deepcopy(FIXTURE["input"])
    if change == "cluster":
        data["cluster_uid"] = "replacement-cluster"
    elif change == "image":
        data["image_root_digest"] = "sha256:" + "e" * 64
    elif change == "values":
        data["effective_values"]["replicaCount"] = 2
    elif change == "profile":
        data["resolved_cluster_profile"]["resourceProfile"] = "medium"
    else:
        data["controller_bindings"]["project"] = "another-project"
    assert desired_fingerprint(DesiredState.model_validate(data)) != FIXTURE["expected_fingerprint"]


def test_unrelated_branch_head_is_not_a_fingerprint_input():
    with pytest.raises(ValidationError):
        DesiredState.model_validate({**FIXTURE["input"], "global_branch_head": "a" * 40})
    app_a = DesiredState.model_validate(FIXTURE["input"])
    app_b = app_a.model_copy(
        update={"app_id": "payments-api", "namespace": "aegis-payments-api-dev"}
    )
    app_b = app_b.model_copy(update={"effective_values": {"replicaCount": 2}})
    assert desired_fingerprint(app_b) != desired_fingerprint(app_a)
    assert desired_fingerprint(app_a) == FIXTURE["expected_fingerprint"]
