from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from aegis_platform.canonical import canonical, digest
from aegis_platform.delivery import CurrentIntent, DeliveryPolicy

from app.contracts import RegistrationFields
from app.demo import demo_config
from app.errors import PortalError
from app.github import GitHub
from app.registration import RegistrationService


@pytest.fixture
def status_reader(fields):
    config = demo_config()
    entry = RegistrationService(config, None, None).entry(
        RegistrationFields.model_validate(fields),
        {
            "repository_id": "101",
            "installation_id": "903",
            "owner": "demo",
            "name": "orders-api",
            "default_branch": "main",
        },
    )
    policy = DeliveryPolicy(
        platform_repository="demo/aegis-platform",
        platform_repository_id="900",
        gitops_repository="demo/aegis-gitops",
        gitops_repository_id="904",
        bootstrap_policy_hash=digest("bootstrap"),
        workflow_bot_user_ids=["41898282"],
        observer_user_ids=["123"],
        production_reviewer_user_ids=["1"],
    )
    rid = "req-" + "a" * 64
    intent = {"request_id": rid, "app_id": "orders-api", "environment": "dev"}
    pr = {
        "number": 5,
        "html_url": "https://github.com/demo/aegis-gitops/pull/5",
        "state": "closed",
        "merged_at": datetime.now(UTC).isoformat(),
        "user": {"id": 41898282, "type": "Bot"},
        "head": {"ref": "aegis-requests/" + rid, "repo": {"id": 904}},
        "base": {"ref": "main", "repo": {"id": 904}},
    }
    current = CurrentIntent(
        fingerprint=digest("desired"),
        intent_anchor="b" * 40,
        source_commit="c" * 40,
        image_root_digest=digest("image"),
        release_id="700",
    )
    row = {
        "id": 1,
        "sha": current.intent_anchor,
        "creator": {"id": 123},
        "context": "aegis/orders-api/dev-health",
        "description": "Healthy " + current.fingerprint,
        "state": "success",
        "created_at": datetime.now(UTC).isoformat(),
    }
    gateway = GitHub.__new__(GitHub)
    gateway.config = config
    gateway.catalog_snapshot = lambda: ("d" * 40, policy)
    gateway.gitops_token = lambda: "fixture-reader"
    gateway.platform_token = lambda: "fixture-reader"
    gateway.api = lambda *_: SimpleNamespace(json=lambda: pr)
    gateway.paginate = lambda path, *_args, **_kwargs: [row] if path.endswith("/statuses") else [pr]
    gateway.file = lambda _repo, path, *_: canonical(
        entry if path.startswith("catalog/") else {"delivery_id": rid}
    )
    gateway.current_intent = lambda *_: current
    return gateway, intent, row, pr


def test_request_is_healthy_only_after_a_fresh_bound_observer_measurement(status_reader):
    gateway, intent, _, _ = status_reader
    result = gateway.delivery_status(intent)
    assert result["status"] == result["health"] == "healthy"
    assert result["pull_request"]["merged"] is True
    assert result["health_observed_at"]


@pytest.mark.parametrize("mutation", ["failure", "wrong_observer", "stale"])
def test_failed_untrusted_or_stale_measurements_never_appear_healthy(status_reader, mutation):
    gateway, intent, row, _ = status_reader
    if mutation == "failure":
        row["state"] = "failure"
    elif mutation == "wrong_observer":
        row["creator"]["id"] = 999
    else:
        row["created_at"] = (datetime.now(UTC) - timedelta(minutes=6)).isoformat()
    result = gateway.delivery_status(intent)
    assert result["status"] == "reconciling"
    assert result["health"] != "healthy"


def test_wrong_pr_issuer_is_rejected(status_reader):
    gateway, intent, _, pr = status_reader
    pr["user"]["id"] = 999
    with pytest.raises(PortalError):
        gateway.delivery_status(intent)


def test_newer_intent_supersedes_old_request_without_claiming_current_health(status_reader):
    gateway, intent, _, _ = status_reader
    gateway.file = lambda _repo, path, *_: canonical(
        {"delivery_id": "req-" + "f" * 64}
        if not path.startswith("catalog/")
        else RegistrationService(demo_config(), None, None).entry(
            RegistrationFields.model_validate(
                {
                    "repository_id": "101",
                    "app_id": "orders-api",
                    "display_name": "Orders API",
                    "owner_user_ids": ["1"],
                    "runtime": {
                        "container_port": 8000,
                        "health_path": "/health",
                        "resource_profile_id": "small",
                    },
                }
            ),
            {
                "repository_id": "101",
                "installation_id": "903",
                "owner": "demo",
                "name": "orders-api",
                "default_branch": "main",
            },
        )
    )
    assert gateway.delivery_status(intent)["status"] == "superseded"
