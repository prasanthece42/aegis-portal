import base64
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from aegis_platform.canonical import canonical, digest
from aegis_platform.delivery import DeliveryPolicy
from aegis_platform.request import RequestTrust
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.contracts import RegistrationFields
from app.demo import demo_config
from app.errors import PortalError
from app.main import create_app
from app.owner_github import OwnerGitHub, observation_state, reported_ci_state, signed_activity
from app.registration import RegistrationService
from app.security import Signer


def test_owner_endpoint_requires_a_real_session(settings):
    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/platform/overview").status_code == 401


def test_owner_endpoint_is_read_only_and_demo_is_explicit(portal):
    client, _ = portal
    assert "platform:view" in client.get("/api/v1/session").json()["allowed_actions"]
    response = client.get("/api/v1/platform/overview")
    assert response.status_code == 200
    assert response.json()["mode"] == "demo"
    assert response.json()["access_mode"] == "read_only"
    assert response.json()["applications"] == []
    for method in ["POST", "PUT", "DELETE"]:
        assert client.request(method, "/api/v1/platform/overview", json={}).status_code == 405


def test_app_owner_does_not_implicitly_gain_platform_access(portal, monkeypatch):
    client, app = portal
    assert app.state.service.config.allowed_owner_user_ids == ["1"]
    monkeypatch.setattr(app.state.service.backend, "owner_allowed", lambda _: False)
    assert client.get("/api/v1/platform/overview?role=owner&user_id=1").status_code == 403
    assert "platform:view" not in client.get("/api/v1/session").json()["allowed_actions"]


def test_owner_lookup_outage_never_grants_access_or_breaks_developer_session(portal, monkeypatch):
    client, app = portal

    def unavailable(_):
        raise PortalError(503, "UNAVAILABLE", "Provider unavailable")

    monkeypatch.setattr(app.state.service.backend, "owner_allowed", unavailable)
    response = client.get("/api/v1/session")
    assert response.status_code == 200
    assert response.json()["allowed_actions"] == ["register"]
    assert response.json()["platform_owner_status"] == "unavailable"
    assert client.get("/api/v1/platform/overview").status_code == 503


@pytest.fixture
def policy_reader():
    gateway = OwnerGitHub()
    gateway.config = SimpleNamespace(
        platform_repository="demo/aegis-platform",
        platform_repository_id="900",
        platform_branch="main",
        platform_installation_id="901",
    )
    data = {
        "schema_version": 1,
        "platform_repository_id": "900",
        "mode": "read_only",
        "owner_user_ids": ["2"],
    }
    scopes = []

    def token(installation, repositories, permissions):
        scopes.append((installation, repositories, permissions))
        return "read-token"

    gateway.installation_token = token
    gateway.api = lambda method, path, _token: SimpleNamespace(
        json=lambda: {"id": 900} if path.endswith("aegis-platform") else {"sha": "a" * 40}
    )
    gateway.file = lambda *_: canonical(data)
    return gateway, data, scopes


def test_live_role_uses_explicit_policy_and_permission_reduced_token(policy_reader):
    gateway, _, scopes = policy_reader
    assert gateway.owner_allowed(SimpleNamespace(user_id="2"))
    assert not gateway.owner_allowed(SimpleNamespace(user_id="1"))
    with pytest.raises(PortalError) as exc:
        gateway.owner_context(SimpleNamespace(user_id="1"))
    assert exc.value.status == 403
    assert all(
        ids == ["900"] and all(value == "read" for value in permissions.values())
        for _, ids, permissions in scopes
    )


def test_owner_revocation_is_checked_on_every_request(policy_reader):
    gateway, data, _ = policy_reader
    session = SimpleNamespace(user_id="2")
    assert gateway.owner_allowed(session)
    data["owner_user_ids"] = []
    assert not gateway.owner_allowed(session)
    with pytest.raises(PortalError):
        gateway.owner_context(session)


def test_missing_or_wrong_audience_policy_fails_closed(policy_reader):
    gateway, data, _ = policy_reader
    data["platform_repository_id"] = "999"
    with pytest.raises(PortalError) as exc:
        gateway.owner_allowed(SimpleNamespace(user_id="2"))
    assert exc.value.status == 503
    gateway.file = lambda *_: None
    assert not gateway.owner_allowed(SimpleNamespace(user_id="2"))


def test_invalid_inventory_is_never_silently_hidden(policy_reader):
    gateway, _, _ = policy_reader
    gateway.api = lambda *_args, **_kwargs: SimpleNamespace(json=lambda: [None] * 101)
    with pytest.raises(PortalError, match="budget"):
        gateway.owner_directory("catalog/apps", "a" * 40, "read-token", object)


def test_malformed_provider_metadata_fails_closed_without_breaking_session(policy_reader):
    gateway, _, _ = policy_reader
    gateway.api = lambda *_: SimpleNamespace(json=lambda: {})
    with pytest.raises(PortalError) as exc:
        gateway.owner_allowed(SimpleNamespace(user_id="2"))
    assert exc.value.code == "OWNER_POLICY_INVALID"


def test_owner_snapshot_binds_catalog_and_desired_state_to_resolved_revisions(
    policy_reader, fields
):
    gateway, owner, scopes = policy_reader
    config = demo_config()
    config.versions.helper_commit = config.versions.workflow_commit
    config.gitops_installation_id = "905"
    config.gitops_repository = "demo/aegis-gitops"
    gateway.config = config
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
    bootstrap = {"resource_profiles": config.model_dump()["resource_profiles"]}
    _, _, delivery, _ = health_case()
    delivery.bootstrap_policy_hash = digest(bootstrap)
    issue, trust = signed_issue()
    documents = {
        "policies/portal-owner.json": owner,
        "policies/delivery.json": delivery.model_dump(),
        "policies/bootstrap.json": bootstrap,
        "policies/request-trust.json": trust.model_dump(),
        "policies/catalog.json": {
            "schema_version": 1,
            "resource_profile_ids": ["small"],
            "runtime_profile_ids": ["python312-web"],
            "environment_branches": {"dev": "main", "staging": "staging", "prod": "prod"},
            "production_human_review_required": True,
            "protected_sync_mode": "operator",
            "max_applications": 100,
        },
        "catalog/apps/orders-api.json": entry,
        "catalog/clusters/kind-local.json": {
            "schema_version": 1,
            "cluster_id": config.cluster_id,
            "cluster_uid": config.cluster_uid,
            "gitops_repository_id": "904",
            "profile_id": "kind-small",
        },
    }

    def api(method, path, token, **kwargs):
        assert method == "GET"
        if "/contents/" in path:
            assert kwargs["params"]["ref"] == "a" * 40
            name = "orders-api.json" if path.endswith("apps") else "kind-local.json"
            value = [{"name": name, "type": "file"}]
        elif "/commits/" in path:
            value = {"sha": ("b" if "gitops" in path else "a") * 40}
        else:
            value = {"id": 904 if path.endswith("gitops") else 900}
        return SimpleNamespace(json=lambda: value)

    def file(repo, path, revision, token):
        assert revision == "a" * 40
        return canonical(documents[path])

    desired_reads = []

    def current(_entry, environment, policy, *, revision):
        desired_reads.append((environment, revision))
        return None

    gateway.api, gateway.file, gateway.current_intent = api, file, current
    gateway.paginate = lambda path, *_args, **_kwargs: [issue] if path.endswith("issues") else []
    snapshot = gateway.owner_overview(SimpleNamespace(user_id="2"))
    assert snapshot["applications"][0]["environments"][0]["state"] == "not_deployed"
    assert snapshot["clusters"][0]["state"] == "enrolled"
    assert snapshot["activity"][0]["integrity"] == "verified"
    assert desired_reads == [("dev", "b" * 40)]
    assert all(len(ids) == 1 and set(p.values()) == {"read"} for _, ids, p in scopes)
    documents["policies/delivery.json"] = None
    with pytest.raises(PortalError) as exc:
        gateway.owner_overview(SimpleNamespace(user_id="2"))
    assert exc.value.code == "OWNER_SNAPSHOT_INVALID"


def test_reported_ci_uses_latest_results_without_claiming_branch_authority():
    old = {"id": 1, "context": "policy", "state": "failure"}
    new = {**old, "id": 2, "state": "success"}
    assert reported_ci_state([], [old, new]) == "reported_passed"
    assert reported_ci_state([], [new, {**new, "id": 3, "state": "pending"}]) == "running"
    assert reported_ci_state([], [new, {**new, "id": 3, "state": "failure"}]) == "failing"
    check = {"id": 1, "name": "contracts", "status": "completed", "conclusion": "failure"}
    assert (
        reported_ci_state([check, {**check, "id": 2, "conclusion": "success"}], [])
        == "reported_passed"
    )
    assert reported_ci_state([], []) == "unknown"


def health_case():
    now = datetime.now(UTC)
    current = SimpleNamespace(fingerprint=digest("state"), intent_anchor="a" * 40)
    policy = DeliveryPolicy(
        platform_repository="demo/aegis-platform",
        platform_repository_id="900",
        gitops_repository="demo/aegis-gitops",
        gitops_repository_id="904",
        bootstrap_policy_hash=digest("bootstrap"),
        workflow_bot_user_ids=["41898282"],
        observer_user_ids=["1"],
        production_reviewer_user_ids=["1"],
    )
    row = {
        "id": 1,
        "sha": current.intent_anchor,
        "creator": {"id": 1},
        "context": "aegis/orders-api/dev-health",
        "state": "success",
        "description": "Healthy " + current.fingerprint,
        "created_at": now.isoformat(),
    }
    return now, current, policy, row


def test_owner_health_never_turns_stale_failed_or_wrong_fingerprint_evidence_green():
    now, current, policy, row = health_case()
    entry = SimpleNamespace(app_id="orders-api")

    def read(rows):
        return observation_state(rows, entry, "dev", current, policy, now)["state"]

    assert read([row]) == "healthy"
    assert read([{**row, "created_at": (now - timedelta(minutes=6)).isoformat()}]) == "stale"
    assert read([row, {**row, "id": 2, "state": "failure"}]) == "unverified"
    assert read([{**row, "description": "Healthy " + digest("other state")}]) == "unverified"
    assert read([{**row, "creator": {"id": 999}}]) == "unverified"


def signed_issue():
    key = Ed25519PrivateKey.generate()
    public = base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    trust = RequestTrust(
        platform_repository_id="900",
        issuers=[
            {
                "issuer_id": "fixture",
                "key_id": "fixture-key",
                "public_key_base64": public,
                "bot_user_id": "902",
                "active": False,
            }
        ],
    )
    intent = {
        "schema_version": 1,
        "request_id": "req-" + "a" * 64,
        "issuer_id": "fixture",
        "platform_repository_id": "900",
        "requester_user_id": "1",
        "created_at": (datetime.now(UTC) - timedelta(days=3)).isoformat(),
        "idempotency_key_hash": digest("key"),
        "payload_hash": digest("payload"),
        "app_id": "orders-api",
        "environment": "dev",
        "operation": "deploy",
        "origin": "portal",
        "catalog_revision": "a" * 40,
        "catalog_entry_hash": digest("entry"),
        "resolved_policy_hash": digest("policy"),
        "source_repository_id": "101",
        "source_commit": "b" * 40,
        "release_id": "700",
        "release_workflow_run_id": "123",
        "release_evidence_hash": digest("receipt"),
        "image_root_digest": digest("image"),
        "platform_digests": {"linux/arm64": digest("arm")},
        "expected_desired_fingerprint": None,
        "expected_intent_anchor": None,
        "prior_environment_evidence": None,
    }
    record = Signer(key, "fixture-key").seal({"kind": "deployment_intent", "intent": intent})
    issue = {
        "number": 12,
        "user": {"id": 902, "type": "Bot"},
        "title": "Aegis delivery " + intent["request_id"],
        "body": json.dumps(record),
    }
    return issue, trust


def test_historical_activity_verifies_signature_without_granting_fresh_admission():
    issue, trust = signed_issue()
    row = signed_activity(issue, trust)
    assert row["integrity"] == "verified"
    assert row["issuer_active"] is False
    assert "health" not in row and "token" not in row
    tampered = deepcopy(issue)
    body = json.loads(tampered["body"])
    body["payload"]["intent"]["app_id"] = "other-app"
    tampered["body"] = json.dumps(body)
    assert signed_activity(tampered, trust)["integrity"] == "unverified"
    issue["user"]["id"] = 999
    assert signed_activity(issue, trust)["integrity"] == "unverified"
