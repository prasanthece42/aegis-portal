from copy import deepcopy
from uuid import uuid4

import pytest
from aegis_platform.canonical import digest
from aegis_platform.delivery import DeploymentFields, DeploymentSubmission

from app.demo import DemoBackend
from app.errors import PortalError


@pytest.fixture
def delivery(portal, monkeypatch):
    client, app = portal
    service = app.state.delivery
    service.config.delivery_workflow_commit = "d" * 40
    context = {
        "catalog_revision": "a" * 40,
        "catalog_entry_hash": digest("entry"),
        "resolved_policy_hash": digest("policy"),
        "source_repository_id": "101",
        "source_commit": "b" * 40,
        "release_workflow_run_id": "123",
        "release_evidence_hash": digest("receipt"),
        "image_root_digest": digest("image"),
        "platform_digests": {"linux/arm64": digest("arm")},
        "expected_desired_fingerprint": None,
        "expected_intent_anchor": None,
        "prior_environment_evidence": None,
    }
    monkeypatch.setattr(
        service.backend, "delivery_context", lambda *_: deepcopy(context), raising=False
    )
    monkeypatch.setattr(service.backend, "delivery_authorize", lambda *_: None, raising=False)
    issues = {}

    def issue(rid, record):
        issues.setdefault(rid, record)
        assert issues[rid] == record
        return {"id": "800", "number": 1, "url": "https://github.com/demo/aegis-platform/issues/1"}

    monkeypatch.setattr(service.backend, "delivery_issue", issue, raising=False)
    monkeypatch.setattr(service.backend, "delivery_dispatch", lambda *_: None, raising=False)
    return client, app, context, issues


def confirm(client, release_id="700"):
    fields = {"app_id": "orders-api", "environment": "dev", "release_id": release_id}
    preview = client.post("/api/v1/deployment-validations", json=fields)
    assert preview.status_code == 200, preview.text
    return {**fields, "review_token": preview.json()["review_token"]}


def test_default_demo_cannot_claim_or_submit_live_deployments(portal):
    client, _app = portal
    assert client.get("/api/v1/status").json()["deployment_enabled"] is False
    result = client.post(
        "/api/v1/deployment-validations",
        json={"app_id": "orders-api", "environment": "dev", "release_id": "700"},
    )
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "DELIVERY_SETUP_REQUIRED"


def test_signed_request_recovers_response_loss_and_rejects_key_reuse(delivery):
    client, app, _, issues = delivery
    fields, key = confirm(client), str(uuid4())
    first = client.post(
        "/api/v1/deployment-requests", json=fields, headers={"Idempotency-Key": key}
    )
    assert first.status_code == 202, first.text
    rid = first.json()["request_id"]
    assert rid.startswith("req-")
    assert len(issues) == 1
    # Browser lost its review token; the already-bound request can be recovered.
    repeated = client.post(
        "/api/v1/deployment-requests",
        json={**fields, "review_token": "recover-existing-reservation-only"},
        headers={"Idempotency-Key": key},
    )
    assert repeated.status_code == 202
    assert repeated.json()["request_id"] == rid
    assert len(issues) == 1
    changed = client.post(
        "/api/v1/deployment-requests",
        json={**fields, "release_id": "701"},
        headers={"Idempotency-Key": key},
    )
    assert changed.status_code == 409
    raw = app.state.delivery.backend.journal(rid)[1]
    assert app.state.delivery.signer.verify(raw)["intent"]["requester_user_id"] == "1"
    assert client.get(first.headers["Location"]).json()["request_id"] == rid


def test_changed_app_state_requires_new_review(delivery):
    client, _, context, issues = delivery
    fields = confirm(client)
    context["expected_desired_fingerprint"] = digest("another update")
    context["expected_intent_anchor"] = "c" * 40
    result = client.post(
        "/api/v1/deployment-requests", json=fields, headers={"Idempotency-Key": str(uuid4())}
    )
    assert result.status_code == 409
    assert not issues


def test_request_binding_recovers_after_issue_created(delivery, monkeypatch):
    client, app, _, issues = delivery
    fields, key = confirm(client), str(uuid4())
    backend = app.state.delivery.backend
    original = backend.save_journal
    failed = False

    def interrupted(rid, record, parent):
        nonlocal failed
        if parent and not failed:
            failed = True
            return False
        return original(rid, record, parent)

    monkeypatch.setattr(backend, "save_journal", interrupted)
    first = client.post(
        "/api/v1/deployment-requests", json=fields, headers={"Idempotency-Key": key}
    )
    assert first.status_code == 503
    second = client.post(
        "/api/v1/deployment-requests", json=fields, headers={"Idempotency-Key": key}
    )
    assert second.status_code == 202
    assert len(issues) == 1
    # Restart can load the signed reservation from disk, not just service memory.
    restarted = DemoBackend(backend.path)
    assert restarted.journal(second.json()["request_id"])


def test_retry_rechecks_current_authorization(delivery, monkeypatch):
    client, app, _, _ = delivery
    fields, key = confirm(client), str(uuid4())
    result = client.post(
        "/api/v1/deployment-requests", json=fields, headers={"Idempotency-Key": key}
    )
    assert result.status_code == 202

    def denied(*_):
        raise PortalError(403, "DEPLOYMENT_FORBIDDEN", "Grant revoked")

    monkeypatch.setattr(app.state.delivery.backend, "delivery_authorize", denied)
    assert client.get(result.headers["Location"]).status_code == 403


def test_completed_request_retry_does_not_redispatch_the_worker(delivery, monkeypatch):
    client, app, _, _ = delivery
    fields, key = confirm(client), str(uuid4())
    first = client.post(
        "/api/v1/deployment-requests", json=fields, headers={"Idempotency-Key": key}
    )
    assert first.status_code == 202
    backend = app.state.delivery.backend
    monkeypatch.setattr(
        backend,
        "delivery_status",
        lambda _: {"status": "healthy", "pull_request": {"merged": True}},
        raising=False,
    )

    def unexpected_dispatch(*_):
        pytest.fail("An already merged request must not re-enter deployment admission")

    monkeypatch.setattr(backend, "delivery_dispatch", unexpected_dispatch)
    repeated = client.post(
        "/api/v1/deployment-requests", json=fields, headers={"Idempotency-Key": key}
    )
    assert repeated.status_code == 202
    assert repeated.json()["request_id"] == first.json()["request_id"]


def test_deployment_json_contract_forbids_browser_destinations():
    with pytest.raises(ValueError):
        DeploymentFields.model_validate(
            {
                "app_id": "orders-api",
                "environment": "dev",
                "release_id": "700",
                "namespace": "kube-system",
            }
        )
    with pytest.raises(ValueError):
        DeploymentSubmission.model_validate(
            {"app_id": "orders-api", "environment": "dev", "release_id": "700"}
        )


@pytest.mark.parametrize("mismatch", [None, "user", "app", "sha", "run", "signature", "attempt"])
def test_pipeline_discovers_only_signed_matching_principal_app_source_and_run(
    delivery, monkeypatch, mismatch
):
    client, app, context, _ = delivery
    response = client.post(
        "/api/v1/deployment-requests",
        json=confirm(client),
        headers={"Idempotency-Key": str(uuid4())},
    )
    assert response.status_code == 202
    service = app.state.delivery
    rid = response.json()["request_id"]
    record = service.backend.journal(rid)[1]
    if mismatch:
        from copy import deepcopy

        record = deepcopy(record)
        changes = {
            "user": ("requester_user_id", "999"),
            "app": ("app_id", "other-app"),
            "sha": ("source_commit", "c" * 40),
            "run": ("release_workflow_run_id", "999"),
        }
        if mismatch in changes:
            key, value = changes[mismatch]
            record["payload"]["intent"][key] = value
            record = service.signer.seal(record["payload"])
        elif mismatch == "signature":
            record["payload"]["intent"]["release_id"] = "999"
    monkeypatch.setattr(service.backend, "delivery_records", lambda: [(rid, record)], raising=False)
    from types import SimpleNamespace

    monkeypatch.setattr(service.backend, "delivery_authorize", lambda *_: (None, None, None))
    monkeypatch.setattr(
        service.backend,
        "admitted_release",
        lambda *_: (SimpleNamespace(run_attempt=1), None, None),
        raising=False,
    )
    session = next(iter(app.state.sessions.records.values()))
    run = {"id": 123, "head_sha": "b" * 40, "run_attempt": 2 if mismatch == "attempt" else 1}
    if mismatch == "signature":
        with pytest.raises(PortalError, match="verified"):
            service.pipeline_status(session, "orders-api", run)
    else:
        result = service.pipeline_status(session, "orders-api", run)
        assert (result is not None) == (mismatch is None)


def test_latest_journey_delivery_is_durable_and_rechecks_current_access(delivery, monkeypatch):
    client, app, _, _ = delivery
    ids = []
    for release_id in ("700", "701"):
        response = client.post(
            "/api/v1/deployment-requests",
            json=confirm(client, release_id),
            headers={"Idempotency-Key": str(uuid4())},
        )
        assert response.status_code == 202
        ids.append(response.json()["request_id"])
    service = app.state.delivery
    monkeypatch.setattr(
        service.backend,
        "delivery_records",
        lambda: [(rid, service.backend.journal(rid)[1]) for rid in ids],
        raising=False,
    )
    session = next(iter(app.state.sessions.records.values()))
    result = service.latest_for_app(session, "orders-api")
    assert result["request_id"] == ids[-1] and result["release_id"] == "701"
    assert service.latest_for_app(session, "another-app") is None
    monkeypatch.setattr(
        service.backend,
        "delivery_authorize",
        lambda *_: (_ for _ in ()).throw(PortalError(403, "DENIED", "Access revoked")),
    )
    with pytest.raises(PortalError, match="revoked"):
        service.latest_for_app(session, "orders-api")
