from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.demo import DemoBackend
from app.errors import PortalError
from app.main import create_app


def submit(confirmed):
    client, _app, payload, key = confirmed
    return client.post("/api/v1/registrations", json=payload, headers={"Idempotency-Key": key})


def test_confirmed_registration_has_separate_setup_states(confirmed):
    response = submit(confirmed)
    assert response.status_code == 201, response.text
    result = response.json()
    assert response.headers["Location"].endswith(result["registration_id"])
    assert result["deployment_available"] is False
    assert result["pull_request"]["demo"] is True
    assert result["pull_request"]["url"] is None
    assert [r["status"] for r in result["requirements"]] == [
        "pending_review",
        "validation_required",
        "operator_setup_required",
        "not_verified",
    ]
    client, app, _payload, _key = confirmed
    journal = app.state.service.backend.journal(result["registration_id"])
    payload = app.state.service.signer.verify(journal[1])
    entry = payload["catalog_entry"]
    assert set(entry["environments"]) == {"dev"}
    assert entry["environments"]["dev"]["delivery_mode"] == "manual"
    assert entry["environments"]["dev"]["namespace"] == "aegis-orders-api-dev"
    assert (
        client.get("/api/v1/registrations").json()["items"][0]["registration_id"]
        == result["registration_id"]
    )


def test_duplicate_clicks_reuse_one_durable_registration(confirmed):
    first, second = submit(confirmed), submit(confirmed)
    assert first.status_code == second.status_code == 201
    assert first.json()["registration_id"] == second.json()["registration_id"]
    assert len(confirmed[1].state.service.backend.journal_ids()) == 1


def test_same_key_different_configuration_is_conflict(confirmed):
    assert submit(confirmed).status_code == 201
    client, _app, payload, key = confirmed
    modified = deepcopy(payload)
    modified["runtime"]["container_port"] = 9000
    response = client.post("/api/v1/registrations", json=modified, headers={"Idempotency-Key": key})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"


def test_reusing_repo_or_app_id_rejected(confirmed, fields):
    assert submit(confirmed).status_code == 201
    client = confirmed[0]
    assert client.post("/api/v1/registration-validations", json=fields).status_code == 409
    changed = {**fields, "repository_id": "102"}
    assert client.post("/api/v1/registration-validations", json=changed).status_code == 409


@pytest.mark.parametrize("changed", ["payload", "source", "policy"])
def test_relevant_change_requires_fresh_review(confirmed, monkeypatch, changed):
    client, app, payload, key = confirmed
    if changed == "payload":
        payload = {**payload, "display_name": "Changed name"}
    elif changed == "policy":
        app.state.service.config.cluster_uid = "replacement-cluster"
    else:
        backend = app.state.service.backend
        original = backend.source
        monkeypatch.setattr(
            backend, "source", lambda *args: {**original(*args), "source_commit": "e" * 40}
        )
    response = client.post("/api/v1/registrations", json=payload, headers={"Idempotency-Key": key})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "REVIEW_REQUIRED"
    assert not app.state.service.backend.journal_ids()


def test_expired_review_cannot_create_registration(confirmed):
    client, app, payload, key = confirmed
    signer = app.state.service.signer
    review = signer.read_review(payload["review_token"])
    payload["review_token"] = signer.review_token(review, now=1)
    response = client.post("/api/v1/registrations", json=payload, headers={"Idempotency-Key": key})
    assert response.status_code == 409


def test_pr_failure_recovers_same_reserved_operation(confirmed, monkeypatch):
    client, app, _payload, _key = confirmed
    backend = app.state.service.backend
    original = backend.registration_pr

    def unavailable(*_args):
        raise PortalError(503, "GITHUB_UNAVAILABLE", "Temporarily unavailable", True)

    monkeypatch.setattr(backend, "registration_pr", unavailable)
    assert submit(confirmed).status_code == 503
    rid = backend.journal_ids()[0]
    assert backend.journal(rid)[1]["payload"]["binding"] is None
    monkeypatch.setattr(backend, "registration_pr", original)
    recovered = submit(confirmed)
    assert recovered.status_code == 201
    assert recovered.json()["registration_id"] == rid


def test_pr_persisted_but_binding_failed_is_resumable(confirmed, monkeypatch):
    _client, app, _payload, _key = confirmed
    backend = app.state.service.backend
    original = backend.save_journal

    def fail_binding(rid, record, parent):
        if parent:
            raise PortalError(503, "JOURNAL_UNAVAILABLE", "Interrupted binding", True)
        return original(rid, record, parent)

    monkeypatch.setattr(backend, "save_journal", fail_binding)
    assert submit(confirmed).status_code == 503
    monkeypatch.setattr(backend, "save_journal", original)
    assert submit(confirmed).status_code == 201
    assert len(backend.journal_ids()) == 1


def test_restart_preserves_registration_but_requires_new_sign_in(confirmed, settings):
    rid = submit(confirmed).json()["registration_id"]
    with TestClient(create_app(settings)) as restarted:
        assert restarted.get(f"/api/v1/registrations/{rid}").status_code == 401
        restarted.post("/auth/demo", headers={"Origin": "http://testserver"})
        response = restarted.get(f"/api/v1/registrations/{rid}")
        assert response.status_code == 200
        assert response.json()["app_id"] == "orders-api"


def test_tampered_signed_journal_is_rejected(confirmed):
    rid = submit(confirmed).json()["registration_id"]
    client, app, _payload, _key = confirmed
    backend = app.state.service.backend
    backend.data[rid]["record"]["payload"]["fields"]["app_id"] = "foreign-app"
    response = client.get(f"/api/v1/registrations/{rid}")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "JOURNAL_INVALID"


def test_second_identity_cannot_view_request(confirmed):
    rid = submit(confirmed).json()["registration_id"]
    client, app, _payload, _key = confirmed
    sid = app.state.sessions.create("2", "other-user", "synthetic-token")
    client.cookies.set("aegis_demo_session", sid)
    assert client.get(f"/api/v1/registrations/{rid}").status_code == 404
    assert client.get("/api/v1/registrations").json()["items"] == []


def test_repository_access_revocation_prevents_replay(confirmed, monkeypatch):
    assert submit(confirmed).status_code == 201
    backend = confirmed[1].state.service.backend
    monkeypatch.setattr(backend, "repositories", lambda _session: [])
    assert submit(confirmed).status_code == 404


def test_cas_rejects_divergent_journal_updates(tmp_path):
    backend = DemoBackend(tmp_path / "records.json")
    assert backend.save_journal("reg-test", {"test": 1}, None)
    assert not backend.save_journal("reg-test", {"test": 2}, None)
    assert backend.save_journal("reg-test", {"test": 2}, "1")
    assert not backend.save_journal("reg-test", {"test": 3}, "1")


def test_overlapping_duplicate_submissions_have_one_reservation(confirmed):
    _client, app, payload, key = confirmed
    service = app.state.service
    session = next(iter(app.state.sessions.records.values()))
    from app.contracts import RegistrationSubmission

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(
            executor.map(
                lambda _: service.submit(
                    session, RegistrationSubmission.model_validate(payload), key
                ),
                range(4),
            )
        )
    assert len({r["registration_id"] for r in results}) == 1
    assert len(service.backend.journal_ids()) == 1


def test_new_key_cannot_submit_without_review(portal, fields):
    client, _app = portal
    response = client.post(
        "/api/v1/registrations",
        json={**fields, "review_token": "recover-existing-reservation-only"},
        headers={"Idempotency-Key": str(uuid4())},
    )
    assert response.status_code == 409
