import json
import time
from copy import deepcopy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.security import Sessions, Signer, digest, strict_json


@pytest.mark.parametrize("mutation", ["owner", "repository", "namespace", "prod", "profile"])
def test_browser_cannot_grant_authority(portal, fields, mutation):
    client, _app = portal
    payload = deepcopy(fields)
    if mutation == "owner":
        payload["owner_user_ids"] = ["2"]
    elif mutation == "repository":
        payload["repository_id"] = "999"
    elif mutation == "namespace":
        payload["namespace"] = "kube-system"
    elif mutation == "prod":
        payload["environment"] = "prod"
    else:
        payload["runtime"]["resource_profile_id"] = "unbounded"
    response = client.post("/api/v1/registration-validations", json=payload)
    assert response.status_code in {403, 404, 422}


def test_csrf_and_origin_are_both_required(portal, fields):
    client, _app = portal
    assert (
        client.post(
            "/api/v1/registration-validations",
            json=fields,
            headers={"Origin": "https://evil.invalid"},
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/api/v1/registration-validations", json=fields, headers={"X-CSRF-Token": "wrong"}
        ).status_code
        == 403
    )


def test_json_limit_and_duplicate_keys(portal):
    client, _app = portal
    headers = {"Content-Type": "application/json"}
    assert (
        client.post(
            "/api/v1/registration-validations",
            content='{"app_id":"first","app_id":"second"}',
            headers=headers,
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/v1/registration-validations", content="x" * 32769, headers=headers
        ).status_code
        == 413
    )


def test_unconfigured_service_fails_closed(monkeypatch):
    monkeypatch.delenv("AEGIS_MODE", raising=False)
    with TestClient(create_app(Settings())) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503
        assert client.get("/api/v1/repositories").status_code == 503
        assert client.post("/auth/demo").status_code == 404
        assert client.get("/api/v1/status").json()["deployment_enabled"] is False


def test_demo_rejects_remote_hosts(settings):
    with TestClient(create_app(settings), base_url="http://public.example") as client:
        assert client.get("/").status_code == 403


def test_signout_invalidates_server_session(portal):
    client, _app = portal
    assert client.post("/auth/logout").status_code == 200
    assert client.get("/api/v1/session").status_code == 401


def test_responses_do_not_contain_credentials(portal):
    client, _app = portal
    response = client.get("/api/v1/session")
    assert "demo-not-a-github-token" not in response.text
    assert response.headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_session_idle_absolute_provider_expiry_and_oauth_single_use(monkeypatch):
    sessions = Sessions()
    monkeypatch.setattr(time, "time", lambda: 10000)
    sid = sessions.create("1", "test", "credential")
    state, verifier = sessions.start_oauth()
    assert sessions.consume_oauth(state) == verifier
    assert sessions.consume_oauth(state) is None
    state, _ = sessions.start_oauth()
    monkeypatch.setattr(time, "time", lambda: 11801)
    assert sessions.get(sid) is None
    assert sessions.consume_oauth(state) is None
    monkeypatch.setattr(time, "time", lambda: 20000)
    sid = sessions.create("1", "test", "credential", lifetime=1)
    monkeypatch.setattr(time, "time", lambda: 20002)
    assert sessions.get(sid) is None
    sid = sessions.create("1", "test", "credential")
    sessions.records[sid].created -= 28801
    assert sessions.get(sid) is None


def test_signature_hash_canonicalization_and_algorithm_rejection():
    signer = Signer(Ed25519PrivateKey.generate(), "test")
    assert digest({"b": 2, "a": 1}) == digest({"a": 1, "b": 2})
    sealed = signer.seal({"message": "hello"})
    assert signer.verify(sealed) == {"message": "hello"}
    altered = deepcopy(sealed)
    altered["payload"]["message"] = "changed"
    with pytest.raises(ValueError):
        signer.verify(altered)
    sealed["envelope"]["algorithm"] = "none"
    with pytest.raises(ValueError):
        signer.verify(sealed)
    with pytest.raises(ValueError):
        strict_json('{"x":1,"x":2}')
    with pytest.raises(ValueError):
        strict_json(json.dumps({"number": float("nan")}))
