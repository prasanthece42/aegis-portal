from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture
def settings(monkeypatch, tmp_path):
    monkeypatch.setenv("AEGIS_MODE", "demo")
    monkeypatch.setenv("AEGIS_DEMO_DATA", str(tmp_path / "demo.json"))
    return Settings()


@pytest.fixture
def portal(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        assert client.post("/auth/demo", headers={"Origin": "http://testserver"}).status_code == 200
        session = client.get("/api/v1/session").json()
        client.headers.update(
            {"Origin": "http://testserver", "X-CSRF-Token": session["csrf_token"]}
        )
        yield client, app


@pytest.fixture
def fields():
    return {
        "repository_id": "101",
        "app_id": "orders-api",
        "display_name": "Orders API",
        "owner_user_ids": ["1"],
        "runtime": {
            "profile_id": "python312-web",
            "container_port": 8000,
            "health_path": "/health",
            "resource_profile_id": "small",
        },
    }


@pytest.fixture
def confirmed(portal, fields):
    client, app = portal
    preview = client.post("/api/v1/registration-validations", json=fields)
    assert preview.status_code == 200, preview.text
    return client, app, {**fields, "review_token": preview.json()["review_token"]}, str(uuid4())
