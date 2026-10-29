import json
from copy import deepcopy
from uuid import uuid4

from app.contracts import RegistrationFields
from tests.test_uploads import archive, inspect, review_and_create


def definition():
    return {
        "schema_version": 1,
        "profile_id": "python312-multiservice",
        "primary_service": "catalog",
        "services": {
            "catalog": {
                "env": {"CACHE_TTL_SECONDS": "30"},
                "secret_env": {"DATABASE_URL": "database-url"},
            },
            "orders": {"service_env": {"CATALOG_URL": "catalog"}, "replicas": 2},
        },
        "dependencies": "postgres17-redis7-nginx",
    }


def uploaded_stack(client):
    upload = inspect(
        client,
        {
            "aegis-stack.json": json.dumps(definition()),
            "Dockerfile": "FROM python:3.12",
            "app/main.py": "from fastapi import FastAPI",
            "requirements.txt": "",
            "requirements-prod.txt": "",
            "tests/test_app.py": "def test_contract(): pass",
        },
    )
    assert upload["detection"]["runtime"] == "python312-multiservice"
    record = review_and_create(client, upload)
    return record, {
        "repository_id": record["repository"]["repository_id"],
        "app_id": "commerce-demo",
        "display_name": "Commerce demo",
        "owner_user_ids": ["1"],
        "runtime": {
            "profile_id": "python312-multiservice",
            "container_port": 8080,
            "health_path": "/health",
            "resource_profile_id": "small",
            "stack": record["detection"]["stack"],
            "credentials_secret": "commerce-demo-runtime",
            "environment": {"catalog": {"CACHE_TTL_SECONDS": "45"}},
        },
    }


def test_upload_to_registration_preserves_stack_and_proposes_correct_workflows(portal):
    client, app = portal
    assert "python312-multiservice" in client.get("/api/v1/session").json()["runtime_profiles"]
    record, fields = uploaded_stack(client)
    loaded = client.get(f"/api/v1/repositories/{fields['repository_id']}/stack")
    assert loaded.status_code == 200
    assert loaded.json()["stack"] == fields["runtime"]["stack"]
    prepared = client.post(f"/api/v1/uploads/{record['upload_id']}/preparation", json=fields)
    assert prepared.status_code == 200, prepared.text
    proposals = prepared.json()["proposed_files"]
    assert "python-stack-ci.yml@" in proposals[0]["content"]
    assert "python-stack-release.yml@" in proposals[1]["content"]
    assert "container-port:" not in proposals[0]["content"]
    preview = client.post("/api/v1/registration-validations", json=fields)
    assert preview.status_code == 200, preview.text
    result = client.post(
        "/api/v1/registrations",
        json={**fields, "review_token": preview.json()["review_token"]},
        headers={"Idempotency-Key": str(uuid4())},
    )
    assert result.status_code == 201, result.text
    assert result.json()["fields"]["runtime"]["environment"] == fields["runtime"]["environment"]
    source = app.state.service.backend.source(
        app.state.sessions.get(client.cookies.get("aegis_demo_session")), fields["repository_id"]
    )
    entry = app.state.service.entry(RegistrationFields.model_validate(fields), source)
    assert entry["versions"] == app.state.service.config.multiservice_versions.model_dump()


def test_source_topology_change_requires_a_new_review(portal):
    client, _ = portal
    _, fields = uploaded_stack(client)
    fields["runtime"]["stack"]["services"]["orders"]["replicas"] = 1
    result = client.post("/api/v1/registration-validations", json=fields)
    assert result.status_code == 409
    assert result.json()["error"]["code"] == "STACK_SOURCE_CHANGED"


def test_secret_values_cross_app_references_and_undeclared_environment_are_rejected(portal):
    client, _ = portal
    _, fields = uploaded_stack(client)
    for mutation in ("literal", "cross_app", "undeclared"):
        changed = deepcopy(fields)
        if mutation == "literal":
            changed["runtime"]["environment"]["catalog"]["DATABASE_URL"] = "must-not-be-persisted"
        elif mutation == "cross_app":
            changed["runtime"]["credentials_secret"] = "another-app-runtime"
        else:
            changed["runtime"]["environment"]["unknown"] = {"CACHE_TTL_SECONDS": "20"}
        result = client.post("/api/v1/registration-validations", json=changed)
        assert result.status_code == 422, result.text


def test_unactivated_stack_profile_fails_closed_without_affecting_single_service(portal):
    client, app = portal
    _, fields = uploaded_stack(client)
    app.state.service.config.multiservice_versions = None
    result = client.post("/api/v1/registration-validations", json=fields)
    assert result.status_code == 503
    assert result.json()["error"]["code"] == "STACK_SETUP_REQUIRED"
    assert client.get("/api/v1/session").json()["runtime_profiles"] == ["python312-web"]


def test_bad_manifest_does_not_fall_back_to_single_service(portal):
    client, _ = portal
    response = client.post(
        "/api/v1/uploads",
        content=archive({"aegis-stack.json": "{}", "app/main.py": "pass", "requirements.txt": ""}),
        headers={"Content-Type": "application/zip"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "STACK_INVALID"


def test_stack_registration_does_not_authorize_single_service_preparation(portal):
    client, _ = portal
    _, fields = uploaded_stack(client)
    result = client.post("/api/v1/registration-validations?guided_setup=true", json=fields)
    assert result.status_code == 409
    assert result.json()["error"]["code"] == "STACK_OPERATOR_SETUP_REQUIRED"


def test_disabled_stack_configuration_preserves_existing_policy_serialization(portal):
    _, app = portal
    config = app.state.service.config
    config.multiservice_versions = None
    assert "multiservice_versions" not in config.model_dump()
