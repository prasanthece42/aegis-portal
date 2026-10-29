from types import SimpleNamespace

import pytest

from app.errors import PortalError
from app.onboarding import onboarding_status


def services(state="preparing", deployment=None, catalog="approved"):
    calls = []
    registration = {"app_id": "orders", "requirements": [{"status": catalog}]}

    def get_registration(*_):
        calls.append("registration")
        return registration

    def latest_setup(*_):
        calls.append("setup")
        return {"state": state}

    def latest_delivery(*_):
        calls.append("delivery")
        return deployment

    return (
        SimpleNamespace(get=get_registration, backend=SimpleNamespace()),
        SimpleNamespace(latest=latest_setup),
        SimpleNamespace(latest_for_app=latest_delivery),
    ), calls


@pytest.mark.parametrize(
    "state,phase",
    [
        ("not_started", "setup_review"),
        ("preparing", "preparing"),
        ("awaiting_review", "setup_approval"),
        ("building", "building"),
        ("ready", "release_review"),
        ("needs_attention", "needs_attention"),
    ],
)
def test_journey_exposes_next_action_without_mutations(state, phase):
    svc, calls = services(state)
    result = onboarding_status(None, "orders", "reg", *svc)
    assert result["phase"] == phase
    assert calls == ["registration", "setup", "delivery"]


def test_journey_waits_for_catalog_before_reading_or_preparing_app():
    svc, calls = services(catalog="pending_review")
    assert onboarding_status(None, "orders", "reg", *svc)["phase"] == "owner_review"
    assert calls == ["registration"]
    with pytest.raises(PortalError):
        onboarding_status(None, "different", "reg", *svc)


@pytest.mark.parametrize(
    "deployment,phase",
    [
        ({"status": "healthy", "security_verified": True}, "healthy"),
        ({"status": "healthy", "security_verified": False}, "deploying"),
        ({"status": "checking"}, "deploying"),
        ({"status": "reconciling", "health_check_failed": True}, "needs_attention"),
        ({"status": "superseded"}, "release_review"),
    ],
)
def test_journey_requires_measured_security_and_health(deployment, phase):
    svc, _ = services("ready", deployment)
    assert onboarding_status(None, "orders", None, *svc)["phase"] == phase


@pytest.mark.parametrize(
    "number,label",
    [
        (1, "Build #1"),
        (27, "Build #27"),
        (None, "Validated build"),
        ("malformed", "Validated build"),
        (True, "Validated build"),
    ],
)
def test_release_labels_use_real_provider_numbers_without_guessing(number, label):
    from app.delivery_github import DeliveryGitHub

    backend = DeliveryGitHub()
    entry = SimpleNamespace(source=SimpleNamespace(owner="demo", name="orders"))
    backend.delivery_authorize = lambda *_: (entry, None, None)
    backend.delivery_source_token = lambda *_: "read-token"
    backend.api = lambda *_a, **_k: SimpleNamespace(
        json=lambda: [
            {"id": 700, "tag_name": "release-123-1", "published_at": "2026-10-29T12:00:00Z"}
        ]
    )
    backend.admitted_release = lambda *_: (
        SimpleNamespace(
            image="image@sha256:abc", source_commit="a" * 40, workflow_run_id="123", run_attempt=2
        ),
        None,
        {"aegis_build_number": number},
    )
    result = backend.delivery_releases(None, "orders", "dev", 1)["items"][0]
    assert result["build_label"] == label
    assert result["release_id"] == "700" and result["run_attempt"] == 2
    assert result["tag"] == "release-123-1"


def test_onboarding_route_requires_session_and_matching_owned_registration(confirmed):
    client, _app, fields, key = confirmed
    response = client.post("/api/v1/registrations", json=fields, headers={"Idempotency-Key": key})
    assert response.status_code == 201
    rid = response.json()["registration_id"]
    path = f"/api/v1/applications/orders-api/onboarding?registration_id={rid}"
    assert client.get(path).json()["phase"] == "owner_review"
    assert client.get(path.replace("orders-api", "another-app")).status_code == 404
    assert (
        client.get(
            "/api/v1/applications/orders-api/onboarding?registration_id=malformed"
        ).status_code
        == 404
    )
    assert client.post("/auth/logout").status_code == 200
    assert client.get(path).status_code == 401


def test_pending_journey_surfaces_trusted_worker_blocker_before_catalog_merge():
    svc, calls = services(catalog="pending_review")
    registration = svc[0].get()
    registration["automatic_setup"] = True
    svc[0].backend.registration_preparation_status = lambda _: "error"
    calls.clear()
    result = onboarding_status(None, "orders", "reg", *svc)
    assert result["phase"] == "needs_attention"
    assert "reconcile" in result["message"]
    assert "setup" not in calls and "delivery" not in calls
