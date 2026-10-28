import json
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from aegis_platform.canonical import canonical
from aegis_platform.observability_policy import password_fingerprint, query_password

from app.contracts import RegistrationFields
from app.demo import demo_config
from app.errors import PortalError
from app.monitoring import MonitoringService, scoped_trace
from app.registration import RegistrationService


@pytest.fixture
def monitoring_gateway(fields):
    config = demo_config()
    config.versions.helper_commit = config.versions.workflow_commit
    config.gitops_repository = "demo/aegis-gitops"
    config.gitops_installation_id = "905"
    config.delivery_workflow_commit = "d" * 40
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
    seed = "unit-test-" * 4
    policy = json.loads(Path("tests/fixtures/observability-policy.json").read_text())
    policy["query_password_sha256"] = password_fingerprint(query_password(seed, config.cluster_uid))
    documents = {
        "policies/observability.json": policy,
        "catalog/apps/orders-api.json": entry,
        "catalog/clusters/kind-local.json": {
            "schema_version": 1,
            "cluster_id": "kind-local",
            "cluster_uid": config.cluster_uid,
            "gitops_repository_id": "904",
            "profile_id": "small",
        },
        "policies/catalog.json": {
            "schema_version": 1,
            "resource_profile_ids": ["small"],
            "runtime_profile_ids": ["python312-web"],
            "environment_branches": {"dev": "main", "staging": "staging", "prod": "prod"},
            "production_human_review_required": True,
            "protected_sync_mode": "operator",
            "max_applications": 100,
        },
        "policies/portal-system.json": {
            "schema_version": 1,
            "operator_user_ids": ["1"],
            "source_repository_id": "101",
            "signing_public_key_base64": "a" * 44,
            "configuration": config.model_dump(),
        },
    }

    class Backend:
        def __init__(self):
            self.config = config
            self.client_secret = seed
            self.user = {"id": 1, "type": "User"}

        def catalog_snapshot(self):
            return "a" * 40, None

        def platform_token(self):
            return "public-policy-reader"

        def file(self, repo, path, revision, token, **kwargs):
            assert revision == "a" * 40
            return canonical(documents[path]) if path in documents else None

        def api(self, method, path, token):
            assert method == "GET" and path == "/user"
            return SimpleNamespace(json=lambda: self.user)

        def owner_context(self, session):
            if session.user_id != "1":
                raise PortalError(403, "FORBIDDEN", "Owner visibility required")
            return "a" * 40, None, None

        def close(self):
            pass

    requests = []

    def transport(request):
        requests.append(request)
        assert request.url.host.endswith(".aegis-observability.svc.cluster.local")
        assert request.headers["Authorization"].startswith("Basic ")
        assert seed not in request.headers["Authorization"]
        if request.url.path.endswith("query_range"):
            return httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "result": [{"values": [[time.time() - 30, "1.25"], [time.time(), "NaN"]]}]
                    },
                },
            )
        return httpx.Response(
            200,
            json={
                "status": "success",
                "data": {"result": [{"value": [time.time(), str(time.time() - 200)]}]},
            },
        )

    backend = Backend()
    client = httpx.Client(transport=httpx.MockTransport(transport))
    service = MonitoringService(backend, client)
    session = SimpleNamespace(user_id="1", user_token="unit-user")
    yield service, session, documents, requests, backend
    service.close()


def test_metric_queries_are_scoped_and_nan_is_not_reported_as_zero(monitoring_gateway):
    service, user, _, requests, _ = monitoring_gateway
    context = service.app_context(user, "orders-api", "dev")
    result = service.query(context, "metrics", "15m")
    assert result["application_signal"] == "stale"
    assert all(len(series["points"]) == 1 for series in result["series"])
    assert all(series["points"][0][1] == 1.25 for series in result["series"])
    assert all("aegis-orders-api-dev" in r.url.params["query"] for r in requests)
    assert all("demo-cluster-not-enrolled" in r.url.params["query"] for r in requests)


def test_revoked_visibility_denies_telemetry_before_backend_read(monitoring_gateway):
    service, user, docs, requests, _ = monitoring_gateway
    docs["catalog/apps/orders-api.json"]["access"] = {
        "owner_user_ids": ["2"],
        "viewer_user_ids": [],
        "deployer_user_ids_by_environment": {"dev": ["2"]},
    }
    with pytest.raises(PortalError) as exc:
        service.app_context(user, "orders-api", "dev")
    assert exc.value.status == 403 and not requests


def test_dev_deployer_does_not_implicitly_gain_prod_logs(monitoring_gateway):
    service, user, docs, requests, _ = monitoring_gateway
    entry = docs["catalog/apps/orders-api.json"]
    entry["access"] = {
        "owner_user_ids": ["2"],
        "viewer_user_ids": [],
        "deployer_user_ids_by_environment": {"dev": ["1"], "prod": ["2"]},
    }
    target = deepcopy(entry["environments"]["dev"])
    target.update(
        namespace="aegis-orders-api-prod",
        argo_application="orders-api-prod",
        argo_project="orders-api-prod",
        gitops_branch="prod",
        values_path="applications/orders-api/environments/prod/values.yaml",
    )
    entry["environments"]["prod"] = target
    assert service.app_context(user, "orders-api", "dev").namespace == "aegis-orders-api-dev"
    with pytest.raises(PortalError):
        service.app_context(user, "orders-api", "prod")
    assert not requests


def test_wrong_public_policy_or_read_capability_fails_closed(monitoring_gateway):
    service, user, docs, requests, _ = monitoring_gateway
    docs["policies/observability.json"]["query_password_sha256"] = "sha256:" + "b" * 64
    with pytest.raises(PortalError) as exc:
        service.app_context(user, "orders-api", "dev")
    assert exc.value.code == "MONITORING_POLICY_INVALID" and not requests


def test_platform_portal_logs_require_current_operator_grant(monitoring_gateway):
    service, user, docs, requests, _ = monitoring_gateway
    assert service.platform_context(user, "portal").namespace == "aegis-portal-system"
    docs["policies/portal-system.json"]["operator_user_ids"] = ["2"]
    with pytest.raises(PortalError):
        service.platform_context(user, "portal")
    assert not requests


def trace_fixture(namespace="aegis-orders-api-dev", cluster="demo-cluster-not-enrolled"):
    return {
        "resource": {
            "attributes": [
                {"key": "k8s.namespace.name", "value": {"stringValue": namespace}},
                {"key": "aegis.cluster.uid", "value": {"stringValue": cluster}},
                {"key": "service.name", "value": {"stringValue": "orders"}},
            ]
        },
        "scopeSpans": [
            {
                "spans": [
                    {
                        "traceId": "a" * 32,
                        "spanId": "b" * 16,
                        "name": "GET /orders",
                        "startTimeUnixNano": "1790000000000000000",
                        "endTimeUnixNano": "1790000000010000000",
                    }
                ]
            }
        ],
    }


def test_trace_lookup_excludes_other_namespaces_and_clusters():
    allowed = trace_fixture()
    forbidden = trace_fixture("aegis-private-prod")
    forbidden["scopeSpans"][0]["spans"][0]["name"] = "private-data"
    other = trace_fixture(cluster="another-cluster")
    result = scoped_trace(
        {"resourceSpans": [forbidden, allowed, other]},
        "aegis-orders-api-dev",
        "a" * 32,
        "demo-cluster-not-enrolled",
    )
    assert len(result["spans"]) == 1 and "private-data" not in json.dumps(result)
    with pytest.raises(PortalError) as exc:
        scoped_trace(
            {"resourceSpans": [forbidden, other]},
            "aegis-orders-api-dev",
            "a" * 32,
            "demo-cluster-not-enrolled",
        )
    assert exc.value.status == 404


def test_wrong_scope_log_stream_never_reaches_browser(monitoring_gateway):
    service, user, _, _, _ = monitoring_gateway
    context = service.app_context(user, "orders-api", "dev")
    service.client.close()
    service.client = httpx.Client(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "status": "success",
                    "data": {
                        "result": [
                            {
                                "stream": {
                                    "k8s_namespace_name": "aegis-private-prod",
                                    "aegis_cluster_uid": context.policy.cluster_uid,
                                },
                                "values": [["1790000000000000000", "private-data"]],
                            }
                        ]
                    },
                },
            )
        )
    )
    with pytest.raises(PortalError) as exc:
        service.logs(context, "15m")
    assert exc.value.code == "TELEMETRY_SCOPE_INVALID" and "private-data" not in exc.value.message


def test_telemetry_redirect_does_not_forward_read_capability(monitoring_gateway):
    service, user, _, _, _ = monitoring_gateway
    context = service.app_context(user, "orders-api", "dev")
    seen = []
    service.client.close()

    def redirect(request):
        seen.append(request)
        return httpx.Response(302, headers={"Location": "http://outside.invalid/"})

    service.client = httpx.Client(transport=httpx.MockTransport(redirect))
    with pytest.raises(PortalError):
        service.logs(context, "15m")
    assert len(seen) == 1 and seen[0].url.host.startswith("loki.")


def test_invalid_query_language_or_window_cannot_be_supplied(monitoring_gateway):
    service, user, _, requests, _ = monitoring_gateway
    context = service.app_context(user, "orders-api", "dev")
    for signal, window in [("query", "15m"), ("metrics", "90d")]:
        with pytest.raises(PortalError):
            service.query(context, signal, window)
    assert not requests


def test_observability_routes_require_authentication_and_are_read_only(settings, portal):
    from fastapi.testclient import TestClient

    from app.main import create_app

    path = "/api/v1/applications/orders-api/observability/logs"
    with TestClient(create_app(settings)) as client:
        assert client.get(path).status_code == 401
    client, _ = portal
    assert client.post(path, json={}).status_code == 405
    assert client.get(path + "?window=90d").status_code == 422
    assert client.get(path).status_code == 503


@pytest.mark.parametrize("signal", ["metrics", "logs", "alerts", "traces"])
@pytest.mark.parametrize("payload", [[], {"status": "success", "data": [], "traces": [None]}])
def test_malformed_provider_data_fails_with_safe_unavailable_error(
    monitoring_gateway, signal, payload
):
    service, user, _, _, _ = monitoring_gateway
    context = service.app_context(user, "orders-api", "dev")
    service.client.close()
    service.client = httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))
    )
    with pytest.raises(PortalError) as exc:
        service.query(context, signal, "15m")
    assert exc.value.status == 503
    assert exc.value.code in {"TELEMETRY_INVALID", "TELEMETRY_UNAVAILABLE"}


def test_malformed_trace_detail_does_not_become_unhandled_failure(monitoring_gateway):
    service, user, _, _, _ = monitoring_gateway
    context = service.app_context(user, "orders-api", "dev")
    service.client.close()
    service.client = httpx.Client(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"resourceSpans": [None]}))
    )
    with pytest.raises(PortalError) as exc:
        service.trace(context, "a" * 32)
    assert exc.value.status == 503 and exc.value.code == "TELEMETRY_INVALID"


def test_chart_queries_run_together_instead_of_exceeding_gateway_budget(monitoring_gateway):
    from threading import Barrier

    service, user, _, _, _ = monitoring_gateway
    context = service.app_context(user, "orders-api", "dev")
    barrier = Barrier(5, timeout=2)
    service.client.close()

    def respond(request):
        barrier.wait()
        now = time.time()
        result = (
            [{"values": [[now, "1"]]}]
            if request.url.path.endswith("query_range")
            else [{"value": [now, str(now)]}]
        )
        return httpx.Response(200, json={"status": "success", "data": {"result": result}})

    service.client = httpx.Client(transport=httpx.MockTransport(respond))
    result = service.query(context, "metrics", "15m")
    assert result["application_signal"] == "fresh"
    assert len(result["series"]) == 4
