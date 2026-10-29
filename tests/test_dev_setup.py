import base64
import hashlib
import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import httpx
import pytest
from aegis_platform.bootstrap import chart_identity
from aegis_platform.canonical import canonical, digest
from aegis_platform.catalog import Catalog, CatalogPolicy, Cluster
from aegis_platform.contracts import CatalogEntry
from aegis_platform.delivery import DeliveryPolicy
from aegis_platform.request import Issuer, RequestTrust
from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from app.contracts import RegistrationFields
from app.demo import demo_config
from app.errors import PortalError
from app.github import GitHub
from app.main import create_app
from app.registration import RegistrationService
from app.setup_contracts import CHARTS, SetupIntent, SetupPolicy, make_plan, verify_setup
from app.setup_worker import Pending, SetupWorker


def sha(value):
    return hashlib.sha1(value if isinstance(value, bytes) else str(value).encode()).hexdigest()


@pytest.fixture
def setup_case(fields):
    config = demo_config()
    config.gitops_repository = "demo/aegis-gitops"
    config.gitops_installation_id = "905"
    config.delivery_workflow_commit = "e" * 40
    config.versions.helper_commit = config.versions.workflow_commit
    config.versions.chart_sha256 = chart_identity(CHARTS / "1.0.0")["sha256"]
    entry = CatalogEntry.model_validate(
        RegistrationService(config, None, None).entry(
            RegistrationFields.model_validate(fields),
            {
                "repository_id": "101",
                "installation_id": "903",
                "owner": "demo",
                "name": "orders-api",
                "default_branch": "main",
            },
        )
    )
    bootstrap = json.loads(Path("tests/fixtures/setup-bootstrap.json").read_text())
    catalog_policy = CatalogPolicy(
        schema_version=1,
        resource_profile_ids=["small"],
        runtime_profile_ids=["python312-web"],
        environment_branches={"dev": "main", "staging": "staging", "prod": "prod"},
        production_human_review_required=True,
        protected_sync_mode="operator",
        max_applications=100,
    )
    cluster = Cluster(
        cluster_id=config.cluster_id,
        cluster_uid=config.cluster_uid,
        gitops_repository_id="904",
        profile_id="kind-local-small",
    )
    catalog = Catalog([entry], [cluster], catalog_policy)
    delivery = DeliveryPolicy(
        platform_repository="demo/aegis-platform",
        platform_repository_id="900",
        gitops_repository="demo/aegis-gitops",
        gitops_repository_id="904",
        bootstrap_policy_hash=digest(bootstrap),
        workflow_bot_user_ids=["41898282"],
        observer_user_ids=["1"],
        production_reviewer_user_ids=["1"],
    )
    policy = SetupPolicy(
        enabled=True,
        platform_repository_id="900",
        gitops_repository_id="904",
        portal_app_id="99",
        cluster_id=config.cluster_id,
        cluster_uid=config.cluster_uid,
        source_owner="demo",
        operator_user_ids=["1"],
    )
    plan = make_plan(entry, catalog, delivery, bootstrap, policy, "d" * 40)
    return SimpleNamespace(
        config=config,
        entry=entry,
        bootstrap=bootstrap,
        catalog=catalog,
        catalog_policy=catalog_policy,
        cluster=cluster,
        delivery=delivery,
        policy=policy,
        plan=plan,
    )


class GitHubTransport:
    def __init__(self, case):
        self.case = case
        self.calls = []
        self.files = {}
        self.refs = {}
        self.commits = {}
        self.trees = {}
        self.fail_after_ref = False
        self.source_commit = "d" * 40
        self.identity = "1"
        self.prs = {}
        self.reviews = {}
        self.source_push = True
        self.rev = "a" * 40
        for path, data in {
            "policies/delivery.json": case.delivery.model_dump(),
            "policies/bootstrap.json": case.bootstrap,
            "policies/catalog.json": case.catalog_policy.model_dump(),
            "policies/portal-setup.json": case.policy.model_dump(),
            "catalog/clusters/kind-local.json": case.cluster.model_dump(),
            "catalog/apps/orders-api.json": case.entry.model_dump(),
        }.items():
            self.files[("demo/aegis-platform", path)] = canonical(data)
        for path in ("Dockerfile", "requirements.txt", "requirements-prod.txt"):
            self.files[("demo/orders-api", path)] = b"reviewed application input\n"

    def api(self, method, path, token, **kwargs):
        self.calls.append((method, path, kwargs))
        body = kwargs.get("json")
        if path == "/repos/demo/aegis-platform":
            return httpx.Response(200, json={"id": 900})
        if path == "/user":
            return httpx.Response(
                200, json={"id": int(self.identity), "login": "demo", "type": "User"}
            )
        if path == "/user/installations":
            return httpx.Response(200, json={"installations": [{"id": 903}]})
        if path == "/user/installations/903/repositories":
            return httpx.Response(
                200,
                json={
                    "repositories": [
                        {
                            "id": 101,
                            "full_name": "demo/orders-api",
                            "default_branch": "main",
                            "private": False,
                            "permissions": {"push": True},
                        }
                    ]
                },
            )
        for repo, pr in self.prs.items():
            root = "/repos/" + repo
            if path == root:
                return httpx.Response(
                    200,
                    json={
                        "id": pr["base"]["repo"]["id"],
                        "permissions": {
                            "push": self.source_push if repo.endswith("orders-api") else True
                        },
                    },
                )
            if path == root + "/pulls":
                return httpx.Response(200, json=[pr])
            if path == root + "/pulls/1":
                return httpx.Response(200, json=pr)
            if path == root + "/pulls/1/files":
                return httpx.Response(
                    200,
                    json=[
                        {"filename": p, "status": "added"} for p in self.commits[pr["head"]["sha"]]
                    ],
                )
            if path == root + "/pulls/1/reviews":
                if method == "POST":
                    self.reviews.setdefault(repo, []).append(
                        {
                            "user": {"id": 1, "type": "User"},
                            "state": "APPROVED",
                            "commit_id": body["commit_id"],
                        }
                    )
                return httpx.Response(200, json=self.reviews.get(repo, []))
        if path.endswith("/commits/main"):
            value = self.source_commit if "/orders-api/" in path else self.rev
            return httpx.Response(200, json={"sha": value})
        if "/contents/" in path:
            repo, filename = path.removeprefix("/repos/").split("/contents/", 1)
            ref = kwargs.get("params", {}).get("ref")
            data = (
                self.commits.get(ref, {}).get(filename)
                if ref in self.commits
                else self.files.get((repo, filename))
            )
            if data is None:
                return httpx.Response(404)
            return httpx.Response(
                200,
                json={
                    "type": "file",
                    "encoding": "base64",
                    "size": len(data),
                    "content": base64.b64encode(data).decode(),
                },
            )
        if path.endswith("/git/trees") and method == "POST":
            value = {r["path"]: r["content"].encode() for r in body["tree"]}
            key = sha(canonical(value.keys().__str__()) + b"".join(value.values()))
            self.trees[key] = value
            return httpx.Response(201, json={"sha": key})
        if path.endswith("/git/commits") and method == "POST":
            key = sha(body["tree"])
            self.commits[key] = self.trees[body["tree"]]
            return httpx.Response(201, json={"sha": key})
        if "/git/ref/heads/" in path:
            branch = path.split("/git/ref/heads/", 1)[1]
            if branch in self.refs:
                return httpx.Response(200, json={"object": {"sha": self.refs[branch]}})
            return httpx.Response(404)
        if "/git/refs/heads/" in path and method == "PATCH":
            assert body["force"] is False
            branch = path.split("/git/refs/heads/", 1)[1]
            self.refs[branch] = body["sha"]
            return httpx.Response(200, json={})
        if path.endswith("/git/refs") and method == "POST":
            branch = body["ref"].removeprefix("refs/heads/")
            if branch in self.refs:
                return httpx.Response(422)
            self.refs[branch] = body["sha"]
            if self.fail_after_ref:
                self.fail_after_ref = False
                raise PortalError(
                    503, "GITHUB_UNAVAILABLE", "Simulated lost confirmation response", True
                )
            return httpx.Response(201, json={})
        if (
            "git/matching-refs/heads/portal-setups/" in path
            or "git/matching-refs/heads/portal-registrations/" in path
        ):
            return httpx.Response(
                200,
                json=[
                    {"ref": "refs/heads/" + p, "object": {"sha": v}}
                    for p, v in self.refs.items()
                    if p.startswith(path.split("/git/matching-refs/heads/", 1)[1])
                ],
            )
        if path.endswith("/actions/runs"):
            return httpx.Response(200, json={"workflow_runs": []})
        if path.endswith("/pulls") or path.endswith("/statuses") or path.endswith("/releases"):
            return httpx.Response(200, json=[])
        raise AssertionError((method, path, kwargs))


@pytest.fixture
def setup_portal(settings, setup_case):
    transport = GitHubTransport(setup_case)
    backend = GitHub.__new__(GitHub)
    backend.config = setup_case.config
    backend.api = transport.api
    backend.installation_token = lambda *_args, **_kwargs: "explicit-test-token"
    backend.close = lambda: None
    app = create_app(settings, backend=backend)
    sid = app.state.sessions.create("1", "demo", "test-user-token")
    csrf = app.state.sessions.get(sid).csrf
    with TestClient(app) as client:
        client.cookies.set(settings.cookie_name, sid)
        client.headers.update({"Origin": "http://testserver", "X-CSRF-Token": csrf})
        yield client, app, transport


def test_real_adapter_routes_preview_confirm_and_lost_response_recovery(setup_portal):
    client, app, transport = setup_portal
    path = "/api/v1/applications/orders-api"
    preview = client.post(path + "/dev-setup-validations")
    assert preview.status_code == 200, preview.text
    assert preview.json()["blockers"] == []
    assert len(preview.json()["workflow_files"]) == 2
    assert (
        "Deployment still needs" not in preview.json()["notice"]
    )  # Dedicated setup notice, not deployment authority.
    key = str(uuid4())
    body = {"review_token": preview.json()["review_token"]}
    transport.fail_after_ref = True
    failed = client.post(path + "/dev-setups", json=body, headers={"Idempotency-Key": key})
    assert failed.status_code == 503
    recovered = client.post(path + "/dev-setups", json=body, headers={"Idempotency-Key": key})
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["state"] == "queued"
    rid = recovered.json()["setup_id"]
    assert client.get(path + "/dev-setup").json()["setup_id"] == rid
    assert len(transport.refs) == 1
    assert (
        sum(
            method == "POST" and endpoint.endswith("/git/refs")
            for method, endpoint, _ in transport.calls
        )
        == 1
    )
    assert not any(
        method != "GET" and "/repos/demo/orders-api/" in endpoint
        for method, endpoint, _ in transport.calls
    )
    assert (
        app.state.setup.verified(app.state.setup.backend.journal(rid)[1], rid).plan.app_id
        == "orders-api"
    )


def test_setup_preview_rejects_replaced_workflows_and_changed_source(setup_portal):
    client, _app, transport = setup_portal
    path = "/api/v1/applications/orders-api"
    original = client.post(path + "/dev-setup-validations").json()
    transport.files[("demo/orders-api", ".github/workflows/ci.yml")] = b"custom: pipeline"
    changed = client.post(path + "/dev-setup-validations").json()
    assert any("ci.yml" in message for message in changed["blockers"])
    response = client.post(
        path + "/dev-setups",
        json={"review_token": original["review_token"]},
        headers={"Idempotency-Key": str(uuid4())},
    )
    assert response.status_code == 409
    assert not transport.refs


def test_setup_authorization_and_csrf(setup_portal):
    client, _app, transport = setup_portal
    path = "/api/v1/applications/orders-api/dev-setup-validations"
    assert client.post(path, headers={"X-CSRF-Token": "invalid"}).status_code == 403
    transport.identity = "2"
    assert client.post(path).status_code == 401
    assert not transport.refs


def trust_for(signer, case):
    public = signer.key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return RequestTrust(
        platform_repository_id="900",
        issuers=[
            Issuer(
                issuer_id=case.config.issuer_id,
                key_id=case.config.signing_key_id,
                public_key_base64=base64.b64encode(public).decode(),
                bot_user_id="902",
                active=True,
            )
        ],
    )


def signed_intent(app, case, *, created=None):
    intent = SetupIntent(
        setup_id="setup-" + "a" * 64,
        issuer_id=case.config.issuer_id,
        platform_repository_id="900",
        requester_user_id="1",
        created_at=(created or datetime.now(UTC)).isoformat(),
        idempotency_hash=digest("key"),
        plan=case.plan,
    )
    return app.state.service.signer.seal(intent.model_dump())


@pytest.mark.parametrize("change", ["payload", "issuer", "revoked", "policy", "expired"])
def test_worker_rejects_tampered_revoked_wrong_policy_and_expired_requests(
    setup_portal, setup_case, change
):
    _client, app, _transport = setup_portal
    record = signed_intent(app, setup_case)
    trust = trust_for(app.state.service.signer, setup_case)
    policy = setup_case.policy.model_copy(deep=True)
    if change == "payload":
        record["payload"]["plan"]["namespace"] = "other-app"
    elif change == "issuer":
        trust.issuers[0].issuer_id = "unknown"
    elif change == "revoked":
        trust.issuers[0].active = False
    elif change == "policy":
        policy.source_owner = "other-owner"
    else:
        record = signed_intent(app, setup_case, created=datetime.now(UTC) - timedelta(days=2))
    with pytest.raises(ValueError):
        verify_setup(record, trust, policy)


def test_exact_plan_is_dev_only_and_does_not_include_release_values(setup_case):
    plan = setup_case.plan
    assert plan.namespace == "aegis-orders-api-dev"
    assert all("@" + "a" * 40 in content for content in plan.workflow_files.values())
    assert not any("environments/dev/values" in path for path in plan.target_files)
    assert not any("applications/orders-api/releases/" in path for path in plan.target_files)
    assert any("argocd/applications/" in path for path in plan.target_files)
    wrong = setup_case.policy.model_copy(update={"cluster_uid": "wrong-cluster"})
    with pytest.raises(ValueError):
        make_plan(
            setup_case.entry,
            setup_case.catalog,
            setup_case.delivery,
            setup_case.bootstrap,
            wrong,
            "d" * 40,
        )


class Repo:
    """Git provider state; the operator writes bytes, the App authors review PRs."""

    def __init__(self, name, repo_id, initial=None, head="d" * 40):
        self.repository, self.repo_id = name, repo_id
        self.head = head
        self.snapshots = {head: dict(initial or {})}
        self.trees = {head: dict(initial or {})}
        self.refs = {}
        self.pr = None
        self.reviews = []
        self.writes = []
        self.ci_status = "in_progress"
        self.ci_conclusion = None
        self.fail_after_ref = False

    def file(self, path, ref):
        value = self.snapshots.get(ref, {}).get(path)
        if value is None:
            raise ValueError("GitHub metadata unavailable HTTP 404")
        return value

    def pages(self, path, **params):
        if path == "pulls":
            return [deepcopy(self.pr)] if self.pr else []
        if path.endswith("/reviews"):
            return deepcopy(self.reviews)
        if path.endswith("/files"):
            old = self.snapshots[self.pr["base"]["sha"]]
            new = self.snapshots[self.pr["head"]["sha"]]
            return [
                {"filename": p, "status": "modified" if p in old else "added"}
                for p in new
                if old.get(p) != new[p]
            ]
        raise AssertionError((path, params))

    def repo(self, method, path, payload=None):
        if method != "GET":
            self.writes.append((method, path, deepcopy(payload)))
        if path == "git/ref/heads/main":
            return {"object": {"sha": self.head}}
        if path.startswith("git/matching-refs/heads/"):
            branch = path.removeprefix("git/matching-refs/heads/")
            return (
                [{"ref": "refs/heads/" + branch, "object": {"sha": self.refs[branch]}}]
                if branch in self.refs
                else []
            )
        if path.startswith("git/commits/"):
            return {"tree": {"sha": path.rsplit("/", 1)[1]}}
        if path == "git/trees":
            files = dict(self.trees[payload["base_tree"]])
            files.update({f["path"]: f["content"].encode() for f in payload["tree"]})
            key = sha(canonical(payload))
            self.trees[key] = files
            return {"sha": key}
        if path == "git/commits":
            key = sha(canonical(payload))
            self.snapshots[key] = self.trees[payload["tree"]]
            self.trees[key] = self.snapshots[key]
            return {"sha": key}
        if path == "git/refs":
            branch = payload["ref"].removeprefix("refs/heads/")
            assert branch not in self.refs
            self.refs[branch] = payload["sha"]
            if self.fail_after_ref:
                self.fail_after_ref = False
                raise ValueError("GitHub provider failure HTTP 503")
            return {}
        if path.startswith("compare/"):
            base, head = path.removeprefix("compare/").split("...")
            return {
                "files": [
                    {"filename": p}
                    for p, v in self.snapshots[head].items()
                    if self.snapshots[base].get(p) != v
                ]
            }
        if path.startswith("actions/runs?"):
            return {
                "workflow_runs": [
                    {
                        "path": ".github/workflows/ci.yml",
                        "head_sha": self.pr["head"]["sha"],
                        "status": self.ci_status,
                        "conclusion": self.ci_conclusion,
                    }
                ]
            }
        if path.startswith("pulls/"):
            if method == "PUT":
                assert payload["sha"] == self.pr["head"]["sha"]
                self.pr["state"], self.pr["merged_at"] = "closed", datetime.now(UTC).isoformat()
                self.head = self.pr["head"]["sha"]
                return {"merged": True, "sha": self.head}
            return deepcopy(self.pr)
        if path == "releases?per_page=5":
            return []
        if path.startswith("statuses/"):
            return {}
        raise AssertionError((method, path, payload))

    def bot(self):
        def create(method, path, payload):
            assert (method, path) == ("POST", "pulls")
            self.pr = {
                "number": 1,
                "state": "open",
                "merged_at": None,
                "mergeable_state": "clean",
                "changed_files": 0,
                "user": {"id": 902, "type": "Bot"},
                "head": {
                    "sha": self.refs[payload["head"]],
                    "ref": payload["head"],
                    "repo": {"id": self.repo_id},
                },
                "base": {"sha": self.head, "ref": payload["base"], "repo": {"id": self.repo_id}},
            }
            return deepcopy(self.pr)

        return SimpleNamespace(repo=create)

    def approve(self, *, uid=1, head=None, state="APPROVED"):
        self.reviews.append(
            {
                "user": {"id": uid, "type": "User"},
                "state": state,
                "commit_id": head or self.pr["head"]["sha"],
            }
        )


@pytest.fixture
def operator(setup_case, tmp_path):
    from aegis_platform.local_agent import LocalConfig

    source = Repo("demo/orders-api", 101)
    target = Repo("demo/aegis-gitops", 904, head="f" * 40)
    core = SimpleNamespace(
        gitops=target, target_files=lambda *_: (target.head, target.snapshots[target.head], None)
    )
    local = LocalConfig(
        kubeconfig="/tmp/fixture-kubeconfig",
        context="kind-fixture",
        cluster_id=setup_case.config.cluster_id,
        cluster_uid=setup_case.config.cluster_uid,
        kind_binary="/tmp/fixture-kind",
        kind_cluster="fixture",
        kind_node="fixture-control-plane",
    )
    service = SetupWorker(
        local,
        core,
        lambda _iid, _rid, repo: source.bot() if repo == source.repository else target.bot(),
        tmp_path / "operator",
        "99",
    )
    service.completed = {}
    service.source_reviewers = {"1"}
    service.target_reviewers = {"1"}
    service.state_path.mkdir()
    applied = []
    service.safe_apply = lambda resource, _entry: applied.append(deepcopy(resource))
    intent = SetupIntent(
        setup_id="setup-" + "a" * 64,
        issuer_id=setup_case.config.issuer_id,
        platform_repository_id="900",
        requester_user_id="1",
        created_at=datetime.now(UTC).isoformat(),
        idempotency_hash=digest("key"),
        plan=setup_case.plan,
    )
    return SimpleNamespace(
        service=service,
        source=source,
        target=target,
        applied=applied,
        intent=intent,
        issuer=SimpleNamespace(bot_user_id="902"),
    )


def process(operator, case):
    return operator.service.process(
        operator.intent, case.entry, operator.source, case.delivery, operator.issuer, case.policy
    )


def test_worker_prepares_proposals_requires_real_head_reviews_then_applies_only_target_permissions(
    operator, setup_case
):
    with pytest.raises(Pending):
        process(operator, setup_case)
    assert operator.source.pr and operator.target.pr
    assert operator.applied == []
    operator.source.approve()
    operator.target.approve()
    with pytest.raises(Pending, match="validation is running"):
        process(operator, setup_case)
    assert operator.applied == []
    operator.source.ci_status, operator.source.ci_conclusion = "completed", "success"
    assert process(operator, setup_case) == "ready"
    assert {r["kind"] for r in operator.applied} == {
        "Namespace",
        "ResourceQuota",
        "LimitRange",
        "AppProject",
    }
    assert not any(r["kind"] in {"Application", "Deployment", "Secret"} for r in operator.applied)
    assert all("prod" not in r["metadata"].get("namespace", "") for r in operator.applied)
    # Restart/retry reconciles the same reviewed plan, without another branch or proposal.
    assert process(operator, setup_case) == "ready"
    assert sum(path == "git/refs" for _, path, _ in operator.source.writes) == 1
    assert sum(path == "git/refs" for _, path, _ in operator.target.writes) == 1
    assert json.loads((operator.service.state_path / "completed.json").read_text())[
        operator.intent.setup_id
    ]


def test_worker_recovers_lost_source_branch_response_without_duplicate(operator, setup_case):
    operator.source.fail_after_ref = True
    with pytest.raises(ValueError, match="503"):
        process(operator, setup_case)
    assert operator.source.pr is None
    with pytest.raises(Pending):
        process(operator, setup_case)
    assert operator.source.pr is not None
    assert sum(path == "git/refs" for _, path, _ in operator.source.writes) == 1
    assert operator.applied == []


@pytest.mark.parametrize(
    "attack", ["unapproved", "wrong_head", "changed_files", "changed_source", "failed_ci"]
)
def test_worker_never_merges_or_applies_unreviewed_or_changed_setup(operator, setup_case, attack):
    with pytest.raises(Pending):
        process(operator, setup_case)
    if attack == "wrong_head":
        operator.source.approve(head="0" * 40)
    elif attack == "changed_files":
        operator.source.snapshots[operator.source.pr["head"]["sha"]]["app/main.py"] = (
            b"unrelated change"
        )
    elif attack == "changed_source":
        operator.source.head = "9" * 40
        operator.source.snapshots[operator.source.head] = {}
    elif attack == "failed_ci":
        operator.source.approve()
        operator.target.approve()
        operator.source.ci_status, operator.source.ci_conclusion = "completed", "failure"
    with pytest.raises((Pending, ValueError)):
        process(operator, setup_case)
    assert operator.applied == []
    assert not any(path.endswith("/merge") for _, path, _ in operator.source.writes)


def test_no_argo_activation_without_independently_signed_delivery(
    operator, setup_case, monkeypatch
):
    from app import setup_worker

    operator.service.activate_after_signed_deployment(setup_case.entry, setup_case.delivery)
    assert operator.applied == []
    # Even a pointer that passed current-state parsing cannot substitute for a signed request.
    pointer_path = (
        setup_case.entry.environments["dev"].values_path.rsplit("/", 1)[0] + "/release.json"
    )
    binding_path = "argocd/applications/orders-api-dev.json"
    pointer = {
        "delivery_id": "req-" + "b" * 64,
        "intent": {},
        "desired_state": {
            "controller_bindings": {
                binding_path: json.loads(setup_case.plan.target_files[binding_path])
            }
        },
    }
    monkeypatch.setattr(__import__("subprocess"), "check_output", lambda *_args, **_kwargs: "")
    operator.target.snapshots[operator.target.head][pointer_path] = canonical(pointer)
    monkeypatch.setattr(
        setup_worker, "current_state", lambda *_: SimpleNamespace(intent_anchor="c" * 40)
    )

    class Platform:
        def repo(self, *_):
            return {"object": {"sha": "a" * 40}}

        def file(self, *_):
            return canonical({"payload": {"binding": {"number": 1}}})

    operator.service.worker.platform = Platform()
    operator.service.worker.snapshot = lambda: (
        "a" * 40,
        setup_case.catalog,
        setup_case.delivery,
        SimpleNamespace(),
        setup_case.bootstrap,
    )
    with pytest.raises((ValueError, KeyError)):
        operator.service.activate_after_signed_deployment(setup_case.entry, setup_case.delivery)
    assert operator.applied == []


def test_safe_apply_refuses_other_app_ownership(operator, setup_case, monkeypatch):
    import subprocess

    from app.setup_worker import SetupWorker

    operator.service.safe_apply = SetupWorker.safe_apply.__get__(operator.service)
    monkeypatch.setattr(
        subprocess,
        "check_output",
        lambda *_a, **_kw: (
            '{"metadata":{"labels":{"aegis.io/app":"other","aegis.io/environment":"dev"}}}'
        ),
    )
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kw: calls.append(args))
    namespace = next(
        json.loads(v)
        for p, v in setup_case.plan.target_files.items()
        if p.endswith("namespace.json")
    )
    with pytest.raises(ValueError, match="not owned"):
        operator.service.safe_apply(namespace, setup_case.entry)
    assert calls == []


def create_job(client):
    path = "/api/v1/applications/orders-api"
    preview = client.post(path + "/dev-setup-validations").json()
    response = client.post(
        path + "/dev-setups",
        json={"review_token": preview["review_token"]},
        headers={"Idempotency-Key": str(uuid4())},
    )
    assert response.status_code == 200, response.text
    return response.json()["setup_id"]


def set_proposals(transport, case, rid):
    for _kind, repo, repo_id, head, files in (
        ("pipeline", "demo/orders-api", 101, "b" * 40, case.plan.workflow_files),
        ("target", "demo/aegis-gitops", 904, "c" * 40, case.plan.target_files),
    ):
        transport.prs[repo] = {
            "number": 1,
            "html_url": "https://github.com/" + repo + "/pull/1",
            "state": "open",
            "merged_at": None,
            "user": {"id": 902, "type": "Bot"},
            "head": {"sha": head, "ref": "aegis-setup/" + rid, "repo": {"id": repo_id}},
            "base": {"sha": "d" * 40, "ref": "main", "repo": {"id": repo_id}},
        }
        transport.commits[head] = {p: v.encode() for p, v in files.items()}


def test_application_owner_can_approve_pipeline_without_platform_owner_grant(
    setup_portal, setup_case
):
    client, _app, transport = setup_portal
    rid = create_job(client)
    set_proposals(transport, setup_case, rid)
    path = f"/api/v1/applications/orders-api/dev-setups/{rid}"
    before = client.get(path)
    assert before.status_code == 200, before.text
    assert before.json()["can_approve_pipeline"] is True
    assert before.json()["can_approve_target"] is False
    response = client.post(
        path + "/approvals", json={"review_token": before.json()["approval_token"]}
    )
    assert response.status_code == 200, response.text
    assert len(transport.reviews["demo/orders-api"]) == 1
    assert "demo/aegis-gitops" not in transport.reviews


def test_platform_owner_approves_both_scopes_with_real_user_reviews(setup_portal, setup_case):
    client, _app, transport = setup_portal
    transport.files[("demo/aegis-platform", "policies/portal-owner.json")] = canonical(
        {
            "schema_version": 1,
            "platform_repository_id": "900",
            "mode": "read_only",
            "owner_user_ids": ["1"],
        }
    )
    rid = create_job(client)
    set_proposals(transport, setup_case, rid)
    path = f"/api/v1/applications/orders-api/dev-setups/{rid}"
    before = client.get(path).json()
    assert before["can_approve_target"] is True
    response = client.post(path + "/approvals", json={"review_token": before["approval_token"]})
    assert response.status_code == 200, response.text
    assert (
        len(transport.reviews["demo/orders-api"])
        == len(transport.reviews["demo/aegis-gitops"])
        == 1
    )
    calls = [call for call in transport.calls if call[0] == "POST" and call[1].endswith("/reviews")]
    assert all(row[2]["json"]["event"] == "APPROVE" for row in calls)


def test_setup_review_rejects_tampered_proposal_files(setup_portal, setup_case):
    client, _app, transport = setup_portal
    rid = create_job(client)
    set_proposals(transport, setup_case, rid)
    transport.commits["b" * 40]["app/main.py"] = b"unrelated change"
    response = client.get(f"/api/v1/applications/orders-api/dev-setups/{rid}")
    assert response.status_code == 409
    assert transport.reviews == {}


def test_setup_approval_does_not_reuse_token_for_changed_head(setup_portal, setup_case):
    client, _app, transport = setup_portal
    rid = create_job(client)
    set_proposals(transport, setup_case, rid)
    path = f"/api/v1/applications/orders-api/dev-setups/{rid}"
    before = client.get(path).json()
    transport.commits["e" * 40] = transport.commits["b" * 40]
    transport.prs["demo/orders-api"]["head"]["sha"] = "e" * 40
    response = client.post(path + "/approvals", json={"review_token": before["approval_token"]})
    assert response.status_code == 409
    assert transport.reviews == {}


def test_setup_rejects_stale_source_before_persisting(setup_portal):
    client, _app, transport = setup_portal
    path = "/api/v1/applications/orders-api"
    preview = client.post(path + "/dev-setup-validations").json()
    transport.source_commit = "e" * 40
    response = client.post(
        path + "/dev-setups",
        json={"review_token": preview["review_token"]},
        headers={"Idempotency-Key": str(uuid4())},
    )
    assert response.status_code == 409
    assert transport.refs == {}


def test_repeated_review_from_another_tab_reuses_same_setup_plan(setup_portal):
    client, _app, transport = setup_portal
    first = create_job(client)
    second = create_job(client)
    assert second == first
    assert len(transport.refs) == 1


def test_worker_rechecks_current_platform_owner_grant_before_any_execution(
    operator, setup_case, monkeypatch
):
    owner_ids = ["1"]

    class Platform:
        def file(self, path, _revision):
            if path == "policies/portal-setup.json":
                return canonical(setup_case.policy.model_dump())
            assert path == "policies/portal-owner.json"
            return canonical(
                {
                    "schema_version": 1,
                    "platform_repository_id": "900",
                    "mode": "read_only",
                    "owner_user_ids": owner_ids,
                }
            )

    operator.service.worker.platform = Platform()
    operator.service.worker.snapshot = lambda: (
        "a" * 40,
        setup_case.catalog,
        setup_case.delivery,
        SimpleNamespace(),
        setup_case.bootstrap,
    )
    operator.service.worker.gitops.call = lambda *_: {"id": 1, "type": "User"}
    monkeypatch.setattr(operator.service.agent, "enroll", lambda *_: None)
    assert operator.service.snapshot()[-1].operator_user_ids == ["1"]
    owner_ids.clear()
    with pytest.raises(ValueError, match="No current enrolled"):
        operator.service.snapshot()
    assert operator.source.writes == operator.target.writes == []


def test_safe_apply_verifies_actual_server_state_after_submission(
    operator, setup_case, monkeypatch
):
    import subprocess

    from app.setup_worker import SetupWorker

    operator.service.safe_apply = SetupWorker.safe_apply.__get__(operator.service)
    project = json.loads(setup_case.plan.target_files["argocd/projects/orders-api-dev.json"])
    wrong = deepcopy(project)
    wrong["spec"]["namespaceResourceWhitelist"].append({"group": "*", "kind": "*"})
    responses = iter(["", json.dumps(wrong)])
    monkeypatch.setattr(subprocess, "check_output", lambda *_a, **_kw: next(responses))
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda *args, **kw: calls.append(args))
    with pytest.raises(ValueError, match="Observed target permissions"):
        operator.service.safe_apply(project, setup_case.entry)
    assert len(calls) == 2


def guided_registration(client, app, fields, monkeypatch):
    backend = app.state.service.backend
    app.state.service.config = backend.config
    monkeypatch.setattr(backend, "catalog", lambda: [])
    monkeypatch.setattr(
        backend,
        "registration_pr",
        lambda *_: {
            "number": 7,
            "url": "https://github.com/demo/aegis-platform/pull/7",
            "state": "open",
        },
    )
    monkeypatch.setattr(backend, "registration_status", lambda b: {**b, "merged": False})
    preview = client.post("/api/v1/registration-validations", json=fields)
    assert preview.status_code == 200, preview.text
    assert preview.json()["automatic_setup"]["blockers"] == []
    result = client.post(
        "/api/v1/registrations",
        json={**fields, "review_token": preview.json()["review_token"]},
        headers={"Idempotency-Key": str(uuid4())},
    )
    assert result.status_code == 201, result.text
    return result.json(), preview.json()


def test_registration_carries_exact_reviewed_plan_and_recovers_it_as_setup(
    setup_portal, setup_case, fields, monkeypatch
):
    client, app, _ = setup_portal
    result, preview = guided_registration(client, app, fields, monkeypatch)
    assert result["automatic_setup"] is True
    rid = result["registration_id"]
    raw = app.state.service.backend.journal(rid)[1]
    intent, _issuer = verify_setup(
        raw, trust_for(app.state.service.signer, setup_case), setup_case.policy
    )
    assert intent.setup_id == "setup-" + rid[4:]
    assert intent.plan.workflow_files == {
        f["path"]: f["content"] for f in preview["automatic_setup"]["workflow_files"]
    }
    response = client.get(f"/api/v1/applications/orders-api/dev-setups/{intent.setup_id}")
    assert response.status_code == 200, response.text
    assert response.json()["setup_id"] == intent.setup_id
    assert not any("/pulls" in p and m == "POST" for m, p, _ in setup_portal[2].calls)


@pytest.mark.parametrize(
    "attack", ["nested_tamper", "root_rebind", "source_changed", "entry_changed", "missing_consent"]
)
def test_nested_registration_setup_requires_bound_signature_and_exact_consent(
    setup_portal, setup_case, fields, monkeypatch, attack
):
    client, app, _ = setup_portal
    result, _ = guided_registration(client, app, fields, monkeypatch)
    raw = deepcopy(app.state.service.backend.journal(result["registration_id"])[1])
    payload = raw["payload"]
    if attack == "nested_tamper":
        payload["setup_intent"]["plan"]["namespace"] = "foreign"
    else:
        if attack == "root_rebind":
            payload["requester_user_id"] = "999"
        elif attack == "source_changed":
            payload["source_commit"] = "f" * 40
        elif attack == "entry_changed":
            payload["catalog_entry"]["runtime"]["container_port"] = 9000
        else:
            payload.pop("setup_intent")
        raw = app.state.service.signer.seal(payload)
    with pytest.raises(ValueError):
        verify_setup(raw, trust_for(app.state.service.signer, setup_case), setup_case.policy)


def test_setup_change_between_registration_preview_and_confirm_requires_new_review(
    setup_portal, fields, monkeypatch
):
    client, app, transport = setup_portal
    backend = app.state.service.backend
    app.state.service.config = backend.config
    monkeypatch.setattr(backend, "catalog", lambda: [])
    preview = client.post("/api/v1/registration-validations", json=fields)
    assert preview.status_code == 200
    transport.files[("demo/aegis-platform", "policies/portal-setup.json")] = canonical(
        {**transport.case.policy.model_dump(), "operator_user_ids": ["1", "2"]}
    )
    result = client.post(
        "/api/v1/registrations",
        json={**fields, "review_token": preview.json()["review_token"]},
        headers={"Idempotency-Key": str(uuid4())},
    )
    assert result.status_code in {409, 503}
    assert not transport.refs


def registration_payload(case, intent):
    return {
        "registration_id": "reg-" + intent.setup_id[6:],
        "issuer_id": intent.issuer_id,
        "platform_repository_id": intent.platform_repository_id,
        "requester_user_id": intent.requester_user_id,
        "created_at": intent.created_at,
        "idempotency_key_hash": intent.idempotency_hash,
        "source_commit": intent.plan.source_commit,
        "catalog_entry": case.entry.model_dump(),
        "policy_hash": digest(case.config.model_dump()),
        "setup_intent": intent.model_dump(),
        "binding": {"number": 1},
    }


@pytest.mark.parametrize(
    "attack",
    [
        None,
        "no_approval",
        "wrong_head",
        "unrelated_file",
        "revoked_onboarding",
        "source_access",
        "source_changed",
        "wrong_branch",
        "foreign_author",
    ],
)
def test_worker_merges_only_exact_reviewed_catalog_after_current_grants(
    operator, setup_case, attack
):
    service, case = operator.service, setup_case
    configuration = {"configuration": case.config.model_dump()}
    platform = Repo(
        "demo/aegis-platform", 900, {"policies/portal-system.json": canonical(configuration)}
    )
    payload = registration_payload(case, operator.intent)
    branch = "portal-onboarding/" + payload["registration_id"]
    path = "catalog/apps/orders-api.json"
    service.ensure_pr(
        platform,
        platform.bot(),
        branch,
        "main",
        {path: canonical(case.entry.model_dump()).decode()},
        title="Register orders-api",
    )
    service.worker.platform = platform
    service.worker.source_factory = lambda _: operator.source
    original_repo = operator.source.repo
    operator.source.repo = lambda method, path, data=None: (
        {"id": 101, "full_name": "demo/orders-api", "private": False, "default_branch": "main"}
        if path == ""
        else original_repo(method, path, data)
    )
    operator.source.pages = lambda *_a, **_k: [
        {"id": 1, "permissions": {"push": attack != "source_access"}}
    ]
    if attack != "no_approval":
        platform.approve(head="0" * 40 if attack == "wrong_head" else None)
    if attack == "unrelated_file":
        platform.snapshots[platform.pr["head"]["sha"]]["policies/unsafe.json"] = b"{}"
    elif attack == "revoked_onboarding":
        configuration["configuration"]["onboarding_user_ids"] = ["2"]
        platform.snapshots[platform.head]["policies/portal-system.json"] = canonical(configuration)
    elif attack == "source_changed":
        operator.source.head = "f" * 40
    elif attack == "wrong_branch":
        platform.pr["head"]["ref"] = "unrelated"
    elif attack == "foreign_author":
        platform.pr["user"]["id"] = 999
    draft = Catalog([], list(case.catalog.clusters.values()), case.catalog.policy)
    with pytest.raises(Pending if attack in {None, "no_approval", "wrong_head"} else ValueError):
        service.merge_registration(
            payload,
            operator.intent,
            operator.issuer,
            case.policy,
            draft,
            case.delivery,
            case.bootstrap,
        )
    assert bool(platform.pr.get("merged_at")) == (attack is None)
    assert operator.target.pr is None and not operator.applied
