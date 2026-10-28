from copy import deepcopy
from types import SimpleNamespace

import pytest
from aegis_platform.canonical import canonical, digest
from aegis_platform.delivery import DeliveryPolicy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.demo import demo_config
from app.errors import PortalError
from app.security import Signer
from app.workflows import WorkflowService, WorkflowSubmission, review_file


@pytest.fixture
def review_gateway():
    config = demo_config()
    config.gitops_repository = "demo/aegis-gitops"
    policy = DeliveryPolicy(
        platform_repository=config.platform_repository,
        platform_repository_id="900",
        gitops_repository=config.gitops_repository,
        gitops_repository_id="904",
        bootstrap_policy_hash=digest("bootstrap"),
        workflow_bot_user_ids=["902"],
        observer_user_ids=["1"],
        production_reviewer_user_ids=["1"],
    )

    class Backend:
        def __init__(self):
            self.config = config
            self.allowed = True
            self.push = True
            self.protected = True
            self.policy = policy.model_dump()
            self.user = {"id": 1, "type": "User", "login": "maintainer"}
            self.pr = {
                "number": 7,
                "title": "Register test app",
                "changed_files": 1,
                "state": "open",
                "draft": False,
                "user": {"id": 902, "type": "Bot"},
                "head": {"sha": "a" * 40, "repo": {"id": 900}},
                "base": {"sha": "b" * 40, "repo": {"id": 900}, "ref": "main"},
                "merged_at": None,
            }
            self.reviews = []
            self.writes = []
            self.pr_reads = 0
            self.move_on_read = None
            self.merge_status = 200
            self.content = b"new\n"
            self.files = [{"filename": "catalog/apps/test.json", "status": "added"}]

        def owner_context(self, session):
            if not self.allowed:
                raise PortalError(403, "FORBIDDEN", "Owner access revoked")
            return "c" * 40, None, "read-policy"

        def file(self, repo, path, ref, token, **kwargs):
            if path == "policies/delivery.json":
                return canonical(self.policy)
            if path == "policies/portal-system.json":
                return canonical({"operator_user_ids": ["1"]})
            assert token == "human-token"
            assert ref == "a" * 40
            return self.content

        def paginate(self, path, token, **kwargs):
            assert token == "human-token"
            return deepcopy(self.files if path.endswith("/files") else self.reviews)

        def api(self, method, path, token, **kwargs):
            assert token == "human-token", (
                "Human operations must never use an App installation token"
            )
            if method == "GET":
                if path == "/user":
                    data = self.user
                elif "/branches/" in path:
                    data = {"protected": self.protected}
                elif path.endswith("/pulls/7"):
                    self.pr_reads += 1
                    if self.move_on_read == self.pr_reads:
                        self.pr["head"]["sha"] = "d" * 40
                    data = self.pr
                else:
                    data = {
                        "id": 904 if path.endswith("aegis-gitops") else 900,
                        "permissions": {"push": self.push},
                    }
                return SimpleNamespace(json=lambda: deepcopy(data))
            self.writes.append((method, path, token, kwargs["json"]))
            if method == "PUT":
                return SimpleNamespace(
                    status_code=self.merge_status, json=lambda: {"merged": True, "sha": "e" * 40}
                )
            body = kwargs["json"]
            data = {
                "id": len(self.reviews) + 1,
                "user": deepcopy(self.user),
                "commit_id": body["commit_id"],
                "body": body["body"],
                "state": "APPROVED" if body["event"] == "APPROVE" else "CHANGES_REQUESTED",
            }
            self.reviews.append(data)
            return SimpleNamespace(json=lambda: deepcopy(data))

    backend = Backend()
    service = WorkflowService(backend, Signer(Ed25519PrivateKey.generate(), "review-test"))
    session = SimpleNamespace(user_id="1", user_token="human-token")
    return backend, service, session


def submission(service, session, action="approve", repo="platform", **changes):
    view = service.details(session, repo, 7)
    return WorkflowSubmission(
        action=action,
        review_token=view["review_token"],
        operation_key="review-operation-12345",
        acknowledge=True,
        **changes,
    )


def test_approval_is_attributed_to_human_and_bound_to_exact_head(review_gateway):
    b, s, user = review_gateway
    fields = submission(s, user)
    result = s.submit(user, "platform", 7, fields)
    assert result["reviewer_user_id"] == "1"
    assert b.writes[0][2] == "human-token"
    assert b.writes[0][3]["commit_id"] == "a" * 40
    assert b.writes[0][3]["event"] == "APPROVE"
    assert result["head"] == "a" * 40


def test_lost_review_response_recovers_without_duplicate_and_dismissal_needs_new_decision(
    review_gateway,
):
    b, s, user = review_gateway
    fields = submission(s, user)
    s.submit(user, "platform", 7, fields)
    assert s.submit(user, "platform", 7, fields)["recovered"]
    assert len(b.writes) == 1
    b.reviews[0]["state"] = "DISMISSED"
    with pytest.raises(PortalError) as exc:
        s.submit(user, "platform", 7, fields)
    assert exc.value.code == "REVIEW_OPERATION_CHANGED"
    assert len(b.writes) == 1


def test_operation_key_cannot_be_reused_for_a_different_decision(review_gateway):
    b, s, user = review_gateway
    fields = submission(s, user)
    s.submit(user, "platform", 7, fields)
    with pytest.raises(PortalError):
        s.submit(
            user,
            "platform",
            7,
            fields.model_copy(update={"action": "request_changes", "reason": "Different"}),
        )
    assert len(b.writes) == 1


@pytest.mark.parametrize(
    "change",
    [
        "revoked",
        "no_push",
        "bot",
        "wrong_user",
        "wrong_repo",
        "self_review",
        "draft",
        "changed_content",
    ],
)
def test_authority_or_content_changes_block_mutation(review_gateway, change):
    b, s, user = review_gateway
    fields = submission(s, user)
    if change == "revoked":
        b.allowed = False
    elif change == "no_push":
        b.push = False
    elif change == "bot":
        b.user["type"] = "Bot"
    elif change == "wrong_user":
        b.user["id"] = 99
    elif change == "wrong_repo":
        b.pr["base"]["repo"]["id"] = 999
    elif change == "self_review":
        b.pr["user"]["id"] = 1
    elif change == "draft":
        b.pr["draft"] = True
    elif change == "changed_content":
        b.content = b"different\n"
    with pytest.raises(PortalError):
        s.submit(user, "platform", 7, fields)
    assert not b.writes


def test_head_race_after_confirmation_is_rejected_before_write(review_gateway):
    b, s, user = review_gateway
    fields = submission(s, user)
    b.move_on_read = b.pr_reads + 3
    with pytest.raises(PortalError) as exc:
        s.submit(user, "platform", 7, fields)
    assert exc.value.code == "REVIEW_CHANGED"
    assert not b.writes


def test_complete_content_budget_and_patch_are_not_silently_truncated(review_gateway):
    b, s, user = review_gateway
    b.files *= 65
    b.pr["changed_files"] = 65
    with pytest.raises(PortalError):
        s.details(user, "platform", 7)
    row = review_file("app.py", b"old\n", b"new\n", "modified")
    assert "-old" in row["diff"] and "+new" in row["diff"]
    binary = review_file("bundle.whl", None, b"\0binary", "added")
    assert binary["binary"] and binary["after"]["sha256"]


def test_merge_uses_expected_sha_and_provider_gate_without_admin_bypass(review_gateway):
    b, s, user = review_gateway
    fields = submission(s, user, action="merge")
    assert s.submit(user, "platform", 7, fields)["status"] == "merged"
    assert b.writes[0][3] == {"sha": "a" * 40, "merge_method": "squash"}
    b.merge_status = 405
    with pytest.raises(PortalError) as exc:
        s.submit(user, "platform", 7, fields)
    assert exc.value.code == "MERGE_BLOCKED"


def test_unprotected_branch_cannot_merge(review_gateway):
    b, s, user = review_gateway
    fields = submission(s, user, action="merge")
    b.protected = False
    with pytest.raises(PortalError) as exc:
        s.submit(user, "platform", 7, fields)
    assert exc.value.code == "MERGE_POLICY_REQUIRED" and not b.writes


def test_production_requires_independent_authorized_exact_head_review(review_gateway):
    b, s, user = review_gateway
    b.pr["base"]["ref"] = "prod"
    b.pr["base"]["repo"]["id"] = b.pr["head"]["repo"]["id"] = 904
    fields = submission(s, user, action="merge", repo="gitops")
    with pytest.raises(PortalError):
        s.submit(user, "gitops", 7, fields)
    assert not b.writes
    b.reviews = [{"id": 1, "user": b.user, "state": "APPROVED", "commit_id": "a" * 40}]
    assert s.submit(user, "gitops", 7, fields)["status"] == "merged"
    b.reviews[0]["commit_id"] = "d" * 40
    with pytest.raises(PortalError):
        s.submit(user, "gitops", 7, fields)
    assert len(b.writes) == 1


def test_review_routes_require_sign_in_csrf_and_live_provider(portal, settings):
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app(settings)) as client:
        assert client.get("/api/v1/platform/reviews/platform/7").status_code == 401
    client, _ = portal
    assert client.get("/api/v1/platform/reviews/platform/7").status_code == 503
    assert client.post("/api/v1/platform/reviews/platform/7", json={}).status_code in {403, 422}


def test_review_mutation_requires_csrf_even_with_valid_fields(portal):
    client, _ = portal
    fields = {
        "action": "approve",
        "review_token": "a" * 64,
        "operation_key": "review-operation-12345",
        "acknowledge": True,
    }
    response = client.post(
        "/api/v1/platform/reviews/platform/7", json=fields, headers={"X-CSRF-Token": ""}
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "CSRF_INVALID"
