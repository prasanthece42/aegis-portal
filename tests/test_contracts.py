import pytest
from pydantic import ValidationError

from app.contracts import DeploymentIntent, RegistrationFields, Runtime


@pytest.mark.parametrize(
    "path",
    [
        "https://evil.invalid",
        "//evil.invalid",
        "/../admin",
        "/%2e%2e/admin",
        "/%252e%252e/admin",
        "/health?secret=1",
        "/health#fragment",
        "/a\\b",
        "/bad\npath",
        "/a/./b",
    ],
)
def test_health_path_cannot_choose_another_authority_or_traverse(path):
    with pytest.raises(ValidationError):
        Runtime(container_port=8000, health_path=path, resource_profile_id="small")


@pytest.mark.parametrize(
    "app_id", ["../other", "UPPER", "a--b", "-start", "trailing-", "ab", "a" * 41]
)
def test_catalog_paths_come_from_bounded_identifiers(fields, app_id):
    with pytest.raises(ValidationError):
        RegistrationFields.model_validate({**fields, "app_id": app_id})


def intent(environment="dev"):
    sha = "a" * 40
    digest = "sha256:" + "b" * 64
    return {
        "request_id": "req-" + "c" * 64,
        "issuer_id": "test",
        "platform_repository_id": "1",
        "requester_user_id": "2",
        "created_at": "2026-10-26T12:00:00Z",
        "idempotency_key_hash": digest,
        "payload_hash": digest,
        "app_id": "orders-api",
        "environment": environment,
        "operation": "deploy",
        "origin": "portal",
        "catalog_revision": sha,
        "catalog_entry_hash": digest,
        "resolved_policy_hash": digest,
        "source_repository_id": "3",
        "source_commit": sha,
        "release_id": "4",
        "release_workflow_run_id": "5",
        "release_evidence_hash": digest,
        "image_root_digest": digest,
        "platform_digests": {"linux/arm64": digest},
        "expected_desired_fingerprint": None,
        "expected_intent_anchor": None,
        "prior_environment_evidence": None,
    }


def test_prod_contract_requires_prior_environment_evidence():
    assert DeploymentIntent.model_validate(intent()).environment == "dev"
    with pytest.raises(ValidationError):
        DeploymentIntent.model_validate(intent("prod"))
    data = intent("prod")
    data["operation"] = "promote"
    data["prior_environment_evidence"] = {
        "environment": "staging",
        "intent_anchor": "anchor",
        "fingerprint": data["image_root_digest"],
        "observed_at": "2026-10-26T12:00:00Z",
        "evidence_reference": "evidence",
    }
    assert DeploymentIntent.model_validate(data).environment == "prod"
    data["prior_environment_evidence"]["environment"] = "dev"
    with pytest.raises(ValidationError):
        DeploymentIntent.model_validate(data)


def test_numeric_and_extra_input_types_rejected(fields):
    with pytest.raises(ValidationError):
        RegistrationFields.model_validate({**fields, "repository_id": 101})
    with pytest.raises(ValidationError):
        RegistrationFields.model_validate({**fields, "requester_user_id": "2"})
