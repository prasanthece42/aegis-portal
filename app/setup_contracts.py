"""Exact DEV preparation plans and signed requests shared with the enrolled operator."""

import base64
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from aegis_platform.bootstrap import bootstrap_plan
from aegis_platform.canonical import canonical, digest
from aegis_platform.contracts import AppId, Commit, Contract, Identifier
from aegis_platform.delivery import timestamp
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

CHARTS = Path(__file__).parent / "setup_chart"


class SetupPolicy(Contract):
    schema_version: Literal[1] = 1
    enabled: Literal[True]
    platform_repository_id: Identifier
    gitops_repository_id: Identifier
    portal_app_id: Identifier
    cluster_id: str
    cluster_uid: str
    source_owner: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
    operator_user_ids: list[Identifier] = Field(min_length=1, max_length=20)
    environment: Literal["dev"] = "dev"
    installation_method: Literal["enrolled_operator"] = "enrolled_operator"


class SetupPlan(Contract):
    app_id: AppId
    source_repository_id: Identifier
    source_repository: str
    source_branch: str
    source_commit: Commit
    catalog_entry_hash: str
    delivery_policy_hash: str
    setup_policy_hash: str
    cluster_id: str
    cluster_uid: str
    namespace: str
    workflow_files: dict[str, str]
    target_files: dict[str, str]


class SetupIntent(Contract):
    schema_version: Literal[1] = 1
    kind: Literal["dev_setup_request"] = "dev_setup_request"
    setup_id: str = Field(pattern=r"^setup-[0-9a-f]{64}$")
    issuer_id: str
    platform_repository_id: Identifier
    requester_user_id: Identifier
    created_at: str
    idempotency_hash: str
    plan: SetupPlan


def workflow_files(entry, platform_repository):
    files = {}
    for kind in ("ci", "release"):
        trigger = "  pull_request:\n" if kind == "ci" else ""
        packages = "" if kind == "ci" else "  packages: write\n"
        permissions = "read" if kind == "ci" else "write"
        content = (
            f"name: Aegis {kind}\n\non:\n{trigger}  push:\n"
            f"    branches: [{json.dumps(entry.source.default_branch)}]\n"
            "  workflow_dispatch:\n\n"
            f"permissions:\n  contents: {permissions}\n{packages}  actions: read\n\n"
            f"concurrency:\n  group: aegis-{kind}-${{{{ github.ref }}}}\n"
            "  cancel-in-progress: false\n\njobs:\n  validate:\n"
            f"    uses: {platform_repository}/.github/workflows/python-web-{kind}.yml"
            f"@{entry.versions.workflow_commit}\n    with:\n      app-id: {entry.app_id}\n"
            f"      container-port: {json.dumps(str(entry.runtime.container_port))}\n"
            f"      health-path: {json.dumps(entry.runtime.health_path)}\n"
        )
        if kind == "ci":
            content += '      platforms: \'["amd64","arm64"]\'\n'
        files[f".github/workflows/{kind}.yml"] = content
    return files


def make_plan(entry, catalog, delivery, bootstrap, policy, source_commit):
    target = entry.environments.get("dev")
    if (
        not target
        or entry.runtime.profile_id != "python312-web"
        or entry.source.owner.lower() != policy.source_owner.lower()
        or policy.platform_repository_id != delivery.platform_repository_id
        or policy.gitops_repository_id != delivery.gitops_repository_id
        or (target.cluster_id, target.cluster_uid) != (policy.cluster_id, policy.cluster_uid)
        or not set(policy.operator_user_ids) <= set(delivery.observer_user_ids)
        or digest(bootstrap) != delivery.bootstrap_policy_hash
        or entry.source.repository_id
        in {delivery.platform_repository_id, delivery.gitops_repository_id}
    ):
        raise ValueError("Application or operator differs from reviewed DEV preparation policy")
    chart = CHARTS / entry.versions.chart_version
    files = bootstrap_plan(
        catalog,
        entry.app_id,
        "dev",
        {
            "gitops_repository": delivery.gitops_repository,
            "gitops_repository_id": delivery.gitops_repository_id,
            "cluster_id": target.cluster_id,
            "cluster_uid": target.cluster_uid,
        },
        bootstrap,
        chart,
    )
    # Files may describe the future Argo binding. The worker does not install that
    # Application until an independent signed deployment request is admitted and merged.
    target_files = {
        p: v.decode() if isinstance(v, bytes) else canonical(v).decode() + "\n"
        for p, v in files.items()
    }
    plan = SetupPlan(
        app_id=entry.app_id,
        source_repository_id=entry.source.repository_id,
        source_repository=entry.source.owner + "/" + entry.source.name,
        source_branch=entry.source.default_branch,
        source_commit=source_commit,
        catalog_entry_hash=digest(entry.model_dump()),
        delivery_policy_hash=digest(delivery.model_dump()),
        setup_policy_hash=digest(policy.model_dump()),
        cluster_id=target.cluster_id,
        cluster_uid=target.cluster_uid,
        namespace=target.namespace,
        workflow_files=workflow_files(entry, delivery.platform_repository),
        target_files=target_files,
    )
    if len(canonical(plan.model_dump())) > 56000:
        raise ValueError("Preparation plan exceeds the bounded signed journal budget")
    return plan


def setup_payload(payload):
    """Extract an explicitly reviewed plan from a signed registration or setup record."""
    if payload.get("kind") == "dev_setup_request":
        return payload
    nested = payload.get("setup_intent")
    if not nested or payload.get("prepare_dev") is not True:
        raise ValueError("Not an explicit DEV setup request")
    intent = SetupIntent.model_validate(nested)
    rid = payload.get("registration_id", "")
    if (
        not re.fullmatch(r"reg-[0-9a-f]{64}", rid)
        or intent.setup_id != "setup-" + rid[4:]
        or any(
            payload.get(k) != getattr(intent, k)
            for k in ("issuer_id", "platform_repository_id", "requester_user_id", "created_at")
        )
        or payload.get("idempotency_key_hash") != intent.idempotency_hash
        or payload.get("source_commit") != intent.plan.source_commit
        or digest(payload.get("catalog_entry")) != intent.plan.catalog_entry_hash
    ):
        raise ValueError("Registration and setup authorization differ")
    return nested


def verify_setup(record, trust, policy, now=None, *, admission=True, require_fresh=True):
    if set(record) != {"payload", "envelope"}:
        raise ValueError("Invalid setup envelope")
    intent = SetupIntent.model_validate(setup_payload(record["payload"]))
    env = record["envelope"]
    matches = [
        i
        for i in trust.issuers
        if i.issuer_id == intent.issuer_id
        and i.key_id == env.get("key_id")
        and (i.active or not admission)
    ]
    if (
        set(env) != {"algorithm", "key_id", "payload_sha256", "signature"}
        or len(matches) != 1
        or env.get("algorithm") != "Ed25519"
        or env.get("payload_sha256") != digest(record["payload"])
        or intent.platform_repository_id != trust.platform_repository_id
        or intent.platform_repository_id != policy.platform_repository_id
        or intent.plan.setup_policy_hash != digest(policy.model_dump())
    ):
        raise ValueError("Setup signature audience or current policy differs")
    try:
        signature = env["signature"]
        raw = base64.b64decode(
            signature + "=" * (-len(signature) % 4), altchars=b"-_", validate=True
        )
        Ed25519PublicKey.from_public_bytes(base64.b64decode(matches[0].public_key_base64)).verify(
            raw, canonical(record["payload"])
        )
    except (KeyError, ValueError, InvalidSignature) as exc:
        raise ValueError("Invalid setup signature") from exc
    if not re.fullmatch(r"setup-[0-9a-f]{64}", intent.setup_id):
        raise ValueError("Invalid setup identity")
    if admission and require_fresh:
        now = now or datetime.now(UTC)
        created = timestamp(intent.created_at)
        if created > now + timedelta(seconds=300) or now - created > timedelta(
            seconds=trust.maximum_request_age_seconds
        ):
            raise ValueError("Setup request expired; review a fresh plan")
    return intent, matches[0]
