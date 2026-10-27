"""Local walkthrough data only. This adapter cannot contact GitHub or a cluster."""

import json
import os
import threading
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

from app.config import LiveConfig
from app.errors import PortalError
from app.security import Session


def demo_config() -> LiveConfig:
    return LiveConfig.model_validate(
        {
            "public_origin": "https://demo.invalid",
            "app_id": "99",
            "client_id": "demo",
            "platform_repository": "demo/aegis-platform",
            "platform_repository_id": "900",
            "platform_installation_id": "901",
            "platform_bot_user_id": "902",
            "source_installation_ids": ["903"],
            "onboarding_user_ids": ["1"],
            "allowed_owner_user_ids": ["1"],
            "issuer_id": "aegis-demo-only",
            "signing_key_id": "demo-not-trusted-by-live",
            "cluster_id": "kind-local",
            "cluster_uid": "demo-cluster-not-enrolled",
            "gitops_repository_id": "904",
            "resource_profiles": {
                "small": {
                    "cpu_request": "100m",
                    "memory_request": "128Mi",
                    "cpu_limit": "500m",
                    "memory_limit": "256Mi",
                }
            },
            "versions": {
                "workflow_commit": "a" * 40,
                "helper_commit": "b" * 40,
                "chart_version": "1.0.0",
                "chart_sha256": "sha256:" + "c" * 64,
            },
        }
    )


class DemoBackend:
    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.RLock()
        self.data = json.loads(path.read_text()) if path.exists() else {}

    def repositories(self, session: Session) -> list[dict]:
        if session.user_id != "1":
            return []
        return [
            {
                "repository_id": "101",
                "installation_id": "903",
                "full_name": "demo/orders-api",
                "default_branch": "main",
            },
            {
                "repository_id": "102",
                "installation_id": "903",
                "full_name": "demo/payments-api",
                "default_branch": "main",
            },
        ]

    def source(self, session: Session, repository_id: str) -> dict:
        for repo in self.repositories(session):
            if repo["repository_id"] == repository_id:
                return {
                    **repo,
                    "owner": "demo",
                    "name": repo["full_name"].split("/")[1],
                    "source_commit": "d" * 40,
                }
        raise PortalError(404, "REPOSITORY_UNAVAILABLE", "Repository is unavailable.")

    def detection(self, source: dict) -> dict:
        return {
            "source_commit": source["source_commit"],
            "dockerfile_present": True,
            "dependency_lock_present": True,
            "pipeline_file_present": False,
            "pipeline_validated": False,
            "message": "Demo detection: pipeline setup and operator target setup remain required.",
        }

    def catalog(self) -> list[dict]:
        return []

    def owner_allowed(self, session):
        return session.user_id == "1"  # Explicit synthetic role; never a live grant.

    def owner_overview(self, session):
        if not self.owner_allowed(session):
            raise PortalError(403, "PLATFORM_FORBIDDEN", "Platform owner access is required.")
        return {
            "mode": "demo",
            "access_mode": "read_only",
            "observed_at": datetime.now(UTC).isoformat(),
            "catalog_revision": None,
            "applications": [],
            "reviews": [],
            "review_total": 0,
            "activity": [],
            "activity_total": 0,
            "clusters": [
                {
                    "cluster_id": "example-kind",
                    "cluster_uid": "demo-only",
                    "profile_id": "small",
                    "state": "demo_only",
                }
            ],
            "policy": {
                "production_human_review_required": True,
                "protected_sync_mode": "operator",
                "maximum_evidence_age_seconds": 86400,
                "owner_user_ids": ["1"],
                "resource_profiles": {
                    "small": {
                        "requests": {"cpu": "100m", "memory": "128Mi"},
                        "limits": {"cpu": "500m", "memory": "256Mi"},
                    }
                },
                "owner_policy_url": None,
                "delivery_policy_url": None,
            },
        }

    def journal(self, registration_id: str) -> tuple[str, dict] | None:
        with self.lock:
            record = self.data.get(registration_id)
            return (str(record["version"]), deepcopy(record["record"])) if record else None

    def save_journal(self, registration_id: str, record: dict, parent: str | None) -> bool:
        with self.lock:
            current = self.data.get(registration_id)
            if (current is None and parent is not None) or (
                current and str(current["version"]) != parent
            ):
                return False
            new_data = deepcopy(self.data)
            new_data[registration_id] = {
                "version": current["version"] + 1 if current else 1,
                "record": record,
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as handle:
                os.chmod(tmp, 0o600)
                json.dump(new_data, handle)
                handle.flush()
                os.fsync(handle.fileno())
            tmp.replace(self.path)
            self.data = new_data
            return True

    def registration_pr(self, registration_id: str, entry: dict) -> dict:
        return {"number": None, "url": None, "state": "demo_pending_review", "demo": True}

    def registration_status(self, binding: dict) -> dict:
        return binding

    def journal_ids(self) -> list[str]:
        with self.lock:
            return list(self.data)

    def close(self):
        pass
