"""Guided, durable DEV preparation. User review authorizes exact setup, never deployment."""

import hashlib
import re
import threading
from datetime import UTC, datetime
from uuid import UUID

from aegis_platform.canonical import digest
from pydantic import BaseModel, ConfigDict, Field

from app.errors import PortalError
from app.setup_contracts import SetupIntent
from app.setup_github import plan_bytes_equal


class SetupConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    review_token: str = Field(max_length=16000)


def file_rows(files, existing):
    rows = []
    for path, content in files.items():
        before = existing.get(path)
        same = plan_bytes_equal(path, before, content)
        rows.append(
            {
                "path": path,
                "content": content,
                "status": "present" if same else "add" if before is None else "conflict",
            }
        )
    return rows


class SetupService:
    def __init__(self, backend, signer):
        self.backend, self.signer = backend, signer
        self.lock = threading.RLock()

    def context(self, session, app_id):
        if not hasattr(self.backend, "setup_context"):
            raise PortalError(
                503,
                "SETUP_UNAVAILABLE",
                "Automatic preparation requires the configured live service.",
            )
        return self.backend.setup_context(session, app_id)

    def preview(self, session, app_id):
        entry, revision, delivery, policy, plan = self.context(session, app_id)
        existing = self.backend.setup_files(entry, plan)
        workflows = file_rows(plan.workflow_files, existing["source"])
        targets = file_rows(plan.target_files, existing["target"])
        blockers = [
            "An existing file needs a maintainer's decision: " + row["path"]
            for row in workflows + targets
            if row["status"] == "conflict"
        ]
        for path in ("Dockerfile", "requirements.txt", "requirements-prod.txt"):
            if existing["source"].get(path) is None:
                blockers.append("Application source is missing " + path + ".")
        binding = {
            "kind": "dev_setup_review",
            "user_id": session.user_id,
            "app_id": app_id,
            "plan_hash": digest(plan.model_dump()),
            "existing_hash": digest(
                {
                    g: {
                        p: hashlib.sha256(v).hexdigest() if v is not None else None
                        for p, v in fs.items()
                    }
                    for g, fs in existing.items()
                }
            ),
        }
        return {
            "app_id": app_id,
            "environment": "dev",
            "namespace": plan.namespace,
            "workflow_files": workflows,
            "target_files": targets,
            "blockers": blockers,
            "review_token": self.signer.review_token(binding),
            "worker_online": self.backend.setup_heartbeat(revision, delivery, policy),
            "notice": (
                "Preparation installs reviewed pipeline files and DEV permissions. "
                "CI builds a release. Deployment requires a separate "
                "release selection and confirmation."
            ),
        }

    def submit(self, session, app_id, token, key):
        with self.lock:
            return self._submit(session, app_id, token, key)

    def _submit(self, session, app_id, token, key):
        try:
            parsed = UUID(key)
            if parsed.version != 4:
                raise ValueError("Expected UUID v4")
        except (ValueError, TypeError, AttributeError):
            raise PortalError(
                422, "IDEMPOTENCY_KEY_REQUIRED", "Use the original setup operation key."
            ) from None
        rid = (
            "setup-"
            + digest([self.backend.config.issuer_id, session.user_id, app_id, str(parsed)]).split(
                ":"
            )[1]
        )
        existing = self.backend.journal(rid)
        if existing:
            intent = self.verified(existing[1], rid)
            if intent.requester_user_id != session.user_id or intent.plan.app_id != app_id:
                raise PortalError(403, "SETUP_FORBIDDEN", "Setup belongs to another identity.")
            self.context(session, app_id)
            return self.get(session, app_id, rid)
        preview = self.preview(session, app_id)
        if preview["blockers"]:
            raise PortalError(
                409, "SETUP_BLOCKED", "Resolve the requirements shown in the setup review."
            )
        try:
            old = self.signer.read_review(token)
            current = self.signer.read_review(preview["review_token"])
            if {k: v for k, v in old.items() if k != "expires_at"} != {
                k: v for k, v in current.items() if k != "expires_at"
            }:
                raise ValueError("Plan changed")
        except (ValueError, KeyError, TypeError):
            raise PortalError(
                409,
                "SETUP_REVIEW_CHANGED",
                "Source or policy changed. Review the current setup again.",
            ) from None
        _entry, _revision, _delivery, _policy, plan = self.context(session, app_id)
        if digest(plan.model_dump()) != current["plan_hash"]:
            raise PortalError(409, "SETUP_REVIEW_CHANGED", "Setup inputs changed. Review again.")
        for existing_id, record in self.backend.setup_records():
            previous = self.verified(record, existing_id)
            if (
                previous.requester_user_id == session.user_id
                and previous.plan.app_id == app_id
                and digest(previous.plan.model_dump()) == current["plan_hash"]
                and (
                    datetime.now(UTC) - datetime.fromisoformat(previous.created_at)
                ).total_seconds()
                < 86400
            ):
                state = self.get(session, app_id, existing_id)
                if state["state"] != "needs_attention":
                    return state
        intent = SetupIntent(
            setup_id=rid,
            issuer_id=self.backend.config.issuer_id,
            platform_repository_id=self.backend.config.platform_repository_id,
            requester_user_id=session.user_id,
            created_at=datetime.now(UTC).isoformat(),
            idempotency_hash=digest(str(parsed)),
            plan=plan,
        )
        self.backend.save_journal(rid, self.signer.seal(intent.model_dump()), None)
        stored = self.backend.journal(rid)
        if not stored:
            raise PortalError(
                503,
                "SETUP_PENDING",
                "Setup reservation is pending; recover the same operation.",
                True,
            )
        self.verified(stored[1], rid)
        return self.get(session, app_id, rid)

    def verified(self, record, rid):
        try:
            intent = SetupIntent.model_validate(self.signer.verify(record))
            if (
                intent.setup_id != rid
                or intent.issuer_id != self.backend.config.issuer_id
                or intent.platform_repository_id != self.backend.config.platform_repository_id
            ):
                raise ValueError("Wrong setup audience")
            return intent
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                503, "SETUP_JOURNAL_INVALID", "The setup request could not be verified."
            ) from exc

    def get(self, session, app_id, rid, *, context=None):
        if not re.fullmatch(r"setup-[0-9a-f]{64}", rid):
            raise PortalError(404, "SETUP_NOT_FOUND", "Setup is unavailable.")
        entry, revision, delivery, policy, current = context or self.context(session, app_id)
        raw = self.backend.journal(rid)
        if not raw:
            raise PortalError(404, "SETUP_NOT_FOUND", "Setup is unavailable.")
        intent = self.verified(raw[1], rid)
        if intent.plan.app_id != app_id:
            raise PortalError(404, "SETUP_NOT_FOUND", "Setup is unavailable.")
        plan = intent.plan
        if (
            plan.catalog_entry_hash != current.catalog_entry_hash
            or plan.delivery_policy_hash != current.delivery_policy_hash
            or plan.setup_policy_hash != current.setup_policy_hash
        ):
            raise PortalError(
                409, "SETUP_POLICY_CHANGED", "Approved settings changed. Review a new setup plan."
            )
        prs = self.backend.setup_prs(entry, rid, plan, policy)
        existing = self.backend.setup_files(entry, current)
        pipeline_ready = all(
            plan_bytes_equal(p, existing["source"].get(p), v)
            for p, v in plan.workflow_files.items()
        )
        target_committed = all(
            plan_bytes_equal(p, existing["target"].get(p), v) for p, v in plan.target_files.items()
        )
        observed, _sha = self.backend.setup_observation(entry, plan, delivery, policy)
        releases = self.backend.delivery_releases(session, app_id, "dev", 1)["items"]
        eligible = [r for r in releases if r.get("eligible")]
        cached = [
            r
            for r in eligible
            if self.backend.setup_release_cache_ready(entry, r["release_id"], delivery)
        ]
        job_state = self.backend.setup_job_evidence(raw[0], policy)
        ci = self.backend.setup_ci_result(entry, current.source_commit, prs.get("pipeline"))
        worker_online = self.backend.setup_heartbeat(revision, delivery, policy)
        state = (
            "ready"
            if pipeline_ready and target_committed and observed and cached
            else "building"
            if pipeline_ready and target_committed and observed
            else "awaiting_review"
            if any(
                not p["merged"] and p["state"] == "open" and not p.get("approved")
                for p in prs.values()
            )
            else "needs_attention"
            if job_state in {"error", "failure"}
            else "preparing"
            if worker_online
            else "queued"
        )
        can_replan = current.source_commit != plan.source_commit and not pipeline_ready
        if can_replan or (
            ci
            and ci["status"] == "completed"
            and ci["conclusion"] in {"failure", "cancelled", "timed_out", "action_required"}
        ):
            state = "needs_attention"
        token = self.signer.review_token(
            {
                "kind": "setup_pr_approval",
                "user_id": session.user_id,
                "setup_id": rid,
                "heads": {
                    k: p["head"] for k, p in prs.items() if not p["merged"] and p["state"] == "open"
                },
            }
        )
        can_approve_target = False
        try:
            can_approve_target = (
                session.user_id in policy.operator_user_ids and self.backend.owner_allowed(session)
            )
        except PortalError:
            pass
        return {
            "setup_id": rid,
            "app_id": app_id,
            "state": state,
            "can_replan": can_replan,
            "ci": ci,
            "worker_online": worker_online,
            "pipeline_ready": pipeline_ready,
            "target_committed": target_committed,
            "target_ready": observed,
            "release_ready": bool(cached),
            "releases": eligible,
            "pull_requests": prs,
            "can_approve_pipeline": True,
            "can_approve_target": can_approve_target,
            "approval_token": token,
            "workflow_files": file_rows(plan.workflow_files, existing["source"]),
            "target_files": file_rows(plan.target_files, existing["target"]),
            "notice": "Setup does not deploy. Select a validated release "
            "and confirm DEV deployment when ready.",
        }

    def latest(self, session, app_id):
        context = self.context(session, app_id)
        values = []
        for rid, record in self.backend.setup_records():
            intent = self.verified(record, rid)
            if intent.plan.app_id == app_id:
                values.append(intent)
        if not values:
            return {
                "app_id": app_id,
                "state": "not_started",
                "setup_id": None,
                "pipeline_ready": False,
                "target_ready": False,
                "release_ready": False,
            }
        latest = max(values, key=lambda value: value.created_at)
        try:
            return self.get(session, app_id, latest.setup_id, context=context)
        except PortalError as exc:
            if exc.code != "SETUP_POLICY_CHANGED":
                raise
            return {
                "app_id": app_id,
                "setup_id": latest.setup_id,
                "state": "needs_attention",
                "pipeline_ready": False,
                "target_ready": False,
                "release_ready": False,
                "message": exc.message,
                "can_replan": True,
            }

    def approve(self, session, app_id, rid, token):
        result = self.get(session, app_id, rid)
        try:
            signed = self.signer.read_review(token)
            expected = self.signer.read_review(result["approval_token"])
            if {k: v for k, v in signed.items() if k != "expires_at"} != {
                k: v for k, v in expected.items() if k != "expires_at"
            }:
                raise ValueError("Proposal changed")
        except (ValueError, KeyError, TypeError):
            raise PortalError(
                409, "SETUP_REVIEW_CHANGED", "Setup proposals changed. Refresh and review again."
            ) from None
        for kind, pr in result["pull_requests"].items():
            if kind == "target" and not result["can_approve_target"]:
                continue
            if kind == "target":
                self.backend.owner_context(session)
            if pr["merged"] or pr["state"] != "open":
                continue
            repo = pr["repository"]
            metadata = self.backend.api("GET", f"/repos/{repo}", session.user_token).json()
            if metadata.get("permissions", {}).get("push") is not True:
                raise PortalError(
                    403,
                    "SETUP_REVIEW_FORBIDDEN",
                    "Current repository maintainer access is required.",
                )
            latest = self.backend.api(
                "GET", f"/repos/{repo}/pulls/{pr['number']}", session.user_token
            ).json()
            if latest["head"]["sha"] != pr["head"] or str(latest["user"]["id"]) == session.user_id:
                raise PortalError(
                    409,
                    "SETUP_REVIEW_CHANGED",
                    "An independent review of the current proposal is required.",
                )
            self.backend.api(
                "POST",
                f"/repos/{repo}/pulls/{pr['number']}/reviews",
                session.user_token,
                json={
                    "commit_id": pr["head"],
                    "event": "APPROVE",
                    "body": "Reviewed DEV preparation through the portal. "
                    "This does not authorize deployment.",
                },
            )
        return self.get(session, app_id, rid)
