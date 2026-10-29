"""Authorized registration proposals. Registration never deploys workloads."""

import threading
from datetime import UTC, datetime

from app.config import LiveConfig
from app.contracts import CatalogEntry, RegistrationFields, RegistrationSubmission
from app.errors import PortalError
from app.security import Session, Signer, digest, operation_id
from app.setup import file_rows
from app.setup_contracts import SetupIntent


class RegistrationService:
    def __init__(self, config: LiveConfig, backend, signer: Signer):
        self.config = config
        self.backend = backend
        self.signer = signer
        self.lock = threading.RLock()

    def authorize(self, session: Session, fields: RegistrationFields) -> dict:
        if session.user_id not in self.config.onboarding_user_ids:
            raise PortalError(
                403, "ONBOARDING_FORBIDDEN", "Your identity is not enabled for onboarding."
            )
        # First increment assigns the signed-in, verified individual as owner.
        if (
            fields.owner_user_ids != [session.user_id]
            or session.user_id not in self.config.allowed_owner_user_ids
        ):
            raise PortalError(
                403,
                "OWNER_FORBIDDEN",
                "Initial registrations must be owned by your verified identity.",
            )
        if fields.runtime.resource_profile_id not in self.config.resource_profiles:
            raise PortalError(422, "PROFILE_UNSUPPORTED", "Choose an approved resource profile.")
        return self.backend.source(session, fields.repository_id)

    def policy_hash(self) -> str:
        return digest(self.config.model_dump())

    def setup_review(self, fields, source):
        if not hasattr(self.backend, "registration_setup_plan"):
            return None, None
        plan, existing = self.backend.registration_setup_plan(self.entry(fields, source), source)
        files = file_rows(plan.workflow_files, existing["source"])
        targets = file_rows(plan.target_files, existing["target"])
        blockers = [
            "Existing file requires a maintainer decision: " + f["path"]
            for f in files + targets
            if f["status"] == "conflict"
        ]
        blockers += [
            "Missing required source file: " + p
            for p in ("Dockerfile", "requirements.txt", "requirements-prod.txt")
            if existing["source"].get(p) is None
        ]
        return plan, {
            "workflow_files": files,
            "target_files": targets,
            "blockers": blockers,
            "notice": "Submitting authorizes these proposals after catalog approval. "
            "Required owner reviews remain separate. Nothing deploys.",
        }

    def unique(self, fields: RegistrationFields, exclude: str | None = None):
        entries = [
            CatalogEntry.model_validate(item).model_dump() for item in self.backend.catalog()
        ]
        for item in entries:
            if (
                item["app_id"] == fields.app_id
                or item["source"]["repository_id"] == fields.repository_id
            ):
                raise PortalError(
                    409, "ALREADY_REGISTERED", "Application ID or repository is already registered."
                )
        for rid in self.backend.journal_ids():
            if rid == exclude:
                continue
            raw = self.backend.journal(rid)
            if raw is None:
                continue
            payload = self.verified(raw[1], rid)
            other = payload["fields"]
            if other["app_id"] == fields.app_id or other["repository_id"] == fields.repository_id:
                # Do not reveal another principal's pending registration.
                raise PortalError(
                    409,
                    "REGISTRATION_CONFLICT",
                    "Application ID or repository has an existing registration reservation.",
                )

    def preview(self, session: Session, fields: RegistrationFields) -> dict:
        with self.lock:
            source = self.authorize(session, fields)
            self.unique(fields)
            detection = self.backend.detection(source)
            setup_plan, setup_review = self.setup_review(fields, source)
            payload = fields.model_dump()
            token = self.signer.review_token(
                {
                    "kind": "registration_review",
                    "principal_id": session.user_id,
                    "payload_hash": digest(payload),
                    "source_commit": source["source_commit"],
                    "policy_hash": self.policy_hash(),
                    **({"setup_plan_hash": digest(setup_plan.model_dump())} if setup_plan else {}),
                }
            )
            return {
                "fields": payload,
                "source": source,
                "detection": detection,
                "delivery": {"environment": "dev", "mode": "manual"},
                "review_token": token,
                "expires_in_seconds": 300,
                "automatic_setup": setup_review,
            }

    def entry(self, fields: RegistrationFields, source: dict) -> dict:
        app_id = fields.app_id
        return CatalogEntry.model_validate(
            {
                "schema_version": 1,
                "app_id": app_id,
                "display_name": fields.display_name,
                "source": {
                    k: source[k]
                    for k in ("repository_id", "installation_id", "owner", "name", "default_branch")
                },
                "access": {
                    "owner_user_ids": fields.owner_user_ids,
                    "viewer_user_ids": [],
                    "deployer_user_ids_by_environment": {"dev": fields.owner_user_ids},
                },
                "runtime": fields.runtime.model_dump(),
                "versions": self.config.versions.model_dump(),
                "environments": {
                    "dev": {
                        "delivery_mode": "manual",
                        "cluster_id": self.config.cluster_id,
                        "cluster_uid": self.config.cluster_uid,
                        "namespace": f"aegis-{app_id}-dev",
                        "argo_application": f"{app_id}-dev",
                        "argo_project": f"{app_id}-dev",
                        "gitops_repository_id": self.config.gitops_repository_id,
                        "gitops_branch": "main",
                        "values_path": f"applications/{app_id}/environments/dev/values.yaml",
                        "access_mapping_id": None,
                    }
                },
            }
        ).model_dump()

    def verified(self, record: dict, rid: str) -> dict:
        try:
            payload = self.signer.verify(record)
            if (
                payload["registration_id"] != rid
                or payload["issuer_id"] != self.config.issuer_id
                or payload["platform_repository_id"] != self.config.platform_repository_id
            ):
                raise ValueError("Journal audience mismatch")
            return payload
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                503, "JOURNAL_INVALID", "Registration journal could not be verified."
            ) from exc

    def submit(self, session: Session, submission: RegistrationSubmission, key: str) -> dict:
        fields = RegistrationFields.model_validate(submission.model_dump(exclude={"review_token"}))
        rid = operation_id(self.config.issuer_id, session.user_id, "registration", key)
        with self.lock:
            source = self.authorize(session, fields)
            existing = self.backend.journal(rid)
            if existing:
                payload = self.verified(existing[1], rid)
                if payload["requester_user_id"] != session.user_id or payload[
                    "payload_hash"
                ] != digest(fields.model_dump()):
                    raise PortalError(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "This key belongs to a different confirmed registration.",
                    )
                if payload["binding"]:
                    return self.result(payload)
            else:
                self.unique(fields)
                setup_plan, setup_review = self.setup_review(fields, source)
                if setup_review and setup_review["blockers"]:
                    raise PortalError(
                        409, "SETUP_BLOCKED", "Resolve the setup requirements before submitting."
                    )
                try:
                    review = self.signer.read_review(submission.review_token)
                except (ValueError, KeyError, TypeError) as exc:
                    raise PortalError(
                        409,
                        "REVIEW_REQUIRED",
                        "Registration review expired or is invalid; validate again.",
                    ) from exc
                expected = {
                    "kind": "registration_review",
                    "principal_id": session.user_id,
                    "payload_hash": digest(fields.model_dump()),
                    "source_commit": source["source_commit"],
                    "policy_hash": self.policy_hash(),
                    **({"setup_plan_hash": digest(setup_plan.model_dump())} if setup_plan else {}),
                }
                if {k: review.get(k) for k in expected} != expected:
                    raise PortalError(
                        409,
                        "REVIEW_REQUIRED",
                        "Source, settings or policy changed; validate again.",
                    )
                payload = {
                    "schema_version": 1,
                    "registration_id": rid,
                    "issuer_id": self.config.issuer_id,
                    "platform_repository_id": self.config.platform_repository_id,
                    "requester_user_id": session.user_id,
                    "created_at": datetime.now(UTC).isoformat(),
                    "idempotency_key_hash": digest(key),
                    "payload_hash": digest(fields.model_dump()),
                    "policy_hash": self.policy_hash(),
                    "source_commit": source["source_commit"],
                    "fields": fields.model_dump(),
                    "catalog_entry": self.entry(fields, source),
                    "binding": None,
                }
                if setup_plan:
                    payload["setup_intent"] = SetupIntent(
                        setup_id="setup-" + rid[4:],
                        issuer_id=self.config.issuer_id,
                        platform_repository_id=self.config.platform_repository_id,
                        requester_user_id=session.user_id,
                        created_at=payload["created_at"],
                        idempotency_hash=payload["idempotency_key_hash"],
                        plan=setup_plan,
                    ).model_dump()
                if not self.backend.save_journal(rid, self.signer.seal(payload), None):
                    existing = self.backend.journal(rid)
                    if existing is None:
                        raise PortalError(
                            503, "RESERVATION_PENDING", "Retry the same registration key.", True
                        )
                    payload = self.verified(existing[1], rid)
                    if payload["payload_hash"] != digest(fields.model_dump()):
                        raise PortalError(
                            409, "IDEMPOTENCY_CONFLICT", "Conflicting registration key."
                        )
            if (
                payload["policy_hash"] != self.policy_hash()
                or payload["source_commit"] != source["source_commit"]
            ):
                raise PortalError(
                    409,
                    "REVIEW_REQUIRED",
                    "Source or policy changed; operator reconciliation is needed.",
                )
            self.unique(fields, exclude=rid)
            binding = self.backend.registration_pr(rid, payload["catalog_entry"])
            latest = self.backend.journal(rid)
            if latest is None:
                raise PortalError(503, "JOURNAL_INVALID", "Registration reservation disappeared.")
            latest_payload = self.verified(latest[1], rid)
            if latest_payload["binding"]:
                return self.result(latest_payload)
            updated = {**latest_payload, "binding": binding}
            if not self.backend.save_journal(rid, self.signer.seal(updated), latest[0]):
                winner = self.backend.journal(rid)
                if winner and self.verified(winner[1], rid)["binding"]:
                    return self.result(self.verified(winner[1], rid))
                raise PortalError(
                    503,
                    "BINDING_PENDING",
                    "PR may exist; retry with the same key to recover.",
                    True,
                )
            return self.result(updated)

    def result(self, payload: dict) -> dict:
        binding = (
            self.backend.registration_status(payload["binding"]) if payload["binding"] else None
        )
        catalog_status = "pending_review"
        if binding and binding.get("merged"):
            catalog_status = "approved"
        elif binding and binding.get("state") == "closed":
            catalog_status = "closed_unmerged"
        return {
            "registration_id": payload["registration_id"],
            "app_id": payload["fields"]["app_id"],
            "display_name": payload["fields"]["display_name"],
            "created_at": payload["created_at"],
            "status_observed_at": datetime.now(UTC).isoformat(),
            "fields": payload["fields"],
            "pull_request": binding,
            "requirements": [
                {
                    "name": "Catalog review",
                    "status": catalog_status if binding else "pending_pr",
                    "actor": "Platform maintainer",
                },
                {"name": "Pipeline setup", "status": "validation_required", "actor": "Developer"},
                {
                    "name": "Target setup",
                    "status": "operator_setup_required",
                    "actor": "Local operator",
                },
                {"name": "Validated release", "status": "not_verified", "actor": "Application CI"},
            ],
            "deployment_available": False,
            "automatic_setup": bool(payload.get("setup_intent")),
        }

    def get(self, session: Session, rid: str) -> dict:
        raw = self.backend.journal(rid)
        if raw is None:
            raise PortalError(404, "REGISTRATION_NOT_FOUND", "Registration is unavailable.")
        payload = self.verified(raw[1], rid)
        if payload["requester_user_id"] != session.user_id:
            raise PortalError(404, "REGISTRATION_NOT_FOUND", "Registration is unavailable.")
        fields = RegistrationFields.model_validate(payload["fields"])
        self.authorize(session, fields)
        return self.result(payload)

    def list(self, session: Session) -> list[dict]:
        records = []
        for rid in self.backend.journal_ids():
            raw = self.backend.journal(rid)
            if raw and self.verified(raw[1], rid)["requester_user_id"] == session.user_id:
                try:
                    records.append(self.get(session, rid))
                except PortalError as exc:
                    if exc.status not in {403, 404}:
                        raise
        return sorted(records, key=lambda r: r["created_at"], reverse=True)
