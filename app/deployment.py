"""Reviewed, signed delivery requests. This service never merges or syncs deployments."""

import threading
from datetime import UTC, datetime

from aegis_platform.canonical import digest
from aegis_platform.contracts import DeploymentIntent
from aegis_platform.delivery import DeploymentFields, DeploymentSubmission, request_id

from app.errors import PortalError
from app.security import Session, Signer


class DeploymentService:
    def __init__(self, config, backend, signer: Signer):
        self.config, self.backend, self.signer = config, backend, signer
        self.lock = threading.RLock()

    def latest_for_app(self, session, app_id):
        self.backend.delivery_authorize(session, app_id, "dev")
        candidates = []
        for rid, record in self.backend.delivery_records():
            payload = self.verified(record, rid)
            intent = payload["intent"]
            if (
                intent["app_id"] == app_id
                and intent["environment"] == "dev"
                and intent["requester_user_id"] == session.user_id
            ):
                candidates.append(intent)
        if not candidates:
            return None
        latest = max(candidates, key=lambda i: datetime.fromisoformat(i["created_at"]))
        return self.get(session, latest["request_id"])

    def pipeline_status(self, session, app_id, run):
        candidates = []
        for rid, record in self.backend.delivery_records():
            payload = self.verified(record, rid)
            intent = payload["intent"]
            if (
                intent["requester_user_id"] == session.user_id
                and intent["app_id"] == app_id
                and intent["environment"] == "dev"
                and intent["source_commit"] == run["head_sha"]
                and str(intent["release_workflow_run_id"]) == str(run["id"])
            ):
                candidates.append(payload)
        if not candidates:
            return None
        latest = max(candidates, key=lambda p: datetime.fromisoformat(p["intent"]["created_at"]))
        entry, _revision, policy = self.backend.delivery_authorize(session, app_id, "dev")
        evidence, _raw, _release = self.backend.admitted_release(
            entry, latest["intent"]["release_id"], policy
        )
        if str(evidence.run_attempt) != str(run["run_attempt"]):
            return None
        return self.get(session, latest["intent"]["request_id"])

    def enabled(self):
        if not self.config.delivery_workflow_commit:
            raise PortalError(
                503,
                "DELIVERY_SETUP_REQUIRED",
                "Delivery requires the approved GitOps request workflow and observer setup.",
            )

    def verified(self, record: dict, rid: str) -> dict:
        try:
            payload = self.signer.verify(record)
            intent = DeploymentIntent.model_validate(payload["intent"])
            if (
                set(payload) != {"kind", "intent", "binding"}
                or payload["kind"] != "deployment_request"
                or intent.request_id != rid
                or intent.issuer_id != self.config.issuer_id
                or intent.platform_repository_id != self.config.platform_repository_id
            ):
                raise ValueError("Request audience mismatch")
            return payload
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                503, "JOURNAL_INVALID", "Delivery request could not be verified."
            ) from exc

    def preview(self, session: Session, fields: DeploymentFields) -> dict:
        self.enabled()
        context = self.backend.delivery_context(session, fields)
        review = {
            "kind": "deployment_review",
            "principal_id": session.user_id,
            "payload_hash": digest(fields.model_dump()),
            "context_hash": digest(context),
        }
        return {
            "fields": fields.model_dump(),
            "context": context,
            "review_token": self.signer.review_token(review),
            "expires_in_seconds": 300,
            "requires_human_approval": fields.environment == "prod",
            "requires_operator_sync": fields.environment != "dev",
        }

    def submit(self, session: Session, submission: DeploymentSubmission, key: str) -> dict:
        self.enabled()
        fields = DeploymentFields.model_validate(submission.model_dump(exclude={"review_token"}))
        rid = request_id(self.config.issuer_id, session.user_id, key)
        with self.lock:
            existing = self.backend.journal(rid)
            if existing:
                payload = self.verified(existing[1], rid)
                intent = payload["intent"]
                if intent["requester_user_id"] != session.user_id or intent[
                    "payload_hash"
                ] != digest(fields.model_dump()):
                    raise PortalError(
                        409, "IDEMPOTENCY_CONFLICT", "Key belongs to another request."
                    )
                # Read authorization is rechecked even for a completed retry. A changed
                # desired state does not erase an already acknowledged durable request.
                self.backend.delivery_authorize(session, fields.app_id, fields.environment)
                if payload["binding"]:
                    return self.acknowledge(payload)
            else:
                context = self.backend.delivery_context(session, fields)
                try:
                    review = self.signer.read_review(submission.review_token)
                except (ValueError, KeyError, TypeError) as exc:
                    raise PortalError(
                        409, "REVIEW_REQUIRED", "Review expired; preview again."
                    ) from exc
                expected = {
                    "kind": "deployment_review",
                    "principal_id": session.user_id,
                    "payload_hash": digest(fields.model_dump()),
                    "context_hash": digest(context),
                }
                if any(review.get(k) != value for k, value in expected.items()):
                    raise PortalError(
                        409, "REVIEW_REQUIRED", "Delivery inputs changed; preview again."
                    )
                intent = DeploymentIntent.model_validate(
                    {
                        "schema_version": 1,
                        "request_id": rid,
                        "issuer_id": self.config.issuer_id,
                        "platform_repository_id": self.config.platform_repository_id,
                        "requester_user_id": session.user_id,
                        "created_at": datetime.now(UTC).isoformat(),
                        "idempotency_key_hash": digest(key),
                        "payload_hash": digest(fields.model_dump()),
                        **fields.model_dump(),
                        "operation": "deploy" if fields.environment == "dev" else "promote",
                        "origin": "portal",
                        **{
                            k: context[k]
                            for k in (
                                "catalog_revision",
                                "catalog_entry_hash",
                                "resolved_policy_hash",
                                "source_repository_id",
                                "source_commit",
                                "release_workflow_run_id",
                                "release_evidence_hash",
                                "image_root_digest",
                                "platform_digests",
                                "expected_desired_fingerprint",
                                "expected_intent_anchor",
                                "prior_environment_evidence",
                            )
                        },
                    }
                ).model_dump()
                payload = {"kind": "deployment_request", "intent": intent, "binding": None}
                if not self.backend.save_journal(rid, self.signer.seal(payload), None):
                    winner = self.backend.journal(rid)
                    if not winner:
                        raise PortalError(503, "REQUEST_PENDING", "Retry with the same key.", True)
                    payload = self.verified(winner[1], rid)
                    if payload["intent"]["payload_hash"] != digest(fields.model_dump()):
                        raise PortalError(409, "IDEMPOTENCY_CONFLICT", "Conflicting request key.")
            # Issue body is signed separately. A timeout after creation is recovered by
            # exact body/author matching; no search-index consistency assumption.
            body = self.signer.seal({"kind": "deployment_intent", "intent": payload["intent"]})
            binding = self.backend.delivery_issue(rid, body)
            latest = self.backend.journal(rid)
            if not latest:
                raise PortalError(503, "JOURNAL_INVALID", "Request reservation disappeared.")
            latest_payload = self.verified(latest[1], rid)
            if latest_payload["binding"]:
                return self.acknowledge(latest_payload)
            updated = {**latest_payload, "binding": binding}
            if not self.backend.save_journal(rid, self.signer.seal(updated), latest[0]):
                raise PortalError(503, "BINDING_PENDING", "Retry the same request key.", True)
            return self.acknowledge(updated)

    def acknowledge(self, payload: dict) -> dict:
        if hasattr(self.backend, "delivery_status"):
            observed = self.backend.delivery_status(payload["intent"])
            if observed.get("pull_request", {}).get("merged"):
                return self.result(payload)
        self.backend.delivery_dispatch(payload["intent"]["request_id"], payload["binding"])
        return self.result(payload)

    def result(self, payload: dict) -> dict:
        intent = payload["intent"]
        result = {
            "request_id": intent["request_id"],
            "app_id": intent["app_id"],
            "environment": intent["environment"],
            "created_at": intent["created_at"],
            "release_id": intent["release_id"],
            "image_root_digest": intent["image_root_digest"],
            "status": "accepted" if payload["binding"] else "reserving",
            "issue": payload["binding"],
            "requires_human_approval": intent["environment"] == "prod",
            "requires_operator_sync": intent["environment"] != "dev",
            "status_observed_at": datetime.now(UTC).isoformat(),
        }
        if payload["binding"] and hasattr(self.backend, "delivery_status"):
            result.update(self.backend.delivery_status(intent))
        return result

    def get(self, session: Session, rid: str) -> dict:
        raw = self.backend.journal(rid)
        if not raw:
            raise PortalError(404, "REQUEST_UNAVAILABLE", "Request is unavailable.")
        payload = self.verified(raw[1], rid)
        intent = payload["intent"]
        if intent["requester_user_id"] != session.user_id:
            raise PortalError(404, "REQUEST_UNAVAILABLE", "Request is unavailable.")
        self.backend.delivery_authorize(session, intent["app_id"], intent["environment"])
        return self.result(payload)
