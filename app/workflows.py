"""Human-attributed reviews and ordinary protected merges inside the portal."""

import difflib
import hashlib
import re
from typing import Literal
from urllib.parse import quote

from aegis_platform.canonical import digest, strict_json
from aegis_platform.contracts import CatalogEntry, Contract
from aegis_platform.delivery import DeliveryPolicy, verify_production_approval
from pydantic import Field

from app.errors import PortalError


class WorkflowSubmission(Contract):
    action: Literal["approve", "request_changes", "merge"]
    review_token: str = Field(min_length=20, max_length=16384)
    operation_key: str = Field(pattern=r"^[a-zA-Z0-9-]{16,80}$")
    reason: str = Field(default="", max_length=2000)
    acknowledge: Literal[True]


def review_file(path, before, after, status, previous_path=None):
    def identity(raw):
        return (
            None if raw is None else {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        )

    row = {
        "path": path,
        "previous_path": previous_path,
        "status": status,
        "before": identity(before),
        "after": identity(after),
    }
    try:
        old, new = (before or b"").decode("utf-8"), (after or b"").decode("utf-8")
        if "\x00" in old or "\x00" in new:
            raise UnicodeError("Binary content")
        row.update(
            binary=False,
            diff="".join(
                difflib.unified_diff(
                    old.splitlines(keepends=True),
                    new.splitlines(keepends=True),
                    fromfile=previous_path or path,
                    tofile=path,
                )
            ),
        )
    except UnicodeError:
        row.update(binary=True, diff="Binary change: review byte sizes and SHA-256 identities.")
    return row


class WorkflowService:
    def __init__(self, backend, signer):
        self.backend, self.signer = backend, signer

    def context(self, session, repository, number):
        if not hasattr(self.backend, "owner_context"):
            raise PortalError(503, "REVIEW_SETUP_REQUIRED", "Reviews require live GitHub sign-in.")
        backend, config = self.backend, self.backend.config
        revision, _, policy_token = backend.owner_context(session)
        policy = DeliveryPolicy.model_validate(
            strict_json(
                backend.file(
                    config.platform_repository, "policies/delivery.json", revision, policy_token
                )
            )
        )
        if policy.platform_repository_id != config.platform_repository_id:
            raise PortalError(503, "REVIEW_SETUP_INVALID", "Platform policy identity differs.")
        if repository == "platform":
            repo, repo_id, branches = (
                config.platform_repository,
                config.platform_repository_id,
                {"main"},
            )
        elif repository == "gitops":
            repo, repo_id, branches = (
                policy.gitops_repository,
                policy.gitops_repository_id,
                {"main", "staging", "prod", "platform-system"},
            )
            if repo != config.gitops_repository or repo_id != config.gitops_repository_id:
                raise PortalError(503, "REVIEW_SETUP_INVALID", "GitOps policy identity differs.")
        elif repository == "portal":
            entry = CatalogEntry.model_validate(
                strict_json(
                    backend.file(
                        config.platform_repository,
                        "catalog/apps/aegis-portal.json",
                        revision,
                        policy_token,
                    )
                )
            )
            repo, repo_id, branches = (
                entry.source.owner + "/" + entry.source.name,
                entry.source.repository_id,
                {"main"},
            )
        else:
            raise PortalError(404, "REVIEW_NOT_FOUND", "Unknown review repository.")
        # User tokens retain the human principal. No installation token may review or merge.
        user = backend.api("GET", "/user", session.user_token).json()
        if str(user.get("id")) != session.user_id or user.get("type") != "User":
            raise PortalError(
                403, "REVIEW_IDENTITY_INVALID", "Sign in with your human GitHub identity."
            )
        metadata = backend.api("GET", f"/repos/{repo}", session.user_token).json()
        if (
            str(metadata.get("id")) != repo_id
            or metadata.get("permissions", {}).get("push") is not True
        ):
            raise PortalError(
                403, "REVIEW_FORBIDDEN", "Current repository maintainer access is required."
            )
        pr = backend.api("GET", f"/repos/{repo}/pulls/{number}", session.user_token).json()
        if (
            pr["base"]["ref"] not in branches
            or str(pr["base"]["repo"]["id"]) != repo_id
            or str(pr["head"]["repo"]["id"]) != repo_id
            or not re.fullmatch(r"[0-9a-f]{40}", pr["head"]["sha"])
            or not re.fullmatch(r"[0-9a-f]{40}", pr["base"]["sha"])
        ):
            raise PortalError(
                403,
                "REVIEW_SCOPE_INVALID",
                "Proposal is outside the supported repository and branch scope.",
            )
        if (
            pr["base"]["ref"] == "prod"
            and session.user_id not in policy.production_reviewer_user_ids
        ):
            raise PortalError(
                403, "REVIEW_FORBIDDEN", "Production requires a reviewed production reviewer grant."
            )
        if pr["base"]["ref"] == "platform-system":
            system = strict_json(
                backend.file(
                    config.platform_repository,
                    "policies/portal-system.json",
                    revision,
                    policy_token,
                )
            )
            if session.user_id not in system["operator_user_ids"]:
                raise PortalError(
                    403, "REVIEW_FORBIDDEN", "System changes require a reviewed operator grant."
                )
            policy = policy.model_copy(
                update={"production_reviewer_user_ids": system["operator_user_ids"]}
            )
        return revision, repo, repo_id, pr, policy

    def details(self, session, repository, number):
        revision, repo, repo_id, pr, _ = self.context(session, repository, number)
        backend = self.backend
        files = backend.paginate(f"/repos/{repo}/pulls/{number}/files", session.user_token)
        if len(files) != pr["changed_files"] or len(files) > 64:
            raise PortalError(
                422, "REVIEW_TOO_LARGE", "This proposal exceeds the 64-file portal review limit."
            )
        rows, size = [], 0
        for file in files:
            path, status = file["filename"], file["status"]
            if status not in {"added", "modified", "removed", "renamed"}:
                raise PortalError(
                    422, "REVIEW_UNSUPPORTED", "This change cannot be represented completely."
                )
            old_path = file.get("previous_filename", path)
            before = (
                None
                if status == "added"
                else backend.file(
                    repo,
                    old_path,
                    pr["base"]["sha"],
                    session.user_token,
                    max_size=262144,
                )
            )
            after = (
                None
                if status == "removed"
                else backend.file(
                    repo,
                    path,
                    pr["head"]["sha"],
                    session.user_token,
                    max_size=262144,
                )
            )
            if (before is None and status != "added") or (after is None and status != "removed"):
                raise PortalError(
                    409, "REVIEW_CONTENT_MISSING", "Full changed file content is unavailable."
                )
            size += len(before or b"") + len(after or b"")
            if size > 1048576:
                raise PortalError(
                    422,
                    "REVIEW_TOO_LARGE",
                    "This proposal exceeds the complete content review budget.",
                )
            rows.append(review_file(path, before, after, status, file.get("previous_filename")))
        # Refetch after reading files: a moved head must never receive a token for mixed content.
        latest = backend.api("GET", f"/repos/{repo}/pulls/{number}", session.user_token).json()
        if latest["head"]["sha"] != pr["head"]["sha"] or latest["base"]["sha"] != pr["base"]["sha"]:
            raise PortalError(
                409, "REVIEW_CHANGED", "Proposal changed while loading. Refresh the review."
            )
        reviews = backend.paginate(f"/repos/{repo}/pulls/{number}/reviews", session.user_token)
        binding = {
            "kind": "portal_human_review",
            "user_id": session.user_id,
            "repository": repository,
            "repository_id": repo_id,
            "number": number,
            "head": pr["head"]["sha"],
            "base": pr["base"]["sha"],
            "policy_revision": revision,
            "files_hash": digest(rows),
        }
        independent = str(pr["user"]["id"]) != session.user_id
        open_pr = pr["state"] == "open" and not pr.get("draft")
        return {
            "repository": repository,
            "number": number,
            "title": pr["title"],
            "head": binding["head"],
            "base": binding["base"],
            "branch": pr["base"]["ref"],
            "state": pr["state"],
            "merged": bool(pr.get("merged_at")),
            "files": rows,
            "content_hash": binding["files_hash"],
            "can_review": open_pr and independent,
            "can_merge": open_pr,
            "review_token": self.signer.review_token(binding),
            "reviews": [
                {"user": r["user"]["login"], "state": r["state"], "commit": r.get("commit_id")}
                for r in reviews
            ],
            "binding": binding,
        }

    def submit(self, session, repository, number, fields):
        try:
            expected = self.signer.read_review(fields.review_token)
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                409, "REVIEW_EXPIRED", "Refresh the review before confirming."
            ) from exc
        current = self.details(session, repository, number)
        if {k: v for k, v in expected.items() if k != "expires_at"} != current["binding"]:
            raise PortalError(
                409, "REVIEW_CHANGED", "Proposal or permissions changed. Review the current files."
            )
        _, repo, _, pr, policy = self.context(session, repository, number)
        if pr["head"]["sha"] != current["head"] or pr["base"]["sha"] != current["base"]:
            raise PortalError(409, "REVIEW_CHANGED", "Proposal changed. Review the current files.")
        if pr.get("merged_at") and fields.action == "merge":
            return {"status": "merged", "head": current["head"], "recovered": True}
        if pr["state"] != "open" or pr.get("draft"):
            raise PortalError(
                409, "REVIEW_CLOSED", "Refresh the current proposal state before acting."
            )
        if fields.action == "merge":
            if not current["can_merge"]:
                raise PortalError(
                    409, "REVIEW_CLOSED", "Only an open, non-draft proposal may merge."
                )
            branch = self.backend.api(
                "GET",
                f"/repos/{repo}/branches/{quote(pr['base']['ref'], safe='')}",
                session.user_token,
            ).json()
            if branch.get("protected") is not True:
                raise PortalError(
                    409, "MERGE_POLICY_REQUIRED", "Enable protected branch checks before merging."
                )
            if pr["base"]["ref"] in {"prod", "platform-system"}:
                reviews = self.backend.paginate(
                    f"/repos/{repo}/pulls/{number}/reviews", session.user_token
                )
                try:
                    verify_production_approval(pr, reviews, policy)
                except (ValueError, KeyError, TypeError) as exc:
                    raise PortalError(
                        409,
                        "INDEPENDENT_REVIEW_REQUIRED",
                        "An authorized independent human must approve this exact revision.",
                    ) from exc
            response = self.backend.api(
                "PUT",
                f"/repos/{repo}/pulls/{number}/merge",
                session.user_token,
                allow=(403, 405, 409, 422),
                json={"sha": current["head"], "merge_method": "squash"},
            )
            if response.status_code in {403, 405, 409, 422}:
                raise PortalError(
                    409,
                    "MERGE_BLOCKED",
                    "Merge is blocked by current checks, reviews, conflicts or branch policy. "
                    "Refresh after they resolve.",
                )
            data = response.json()
            if data.get("merged") is not True:
                raise PortalError(
                    409, "MERGE_BLOCKED", "GitHub has not confirmed the protected merge."
                )
            return {"status": "merged", "head": current["head"], "merge_commit": data["sha"]}
        if not current["can_review"]:
            raise PortalError(
                403,
                "INDEPENDENT_REVIEW_REQUIRED",
                "An independent human must review an open, non-draft proposal.",
            )
        if fields.action == "request_changes" and not fields.reason.strip():
            raise PortalError(422, "REVIEW_REASON_REQUIRED", "Explain which changes are required.")
        event = "APPROVE" if fields.action == "approve" else "REQUEST_CHANGES"
        marker = "Aegis portal operation: " + digest(
            [session.user_id, repository, number, fields.operation_key]
        )
        body = (
            fields.reason.strip()
            + "\n\n"
            + marker
            + "\nIntent: "
            + digest([current["head"], fields.action, fields.reason])
        )
        reviews = self.backend.paginate(f"/repos/{repo}/pulls/{number}/reviews", session.user_token)
        matches = [
            r
            for r in reviews
            if str(r["user"]["id"]) == session.user_id
            and marker in (r.get("body") or "").splitlines()
        ]
        if matches and (
            len(matches) != 1
            or matches[0].get("body") != body
            or matches[0].get("commit_id") != current["head"]
            or matches[0].get("state")
            != {"APPROVE": "APPROVED", "REQUEST_CHANGES": "CHANGES_REQUESTED"}[event]
        ):
            raise PortalError(
                409,
                "REVIEW_OPERATION_CHANGED",
                "This review operation changed or was dismissed. Refresh before a new decision.",
            )
        review = (
            matches[-1]
            if matches
            else self.backend.api(
                "POST",
                f"/repos/{repo}/pulls/{number}/reviews",
                session.user_token,
                json={"commit_id": current["head"], "event": event, "body": body},
            ).json()
        )
        if (
            str(review["user"]["id"]) != session.user_id
            or review["user"].get("type") != "User"
            or review.get("commit_id") != current["head"]
        ):
            raise PortalError(
                503,
                "REVIEW_READBACK_INVALID",
                "Review identity could not be verified. Refresh before retrying.",
            )
        return {
            "status": review["state"].lower(),
            "review_id": str(review["id"]),
            "head": current["head"],
            "reviewer_user_id": session.user_id,
            "recovered": bool(matches),
        }
