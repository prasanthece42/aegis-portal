"""Read-only owner projection from reviewed Git and trusted observer evidence."""

import re
from collections import Counter
from datetime import UTC, datetime
from urllib.parse import quote

from aegis_platform.canonical import digest, strict_json
from aegis_platform.catalog import Catalog, CatalogPolicy, Cluster
from aegis_platform.contracts import CatalogEntry
from aegis_platform.delivery import DeliveryPolicy, timestamp, verify_status
from aegis_platform.portal_owner import PortalOwnerPolicy
from aegis_platform.release import validate_repository
from aegis_platform.request import RequestTrust, verify_record

from app.errors import PortalError


def repository_link(repository, path):
    return "https://github.com/" + validate_repository(repository) + "/" + path


def observation_state(statuses, entry, environment, current, policy, now):
    try:
        observed = verify_status(
            statuses,
            f"aegis/{entry.app_id}/{environment}-health",
            "Healthy " + current.fingerprint,
            current.intent_anchor,
            policy,
            now,
        )
    except (ValueError, KeyError, TypeError):
        return {"state": "unverified", "health_observed_at": None}
    return {
        "state": "stale"
        if (now - timestamp(observed["created_at"])).total_seconds() > 300
        else "healthy",
        "health_observed_at": observed["created_at"],
    }


def signed_activity(issue, trust):
    """Historical signature evidence, never a fresh admission or deployment authority."""
    number = int(issue["number"])
    result = {"issue_number": number, "integrity": "unverified", "request_id": None}
    try:
        raw = issue.get("body") or ""
        if len(raw.encode()) > 65536:
            raise ValueError("Oversized signed issue")
        payload, issuer = verify_record(strict_json(raw), trust, admission=False)
        intent = payload["intent"]
        if (
            set(payload) != {"kind", "intent"}
            or payload["kind"] != "deployment_intent"
            or issue.get("user", {}).get("type") != "Bot"
            or str(issue["user"]["id"]) != issuer.bot_user_id
            or "pull_request" in issue
            or issue.get("title") != "Aegis delivery " + intent["request_id"]
        ):
            raise ValueError("Signed issue identity differs")
        result.update(
            integrity="verified",
            request_id=intent["request_id"],
            app_id=intent["app_id"],
            environment=intent["environment"],
            release_id=intent["release_id"],
            source_commit=intent["source_commit"],
            created_at=intent["created_at"],
            requester_user_id=intent["requester_user_id"],
            issuer_active=issuer.active,
        )
    except (ValueError, KeyError, TypeError):
        pass
    return result


def reported_ci_state(checks, statuses):
    """Latest provider report wins; this is not a branch-protection verdict."""
    latest_checks, latest_statuses = {}, {}
    for check in checks:
        key = (check["name"], check.get("app", {}).get("id"))
        if key not in latest_checks or int(check["id"]) > int(latest_checks[key]["id"]):
            latest_checks[key] = check
    for status in statuses:
        key = status["context"]
        if key not in latest_statuses or int(status["id"]) > int(latest_statuses[key]["id"]):
            latest_statuses[key] = status
    checks, statuses = list(latest_checks.values()), list(latest_statuses.values())
    failures = {"failure", "cancelled", "timed_out", "action_required", "startup_failure"}
    if any(c.get("conclusion") in failures for c in checks) or any(
        s.get("state") in {"failure", "error"} for s in statuses
    ):
        return "failing"
    if any(c.get("status") != "completed" for c in checks) or any(
        s.get("state") == "pending" for s in statuses
    ):
        return "running"
    return "reported_passed" if checks or statuses else "unknown"


class OwnerGitHub:
    def owner_token(self, *, gitops=False):
        config = self.config
        installation = config.gitops_installation_id if gitops else config.platform_installation_id
        repository_id = config.gitops_repository_id if gitops else config.platform_repository_id
        if not installation:
            raise PortalError(503, "OWNER_SETUP_REQUIRED", "GitOps integration is not configured.")
        permissions = {
            "contents": "read",
            "pull_requests": "read",
            "checks": "read",
            "statuses": "read",
        }
        if not gitops:
            permissions["issues"] = "read"
        return self.installation_token(installation, [repository_id], permissions)

    def owner_context(self, session, *, required=True):
        try:
            return self._owner_context(session, required=required)
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                503, "OWNER_POLICY_INVALID", "Platform owner policy could not be verified."
            ) from exc

    def _owner_context(self, session, *, required=True):
        if self.config.platform_branch != "main":
            raise PortalError(503, "OWNER_POLICY_INVALID", "Owner policy requires reviewed main.")
        repo = self.config.platform_repository
        token = self.installation_token(
            self.config.platform_installation_id,
            [self.config.platform_repository_id],
            {"contents": "read"},
        )
        metadata = self.api("GET", f"/repos/{repo}", token).json()
        if str(metadata["id"]) != self.config.platform_repository_id:
            raise PortalError(503, "OWNER_POLICY_INVALID", "Platform repository identity differs.")
        revision = self.api(
            "GET", f"/repos/{repo}/commits/{quote(self.config.platform_branch, safe='')}", token
        ).json()["sha"]
        raw = self.file(repo, "policies/portal-owner.json", revision, token)
        if raw is None:
            if not required:
                return None
            raise PortalError(403, "PLATFORM_FORBIDDEN", "Platform owner access is not enabled.")
        try:
            policy = PortalOwnerPolicy.model_validate(strict_json(raw))
            if policy.platform_repository_id != self.config.platform_repository_id:
                raise ValueError("Wrong policy audience")
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                503, "OWNER_POLICY_INVALID", "Platform owner policy is invalid."
            ) from exc
        if session.user_id not in policy.owner_user_ids:
            if not required:
                return None
            raise PortalError(403, "PLATFORM_FORBIDDEN", "Platform owner access is required.")
        return revision, policy, token

    def owner_allowed(self, session):
        return self.owner_context(session, required=False) is not None

    def owner_directory(self, path, revision, token, model):
        repo = self.config.platform_repository
        entries = self.api(
            "GET", f"/repos/{repo}/contents/{path}", token, params={"ref": revision}
        ).json()
        if not isinstance(entries, list) or len(entries) > 100:
            raise PortalError(503, "OWNER_BUDGET_EXCEEDED", "Inventory exceeds the console budget.")
        result = []
        for entry in entries:
            if entry["name"] == ".gitkeep":
                continue
            if entry["type"] != "file" or not entry["name"].endswith(".json"):
                raise PortalError(503, "OWNER_INVENTORY_INVALID", "Unexpected inventory entry.")
            result.append(
                model.model_validate(
                    strict_json(self.file(repo, path + "/" + entry["name"], revision, token))
                )
            )
        return result

    def owner_reviews(self, repository, token, label):
        prs = self.paginate(
            f"/repos/{repository}/pulls", token, state="open", sort="updated", direction="desc"
        )
        rows = []
        for pr in prs[:20]:
            number = int(pr["number"])
            sha = pr["head"]["sha"]
            if not re.fullmatch(r"[0-9a-f]{40}", sha):
                raise PortalError(503, "OWNER_REVIEW_INVALID", "Invalid proposal revision.")
            checks = self.paginate(
                f"/repos/{repository}/commits/{sha}/check-runs", token, collection="check_runs"
            )
            statuses = self.paginate(f"/repos/{repository}/commits/{sha}/statuses", token)
            ci = reported_ci_state(checks, statuses)
            rows.append(
                {
                    "repository": label,
                    "repository_key": label.lower(),
                    "number": number,
                    "title": pr["title"],
                    "branch": pr["base"]["ref"],
                    "draft": bool(pr.get("draft")),
                    "ci_state": ci,
                    "url": repository_link(repository, f"pull/{number}"),
                }
            )
        return rows, len(prs)

    def owner_environment(self, entry, environment, policy, branch, token, now):
        target = entry.environments[environment]
        row = {
            "environment": environment,
            "namespace": target.namespace,
            "argo_application": target.argo_application,
            "cluster_id": target.cluster_id,
            "branch": target.gitops_branch,
            "state": "not_deployed",
            "health_observed_at": None,
            "values_url": repository_link(
                policy.gitops_repository, "blob/" + branch + "/" + target.values_path
            ),
        }
        current = self.current_intent(entry, environment, policy, revision=branch)
        if current is None:
            return row
        row.update(
            observation_state(
                self.paginate(
                    f"/repos/{policy.gitops_repository}/commits/{current.intent_anchor}/statuses",
                    token,
                ),
                entry,
                environment,
                current,
                policy,
                now,
            )
        )
        row.update(
            image_digest=current.image_root_digest,
            source_commit=current.source_commit,
            release_id=current.release_id,
            fingerprint=current.fingerprint,
        )
        return row

    def owner_overview(self, session):
        try:
            return self._owner_overview(session)
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                503, "OWNER_SNAPSHOT_INVALID", "Platform snapshot could not be verified."
            ) from exc

    def _owner_overview(self, session):
        revision, owner, _policy_token = self.owner_context(session)
        token = self.owner_token()
        repo = self.config.platform_repository
        now = datetime.now(UTC)

        def read(path):
            return strict_json(self.file(repo, path, revision, token))

        policy = DeliveryPolicy.model_validate(read("policies/delivery.json"))
        bootstrap = read("policies/bootstrap.json")
        if (
            policy.platform_repository_id != owner.platform_repository_id
            or policy.gitops_repository_id != self.config.gitops_repository_id
            or policy.gitops_repository != self.config.gitops_repository
            or digest(bootstrap) != policy.bootstrap_policy_hash
        ):
            raise PortalError(503, "OWNER_POLICY_INVALID", "Reviewed platform bindings differ.")
        catalog = Catalog(
            self.owner_directory("catalog/apps", revision, token, CatalogEntry),
            self.owner_directory("catalog/clusters", revision, token, Cluster),
            CatalogPolicy.model_validate(read("policies/catalog.json")),
        )
        gitops_token = self.owner_token(gitops=True)
        gitops_metadata = self.api("GET", f"/repos/{policy.gitops_repository}", gitops_token).json()
        if str(gitops_metadata["id"]) != policy.gitops_repository_id:
            raise PortalError(503, "OWNER_POLICY_INVALID", "GitOps repository identity differs.")
        branches = {
            target.gitops_branch
            for entry in catalog.apps.values()
            for target in entry.environments.values()
        }
        heads = {
            branch: self.api(
                "GET",
                f"/repos/{policy.gitops_repository}/commits/" + quote(branch, safe=""),
                gitops_token,
            ).json()["sha"]
            for branch in branches
        }
        applications = []
        for entry in catalog.apps.values():
            environments = []
            for env, target in entry.environments.items():
                try:
                    row = self.owner_environment(
                        entry, env, policy, heads[target.gitops_branch], gitops_token, now
                    )
                except PortalError as exc:
                    if exc.code != "DESIRED_STATE_INVALID":
                        raise
                    row = {
                        "environment": env,
                        "namespace": target.namespace,
                        "argo_application": target.argo_application,
                        "cluster_id": target.cluster_id,
                        "branch": target.gitops_branch,
                        "state": "unverified",
                        "health_observed_at": None,
                    }
                environments.append(row)
            applications.append(
                {
                    "app_id": entry.app_id,
                    "display_name": entry.display_name,
                    "source": entry.source.owner + "/" + entry.source.name,
                    "source_url": repository_link(entry.source.owner + "/" + entry.source.name, ""),
                    "owner_user_ids": entry.access.owner_user_ids,
                    "environments": environments,
                }
            )
        reviews, platform_total = self.owner_reviews(repo, token, "Platform")
        portal_total = 0
        portal = catalog.apps.get("aegis-portal")
        if portal:
            portal_token = self.installation_token(
                portal.source.installation_id,
                [portal.source.repository_id],
                {"contents": "read", "pull_requests": "read", "checks": "read", "statuses": "read"},
            )
            portal_reviews, portal_total = self.owner_reviews(
                portal.source.owner + "/" + portal.source.name, portal_token, "Portal"
            )
            reviews += portal_reviews
        gitops_reviews, gitops_total = self.owner_reviews(
            policy.gitops_repository, gitops_token, "GitOps"
        )
        trust = RequestTrust.model_validate(read("policies/request-trust.json"))
        if trust.platform_repository_id != owner.platform_repository_id:
            raise PortalError(503, "OWNER_POLICY_INVALID", "Request registry audience differs.")
        issues = self.paginate(
            f"/repos/{repo}/issues", token, state="all", sort="created", direction="desc"
        )
        bot_ids = {issuer.bot_user_id for issuer in trust.issuers}
        issues = [
            issue
            for issue in issues
            if "pull_request" not in issue
            and str(issue.get("user", {}).get("id")) in bot_ids
            and issue.get("title", "").startswith("Aegis delivery ")
        ]
        activity = [signed_activity(issue, trust) for issue in issues[:20]]
        duplicates = Counter(row.get("request_id") for row in activity if row.get("request_id"))
        for row in activity:
            row["url"] = repository_link(repo, f"issues/{row['issue_number']}")
            if duplicates.get(row.get("request_id"), 0) > 1:
                row["integrity"] = "duplicate"
        return {
            "mode": "live",
            "access_mode": owner.mode,
            "observed_at": now.isoformat(),
            "catalog_revision": revision,
            "applications": applications,
            "clusters": [
                {**cluster.model_dump(), "state": "enrolled"}
                for cluster in catalog.clusters.values()
            ],
            "reviews": reviews + gitops_reviews,
            "review_total": platform_total + portal_total + gitops_total,
            "activity": activity,
            "activity_total": len(issues),
            "policy": {
                "production_human_review_required": policy.production_human_review_required,
                "protected_sync_mode": policy.protected_sync_mode,
                "maximum_evidence_age_seconds": policy.maximum_evidence_age_seconds,
                "resource_profiles": bootstrap["resource_profiles"],
                "owner_user_ids": owner.owner_user_ids,
                "owner_policy_url": repository_link(
                    repo, "blob/" + revision + "/policies/portal-owner.json"
                ),
                "delivery_policy_url": repository_link(
                    repo, "blob/" + revision + "/policies/delivery.json"
                ),
            },
        }
