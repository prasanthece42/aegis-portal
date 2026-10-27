"""Repository-scoped, read-only delivery discovery and durable request transport."""

from datetime import UTC, datetime
from urllib.parse import quote, urlsplit

import httpx
from aegis_platform.canonical import canonical, digest, strict_json
from aegis_platform.contracts import CatalogEntry, DesiredState
from aegis_platform.delivery import (
    DeliveryPolicy,
    admit_release,
    authorize,
    cache_fingerprint,
    receipt_hash,
    verify_status,
)
from aegis_platform.release import ReleaseEvidence

from app.errors import PortalError


class DeliveryGitHub:
    def delivery_dispatch(self, rid, binding):
        repo, token = self.config.gitops_repository, self.gitops_token(write=True)
        path = ".github/workflows/delivery-request.yml"
        approved = self.file(repo, path, self.config.delivery_workflow_commit, token)
        current = self.file(repo, path, "main", token)
        if approved is None or current != approved:
            raise PortalError(
                503, "DELIVERY_WORKFLOW_CHANGED", "Delivery workflow needs operator review."
            )
        self.api(
            "POST",
            f"/repos/{repo}/actions/workflows/delivery-request.yml/dispatches",
            token,
            json={
                "ref": "main",
                "inputs": {"request_id": rid, "issue_number": str(binding["number"])},
            },
        )

    def delivery_releases(self, session, app_id, environment, page):
        entry, _revision, policy = self.delivery_authorize(session, app_id, environment)
        repo = entry.source.owner + "/" + entry.source.name
        releases = self.api(
            "GET",
            f"/repos/{repo}/releases",
            self.delivery_source_token(entry),
            params={"per_page": 10, "page": page},
        ).json()
        items = []
        for release in releases:
            if release.get("draft") or release.get("prerelease"):
                continue
            item = {
                "release_id": str(release["id"]),
                "tag": release["tag_name"],
                "published_at": release["published_at"],
                "eligible": False,
            }
            try:
                evidence, _raw, _release = self.admitted_release(entry, item["release_id"], policy)
                item.update(
                    eligible=True, image=evidence.image, source_commit=evidence.source_commit
                )
            except PortalError as exc:
                if exc.code != "RELEASE_INELIGIBLE":
                    raise
                item["reason"] = exc.message
            items.append(item)
        return {
            "items": items,
            "page": page,
            "next_page": page + 1 if len(releases) == 10 and page < 10 else None,
        }

    def catalog_snapshot(self):
        token = self.platform_token()
        repo = self.config.platform_repository
        revision = self.api(
            "GET", f"/repos/{repo}/commits/{quote(self.config.platform_branch, safe='')}", token
        ).json()["sha"]
        raw = self.file(repo, "policies/delivery.json", revision, token)
        if raw is None:
            raise PortalError(503, "DELIVERY_SETUP_REQUIRED", "Delivery policy is not installed.")
        policy = DeliveryPolicy.model_validate(strict_json(raw))
        bootstrap = self.file(repo, "policies/bootstrap.json", revision, token)
        if bootstrap is None or digest(strict_json(bootstrap)) != policy.bootstrap_policy_hash:
            raise PortalError(
                503, "POLICY_INVALID", "Resource policy differs from approved delivery policy."
            )
        if (
            policy.platform_repository_id != self.config.platform_repository_id
            or policy.platform_repository != repo
            or policy.gitops_repository_id != self.config.gitops_repository_id
            or policy.gitops_repository != self.config.gitops_repository
        ):
            raise PortalError(503, "POLICY_INVALID", "Delivery repository bindings differ.")
        return revision, policy

    def delivery_authorize(self, session, app_id, environment):
        revision, policy = self.catalog_snapshot()
        raw = self.file(
            self.config.platform_repository,
            f"catalog/apps/{app_id}.json",
            revision,
            self.platform_token(),
        )
        if raw is None:
            raise PortalError(404, "APPLICATION_UNAVAILABLE", "Application is unavailable.")
        entry = CatalogEntry.model_validate(strict_json(raw))
        source = self.source(session, entry.source.repository_id)
        if (
            source["installation_id"] != entry.source.installation_id
            or source["full_name"].lower() != (entry.source.owner + "/" + entry.source.name).lower()
        ):
            raise PortalError(403, "SOURCE_CHANGED", "Source installation or identity changed.")
        try:
            authorize(entry, session.user_id, environment, True)
        except ValueError as exc:
            raise PortalError(403, "DEPLOYMENT_FORBIDDEN", "No current deployment grant.") from exc
        return entry, revision, policy

    def delivery_source_token(self, entry):
        return self.installation_token(
            entry.source.installation_id,
            [entry.source.repository_id],
            {"contents": "read", "actions": "read", "statuses": "read"},
        )

    def receipt_asset(self, repository, asset_id, token):
        url = f"https://api.github.com/repos/{repository}/releases/assets/{int(asset_id)}"
        headers = {"Authorization": "Bearer " + token, "Accept": "application/octet-stream"}
        try:
            for _ in range(3):
                with self.client.stream("GET", url, headers=headers) as response:
                    if response.status_code in {301, 302, 307, 308}:
                        url = response.headers.get("location", "")
                        parsed = urlsplit(url)
                        if (
                            parsed.scheme != "https"
                            or parsed.hostname
                            not in {
                                "release-assets.githubusercontent.com",
                                "objects.githubusercontent.com",
                            }
                            or parsed.username
                            or parsed.password
                            or parsed.port not in {None, 443}
                        ):
                            raise ValueError("Unapproved release asset redirect")
                        headers = {}  # Never forward an installation credential across origins.
                        continue
                    response.raise_for_status()
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > 65536:
                            raise ValueError("Release receipt exceeds 64 KiB")
                    return bytes(content)
        except (httpx.HTTPError, ValueError) as exc:
            raise PortalError(
                503, "RELEASE_UNAVAILABLE", "Release receipt is unavailable."
            ) from exc
        raise PortalError(503, "RELEASE_UNAVAILABLE", "Release asset redirect budget exceeded.")

    def admitted_release(self, entry, release_id, policy):
        source = entry.source.owner + "/" + entry.source.name
        token = self.delivery_source_token(entry)
        repository = self.api("GET", f"/repos/{source}", token).json()
        release = self.api("GET", f"/repos/{source}/releases/{release_id}", token).json()
        assets = [a for a in release.get("assets", []) if a.get("name") == "release.json"]
        if len(assets) != 1 or str(release.get("id")) != release_id:
            raise PortalError(409, "RELEASE_INELIGIBLE", "Release receipt is missing or ambiguous.")
        raw = self.receipt_asset(source, assets[0]["id"], token)
        try:
            evidence = ReleaseEvidence.model_validate(strict_json(raw))
            run = self.api(
                "GET",
                f"/repos/{source}/actions/runs/{evidence.workflow_run_id}/attempts/{evidence.run_attempt}",
                token,
            ).json()
            evidence = admit_release(entry, raw, release, repository, run, policy)
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                409, "RELEASE_INELIGIBLE", "Release failed source and workflow admission."
            ) from exc
        return evidence, raw, release

    def gitops_token(self, *, write=False):
        return self.installation_token(
            self.config.gitops_installation_id,
            [self.config.gitops_repository_id],
            {
                "contents": "read",
                "statuses": "read",
                "pull_requests": "read",
                "actions": "write" if write else "read",
            },
        )

    def delivery_status(self, intent):
        _revision, policy = self.catalog_snapshot()
        repo, token = policy.gitops_repository, self.gitops_token()
        prs = self.paginate(
            f"/repos/{repo}/pulls",
            token,
            state="all",
            head=repo.split("/")[0] + ":aegis-requests/" + intent["request_id"],
        )
        if not prs:
            return {"status": "accepted", "health": "not_observed"}
        if len(prs) != 1:
            raise PortalError(
                503, "REQUEST_STATE_INVALID", "Request has ambiguous GitOps proposals."
            )
        pr = self.api("GET", f"/repos/{repo}/pulls/{prs[0]['number']}", token).json()
        if (
            str(pr["user"]["id"])
            not in {*policy.workflow_bot_user_ids, self.config.platform_bot_user_id}
            or pr["user"].get("type") != "Bot"
            or str(pr["head"]["repo"]["id"]) != policy.gitops_repository_id
            or pr["head"]["ref"] != "aegis-requests/" + intent["request_id"]
            or str(pr["base"]["repo"]["id"]) != policy.gitops_repository_id
            or pr["base"]["ref"]
            != {"dev": "main", "staging": "staging", "prod": "prod"}[intent["environment"]]
        ):
            raise PortalError(503, "REQUEST_STATE_INVALID", "GitOps proposal identity differs.")
        result = {
            "status": "awaiting_review" if intent["environment"] == "prod" else "checking",
            "health": "not_observed",
            "pull_request": {
                "number": pr["number"],
                "url": pr["html_url"],
                "state": pr["state"],
                "merged": bool(pr.get("merged_at")),
            },
        }
        if not pr.get("merged_at"):
            if pr["state"] == "closed":
                result["status"] = "closed_unmerged"
            return result
        entry = CatalogEntry.model_validate(
            strict_json(
                self.file(
                    self.config.platform_repository,
                    f"catalog/apps/{intent['app_id']}.json",
                    _revision,
                    self.platform_token(),
                )
            )
        )
        target = entry.environments[intent["environment"]]
        pointer_path = target.values_path.rsplit("/", 1)[0] + "/release.json"
        pointer = strict_json(self.file(repo, pointer_path, target.gitops_branch, token))
        if pointer.get("delivery_id") != intent["request_id"]:
            result["status"] = "superseded"
            return result
        current = self.current_intent(entry, intent["environment"], policy)
        result["status"] = "reconciling"
        if current:
            statuses = self.paginate(
                f"/repos/{repo}/commits/{current.intent_anchor}/statuses", token
            )
            try:
                observation = verify_status(
                    statuses,
                    f"aegis/{entry.app_id}/{intent['environment']}-health",
                    "Healthy " + current.fingerprint,
                    current.intent_anchor,
                    policy,
                    datetime.now(UTC),
                )
            except (ValueError, KeyError, TypeError):
                result["health"] = "not_healthy_or_not_observed"
            else:
                from aegis_platform.delivery import timestamp

                result["health_observed_at"] = observation["created_at"]
                if (datetime.now(UTC) - timestamp(observation["created_at"])).total_seconds() > 300:
                    result["health"] = "stale"
                else:
                    result.update(
                        status="healthy", health="healthy", fingerprint=current.fingerprint
                    )
        return result

    def current_intent(self, entry, environment, policy):
        from aegis_platform.proposal import current_state

        target = entry.environments[environment]
        repo, token = policy.gitops_repository, self.gitops_token()
        branch = self.api(
            "GET", f"/repos/{repo}/commits/{quote(target.gitops_branch, safe='')}", token
        ).json()["sha"]
        path = target.values_path.rsplit("/", 1)[0] + "/release.json"
        raw = self.file(repo, path, branch, token)
        if raw is None:
            return None
        try:
            state = DesiredState.model_validate(strict_json(raw)["desired_state"])
            files = {
                path: raw,
                target.values_path: self.file(repo, target.values_path, branch, token),
            }
            for binding in state.controller_bindings:
                files[binding] = self.file(repo, binding, branch, token)
            commits = self.api(
                "GET",
                f"/repos/{repo}/commits",
                token,
                params={"sha": branch, "path": path, "per_page": 1},
            ).json()
            return current_state(
                entry, environment, files, commits[0]["sha"], digest(policy.model_dump())
            )
        except (ValueError, KeyError, TypeError, IndexError) as exc:
            raise PortalError(
                409, "DESIRED_STATE_INVALID", "Current app bindings need reconciliation."
            ) from exc

    def delivery_context(self, session, fields):
        entry, revision, policy = self.delivery_authorize(
            session, fields.app_id, fields.environment
        )
        evidence, raw, _release = self.admitted_release(entry, fields.release_id, policy)
        current = self.current_intent(entry, fields.environment, policy)
        target = entry.environments[fields.environment]
        # Cache evidence is posted on the immutable source commit by the enrolled local agent.
        source = entry.source.owner + "/" + entry.source.name
        statuses = self.paginate(
            f"/repos/{source}/commits/{evidence.source_commit}/statuses",
            self.delivery_source_token(entry),
        )
        try:
            verify_status(
                statuses,
                f"aegis/{entry.app_id}/{target.cluster_id}-cache",
                "cachefp:" + cache_fingerprint(entry, fields.environment, evidence).split(":")[1],
                evidence.source_commit,
                policy,
                datetime.now(UTC),
            )
            if current:
                comparison = self.api(
                    "GET",
                    f"/repos/{source}/compare/{current.source_commit}...{evidence.source_commit}",
                    self.delivery_source_token(entry),
                ).json()
                if comparison.get("status") not in {"ahead", "identical"}:
                    raise ValueError(
                        "Normal delivery cannot move backwards or across source lineage"
                    )
            prior = None
            if fields.environment != "dev":
                prior_env = {"staging": "dev", "prod": "staging"}[fields.environment]
                previous = self.current_intent(entry, prior_env, policy)
                if not previous or previous.image_root_digest != evidence.image.rsplit("@", 1)[1]:
                    raise ValueError("Prior environment does not use the selected root image")
                observed = verify_status(
                    self.paginate(
                        f"/repos/{policy.gitops_repository}/commits/{previous.intent_anchor}/statuses",
                        self.gitops_token(),
                    ),
                    f"aegis/{entry.app_id}/{prior_env}-health",
                    "Healthy " + previous.fingerprint,
                    previous.intent_anchor,
                    policy,
                    datetime.now(UTC),
                )
                prior = {
                    "environment": prior_env,
                    "intent_anchor": previous.intent_anchor,
                    "fingerprint": previous.fingerprint,
                    "observed_at": observed["created_at"],
                    "evidence_reference": str(observed["id"]),
                }
        except (ValueError, KeyError, TypeError) as exc:
            raise PortalError(
                409,
                "DELIVERY_BLOCKED",
                "Fresh cache, source lineage or prior health evidence is missing.",
            ) from exc
        return {
            "catalog_revision": revision,
            "catalog_entry_hash": digest(entry.model_dump()),
            "resolved_policy_hash": digest(policy.model_dump()),
            "source_repository_id": entry.source.repository_id,
            "source_commit": evidence.source_commit,
            "release_workflow_run_id": evidence.workflow_run_id,
            "release_evidence_hash": receipt_hash(raw),
            "image_root_digest": evidence.image.rsplit("@", 1)[1],
            "platform_digests": {
                k: v.image.rsplit("@", 1)[1] for k, v in evidence.platforms.items()
            },
            "expected_desired_fingerprint": current.fingerprint if current else None,
            "expected_intent_anchor": current.intent_anchor if current else None,
            "prior_environment_evidence": prior,
            "target": target.model_dump(),
        }

    def delivery_issue(self, rid, record):
        repo = self.config.platform_repository
        token = self.installation_token(
            self.config.platform_installation_id,
            [self.config.platform_repository_id],
            {"issues": "write"},
        )
        title = "Aegis delivery " + rid
        body = canonical(record).decode()
        issues = self.paginate(f"/repos/{repo}/issues", token, state="all")
        matches = [
            issue for issue in issues if issue.get("title") == title and "pull_request" not in issue
        ]
        if not matches:
            matches = [
                self.api(
                    "POST", f"/repos/{repo}/issues", token, json={"title": title, "body": body}
                ).json()
            ]
        if len(matches) != 1:
            raise PortalError(409, "ISSUE_CONFLICT", "Request has ambiguous issue bindings.")
        issue = matches[0]
        if (
            str(issue["user"]["id"]) != self.config.platform_bot_user_id
            or issue["user"].get("type") != "Bot"
            or issue.get("body") != body
        ):
            raise PortalError(
                409, "ISSUE_INVALID", "Request issue author or signed content differs."
            )
        return {"id": str(issue["id"]), "number": issue["number"], "url": issue["html_url"]}
