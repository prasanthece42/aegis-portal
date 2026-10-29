"""Portal-side setup reads, signed journals and human reviews; no workflow/cluster writes."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from aegis_platform.canonical import canonical, digest, strict_json
from aegis_platform.catalog import Catalog, CatalogPolicy, Cluster
from aegis_platform.delivery import cache_fingerprint, timestamp, verify_status

from app.errors import PortalError
from app.setup_contracts import SetupPolicy, make_plan


def plan_bytes_equal(path, actual, expected):
    try:
        if actual is None:
            return False
        if isinstance(actual, bytes):
            actual = actual.decode()
        if path.endswith(".json"):
            return canonical(strict_json(actual.encode())) == canonical(
                strict_json(expected.encode())
            )
        return actual == expected
    except (UnicodeError, ValueError, TypeError):
        return False


class SetupGitHub:
    def registration_setup_plan(self, raw_entry, source):
        from app.contracts import CatalogEntry

        entry = CatalogEntry.model_validate(raw_entry)
        revision, delivery = self.catalog_snapshot()
        policy = self.setup_policy(revision, delivery)
        repo, token = self.config.platform_repository, self.platform_token()
        bootstrap = strict_json(self.file(repo, "policies/bootstrap.json", revision, token))
        cluster = Cluster.model_validate(
            strict_json(
                self.file(repo, f"catalog/clusters/{policy.cluster_id}.json", revision, token)
            )
        )
        catalog_policy = CatalogPolicy.model_validate(
            strict_json(self.file(repo, "policies/catalog.json", revision, token))
        )
        plan = make_plan(
            entry,
            Catalog([entry], [cluster], catalog_policy),
            delivery,
            bootstrap,
            policy,
            source["source_commit"],
        )
        return plan, self.setup_files(entry, plan)

    def registration_setup_journal(self, setup_id):
        raw = self.journal("reg-" + setup_id[6:])
        return (
            raw
            if raw
            and (
                raw[1].get("payload", {}).get("prepare_dev") is True
                and raw[1].get("payload", {}).get("setup_intent")
            )
            else None
        )

    def registration_preparation_status(self, registration_id):
        raw = self.journal(registration_id)
        if not raw or not (
            raw[1].get("payload", {}).get("prepare_dev") is True
            and raw[1].get("payload", {}).get("setup_intent")
        ):
            return "unknown"
        revision, delivery = self.catalog_snapshot()
        return self.setup_job_evidence(raw[0], self.setup_policy(revision, delivery))

    def setup_policy_token(self):
        return self.installation_token(
            self.config.platform_installation_id,
            [self.config.platform_repository_id],
            {"contents": "read", "statuses": "read"},
        )

    def setup_source_token(self, entry):
        return self.installation_token(
            entry.source.installation_id,
            [entry.source.repository_id],
            {"contents": "read", "actions": "read", "statuses": "read", "pull_requests": "read"},
        )

    def setup_policy(self, revision, delivery):
        raw = self.file(
            self.config.platform_repository,
            "policies/portal-setup.json",
            revision,
            self.platform_token(),
        )
        if raw is None:
            raise PortalError(
                503, "SETUP_WORKER_UNAVAILABLE", "Automatic DEV preparation is not enabled yet."
            )
        try:
            policy = SetupPolicy.model_validate(strict_json(raw))
        except ValueError as exc:
            raise PortalError(
                503,
                "SETUP_POLICY_INVALID",
                "Automatic DEV preparation is disabled or its policy needs review.",
            ) from exc
        if (
            policy.platform_repository_id != self.config.platform_repository_id
            or policy.gitops_repository_id != self.config.gitops_repository_id
            or policy.portal_app_id != self.config.app_id
            or not set(policy.operator_user_ids) <= set(delivery.observer_user_ids)
        ):
            raise PortalError(503, "SETUP_POLICY_INVALID", "Preparation policy identity differs.")
        return policy

    def setup_context(self, session, app_id):
        self.validate_session(session)
        entry, revision, delivery = self.delivery_authorize(session, app_id, "dev")
        if session.user_id not in entry.access.owner_user_ids:
            raise PortalError(
                403, "SETUP_FORBIDDEN", "An application owner must authorize preparation."
            )
        policy = self.setup_policy(revision, delivery)
        platform, token = self.config.platform_repository, self.platform_token()
        bootstrap = strict_json(self.file(platform, "policies/bootstrap.json", revision, token))
        cluster = Cluster.model_validate(
            strict_json(
                self.file(platform, f"catalog/clusters/{policy.cluster_id}.json", revision, token)
            )
        )
        catalog_policy = CatalogPolicy.model_validate(
            strict_json(self.file(platform, "policies/catalog.json", revision, token))
        )
        catalog = Catalog([entry], [cluster], catalog_policy)
        source = self.source(session, entry.source.repository_id)
        try:
            plan = make_plan(entry, catalog, delivery, bootstrap, policy, source["source_commit"])
        except ValueError as exc:
            raise PortalError(409, "SETUP_UNSUPPORTED", str(exc)) from exc
        return entry, revision, delivery, policy, plan

    def setup_files(self, entry, plan):
        source = entry.source.owner + "/" + entry.source.name
        stoken = self.delivery_source_token(entry)
        gitops, gtoken = self.config.gitops_repository, self.gitops_token()
        gitops_sha = self.api("GET", f"/repos/{gitops}/commits/main", gtoken).json()["sha"]
        work = [
            ("source", source, path, plan.source_commit, stoken) for path in plan.workflow_files
        ]
        work += [("target", gitops, path, gitops_sha, gtoken) for path in plan.target_files]
        work += [
            ("source", source, path, plan.source_commit, stoken)
            for path in ("Dockerfile", "requirements.txt", "requirements-prod.txt")
        ]

        def read(row):
            group, repo, path, sha, token = row
            return group, path, self.file(repo, path, sha, token, max_size=262144)

        with ThreadPoolExecutor(max_workers=6) as pool:
            rows = list(pool.map(read, work))
        files = {"source": {}, "target": {}}
        for group, path, data in rows:
            files[group][path] = data
        return files

    def setup_prs(self, entry, setup_id, plan, policy):
        branch = "aegis-setup/" + setup_id
        result = {}
        for kind, repo, token in (
            (
                "pipeline",
                entry.source.owner + "/" + entry.source.name,
                self.setup_source_token(entry),
            ),
            ("target", self.config.gitops_repository, self.gitops_token()),
        ):
            values = self.api(
                "GET",
                f"/repos/{repo}/pulls",
                token,
                params={"state": "all", "head": repo.split("/")[0] + ":" + branch, "per_page": 3},
            ).json()
            if len(values) > 1:
                raise PortalError(
                    409, "SETUP_CONFLICT", "More than one proposal exists for this setup."
                )
            if values:
                pr = values[0]
                expected_id = (
                    entry.source.repository_id
                    if kind == "pipeline"
                    else self.config.gitops_repository_id
                )
                expected_branch = entry.source.default_branch if kind == "pipeline" else "main"
                files = plan.workflow_files if kind == "pipeline" else plan.target_files
                if (
                    str(pr["head"]["repo"]["id"]) != expected_id
                    or str(pr["base"]["repo"]["id"]) != expected_id
                    or pr["base"]["ref"] != expected_branch
                    or pr["head"]["ref"] != branch
                    or str(pr["user"]["id"]) != self.config.platform_bot_user_id
                    or pr["user"].get("type") != "Bot"
                ):
                    raise PortalError(409, "SETUP_CONFLICT", "Setup proposal identity changed.")
                cache = getattr(self, "_setup_pr_cache", {})
                cache_key = (repo, pr["head"]["sha"], pr["base"]["sha"], digest(files))
                if cache_key not in cache:
                    changed = self.paginate(f"/repos/{repo}/pulls/{pr['number']}/files", token)
                    if len(changed) > 32 or any(
                        f["filename"] not in files
                        or f["status"] not in {"added", "modified"}
                        or "previous_filename" in f
                        for f in changed
                    ):
                        raise PortalError(
                            409, "SETUP_CONFLICT", "Setup proposal contains unrelated changes."
                        )
                    for path, expected in files.items():
                        actual = self.file(repo, path, pr["head"]["sha"], token, max_size=262144)
                        if not plan_bytes_equal(path, actual, expected):
                            raise PortalError(
                                409,
                                "SETUP_CONFLICT",
                                "Setup proposal differs from the files shown for review.",
                            )
                    if len(cache) >= 64:
                        cache.clear()
                    cache[cache_key] = True
                    self._setup_pr_cache = cache
                reviews = self.paginate(f"/repos/{repo}/pulls/{pr['number']}/reviews", token)
                latest_reviews = {}
                for review in reviews:
                    if review["state"] in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
                        latest_reviews[str(review["user"]["id"])] = review
                reviewers = (
                    entry.access.owner_user_ids if kind == "pipeline" else policy.operator_user_ids
                )
                approved = any(
                    uid in reviewers
                    and r["state"] == "APPROVED"
                    and r.get("commit_id") == pr["head"]["sha"]
                    and r["user"].get("type") == "User"
                    for uid, r in latest_reviews.items()
                )
                result[kind] = {
                    "repository": repo,
                    "approved": approved,
                    "number": pr["number"],
                    "url": pr["html_url"],
                    "head": pr["head"]["sha"],
                    "base": pr["base"]["sha"],
                    "state": pr["state"],
                    "merged": bool(pr.get("merged_at")),
                }
        return result

    def setup_observation(self, entry, plan, delivery, policy):
        repo = entry.source.owner + "/" + entry.source.name
        token = self.delivery_source_token(entry)
        sha = self.api("GET", f"/repos/{repo}/commits/{entry.source.default_branch}", token).json()[
            "sha"
        ]
        statuses = self.paginate(f"/repos/{repo}/commits/{sha}/statuses", token)
        try:
            observed = verify_status(
                statuses,
                f"aegis/{entry.app_id}/dev-setup",
                "setupfp:"
                + digest(
                    {
                        "entry": plan.catalog_entry_hash,
                        "files": plan.target_files,
                        "policy": plan.setup_policy_hash,
                    }
                ).split(":")[1],
                sha,
                delivery.model_copy(update={"observer_user_ids": policy.operator_user_ids}),
                datetime.now(UTC),
            )
            ready = (datetime.now(UTC) - timestamp(observed["created_at"])).total_seconds() <= 300
        except (ValueError, KeyError, TypeError):
            ready = False
        return ready, sha

    def setup_heartbeat(self, revision, delivery, policy):
        try:
            statuses = self.paginate(
                f"/repos/{self.config.platform_repository}/commits/{revision}/statuses",
                self.setup_policy_token(),
            )
            observed = verify_status(
                statuses,
                "aegis/dev-setup-worker",
                "readyfp:" + digest(policy.model_dump()).split(":")[1],
                revision,
                delivery.model_copy(update={"observer_user_ids": policy.operator_user_ids}),
                datetime.now(UTC),
            )
            return (datetime.now(UTC) - timestamp(observed["created_at"])).total_seconds() <= 120
        except (ValueError, KeyError, TypeError):
            return False

    def setup_job_evidence(self, sha, policy):
        statuses = self.paginate(
            f"/repos/{self.config.platform_repository}/commits/{sha}/statuses",
            self.setup_policy_token(),
        )
        valid = [
            s
            for s in statuses
            if s.get("context") == "aegis/dev-setup"
            and str(s.get("creator", {}).get("id")) in policy.operator_user_ids
            and s.get("creator", {}).get("type") == "User"
        ]
        valid.sort(key=lambda s: int(s["id"]), reverse=True)
        if valid and (datetime.now(UTC) - timestamp(valid[0]["created_at"])).total_seconds() <= 300:
            return valid[0]["state"]
        return "unknown"

    def setup_release_cache_ready(self, entry, release_id, delivery):
        try:
            evidence, _raw, _release = self.admitted_release(entry, release_id, delivery)
            statuses = self.paginate(
                f"/repos/{entry.source.owner}/{entry.source.name}/commits/{evidence.source_commit}/statuses",
                self.delivery_source_token(entry),
            )
            verify_status(
                statuses,
                f"aegis/{entry.app_id}/{entry.environments['dev'].cluster_id}-cache",
                "cachefp:" + cache_fingerprint(entry, "dev", evidence).split(":")[1],
                evidence.source_commit,
                delivery,
                datetime.now(UTC),
            )
            return True
        except (ValueError, KeyError, TypeError, PortalError):
            return False

    def setup_records(self):
        refs = self.api(
            "GET",
            f"/repos/{self.config.platform_repository}/git/matching-refs/heads/portal-setups/",
            self.platform_token(),
        ).json()
        if len(refs) > 100:
            raise PortalError(
                503, "SETUP_DISCOVERY_LIMIT", "Preparation history exceeds the discovery budget."
            )
        result = []
        for ref in refs:
            rid = ref["ref"].removeprefix("refs/heads/portal-setups/")
            if not __import__("re").fullmatch(r"setup-[0-9a-f]{64}", rid):
                continue
            raw = self.file(
                self.config.platform_repository,
                "record.json",
                ref["object"]["sha"],
                self.platform_token(),
                max_size=65536,
            )
            result.append((rid, strict_json(raw)))
        for rid in self.journal_ids():
            raw = self.journal(rid)
            if raw and (
                raw[1].get("payload", {}).get("prepare_dev") is True
                and raw[1].get("payload", {}).get("setup_intent")
            ):
                result.append(("setup-" + rid[4:], raw[1]))
        if len(result) > 100:
            raise PortalError(
                503, "SETUP_DISCOVERY_LIMIT", "Preparation history exceeds its budget."
            )
        return result

    def setup_ci_result(self, entry, source_commit, proposal):
        if not proposal:
            return None
        pipeline = not proposal["merged"]
        sha = proposal["head"] if pipeline else source_commit
        event = "pull_request" if pipeline else "push"
        path = ".github/workflows/ci.yml" if pipeline else ".github/workflows/release.yml"
        values = self.api(
            "GET",
            f"/repos/{entry.source.owner}/{entry.source.name}/actions/runs",
            self.setup_source_token(entry),
            params={"head_sha": sha, "event": event, "per_page": 10},
        ).json()["workflow_runs"]
        matches = [r for r in values if r.get("path") == path and r.get("head_sha") == sha]
        if not matches:
            return None
        run = matches[0]
        return {
            "status": run["status"],
            "conclusion": run.get("conclusion"),
            "url": run["html_url"],
            "label": "Pipeline validation" if pipeline else "Release build",
        }
