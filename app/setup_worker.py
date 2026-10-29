"""Enrolled operator execution for signed DEV setup; no app code execution or deployments."""

import fcntl
import os
import re
import subprocess
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote

from aegis_platform.canonical import canonical, digest, strict_json
from aegis_platform.catalog import Catalog
from aegis_platform.contracts import CatalogEntry
from aegis_platform.delivery import authorize
from aegis_platform.local_agent import LocalAgent
from aegis_platform.portal_owner import PortalOwnerPolicy
from aegis_platform.proposal import current_state, proposal
from aegis_platform.release import ReleaseEvidence
from aegis_platform.request import verify_request

from app.config import LiveConfig
from app.setup_contracts import CHARTS, SetupPolicy, make_plan, verify_setup
from app.setup_github import plan_bytes_equal


class Pending(Exception):
    """An expected asynchronous provider or human-review gate."""


class SetupWorker:
    def __init__(self, config, worker, bot_factory, state_path, portal_app_id):
        self.config, self.worker, self.bot_factory = config, worker, bot_factory
        self.portal_app_id = portal_app_id
        self.agent = LocalAgent(config, worker)
        self.state_path = Path(state_path)

    @contextmanager
    def lock(self):
        self.state_path.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.state_path / "worker.lock", os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield

    def snapshot(self):
        revision, catalog, delivery, trust, bootstrap = self.worker.snapshot()
        policy = SetupPolicy.model_validate(
            strict_json(self.worker.platform.file("policies/portal-setup.json", revision))
        )
        user = self.worker.gitops.call("GET", "/user")
        if (
            policy.portal_app_id != self.portal_app_id
            or str(user.get("id")) not in policy.operator_user_ids
            or user.get("type") != "User"
            or policy.platform_repository_id != delivery.platform_repository_id
            or policy.gitops_repository_id != delivery.gitops_repository_id
            or not set(policy.operator_user_ids) <= set(delivery.observer_user_ids)
            or (policy.cluster_id, policy.cluster_uid)
            != (self.config.cluster_id, self.config.cluster_uid)
        ):
            raise ValueError("Setup operator or cluster is not enrolled in current policy")
        owner = PortalOwnerPolicy.model_validate(
            strict_json(self.worker.platform.file("policies/portal-owner.json", revision))
        )
        self.target_reviewers = set(policy.operator_user_ids) & set(owner.owner_user_ids)
        if (
            owner.platform_repository_id != policy.platform_repository_id
            or not self.target_reviewers
        ):
            raise ValueError("No current enrolled platform-owner reviewer is available")
        # Read-only enrollment check before heartbeat, Git writes or Kubernetes changes.
        entry = next(
            (
                e
                for e in catalog.apps.values()
                if e.environments.get("dev")
                and e.environments["dev"].cluster_uid == policy.cluster_uid
            ),
            None,
        )
        if entry is None:
            raise ValueError("No enrolled DEV application exists")
        self.agent.enroll(entry, "dev", delivery)
        return revision, catalog, delivery, trust, bootstrap, policy

    def tick(self):
        with self.lock():
            revision, catalog, delivery, trust, bootstrap, policy = self.snapshot()
            self.worker.platform.repo(
                "POST",
                "statuses/" + revision,
                {
                    "state": "success",
                    "context": "aegis/dev-setup-worker",
                    "description": "readyfp:" + digest(policy.model_dump()).split(":")[1],
                },
            )
            refs = self.worker.platform.repo("GET", "git/matching-refs/heads/portal-setups/")
            refs += self.worker.platform.repo(
                "GET", "git/matching-refs/heads/portal-registrations/"
            )
            if len(refs) > 100:
                raise ValueError("Preparation request discovery exceeds its bounded budget")
            completed_path = self.state_path / "completed.json"
            self.completed = (
                strict_json(completed_path.read_bytes()) if completed_path.exists() else {}
            )
            result = []
            for ref in refs:
                name = ref.get("ref", "")
                registration = name.startswith("refs/heads/portal-registrations/")
                original_id = name.rsplit("/", 1)[-1]
                rid = "setup-" + original_id[4:] if registration else original_id
                if not re.fullmatch(r"setup-[0-9a-f]{64}", rid):
                    continue
                try:
                    record = strict_json(
                        self.worker.platform.file("record.json", ref["object"]["sha"])
                    )
                    if registration:
                        if record.get("payload", {}).get(
                            "prepare_dev"
                        ) is not True or not record.get("payload", {}).get("setup_intent"):
                            continue
                        if record["payload"].get("registration_id") != original_id:
                            raise ValueError("Registration journal identity changed")
                    intent, issuer = verify_setup(
                        record, trust, policy, require_fresh=rid not in self.completed
                    )
                    if intent.setup_id != rid:
                        raise ValueError("Setup journal ref differs from its signed identity")
                    if intent.plan.app_id not in catalog.apps:
                        if registration:
                            self.merge_registration(
                                record["payload"],
                                intent,
                                issuer,
                                policy,
                                catalog,
                                delivery,
                                bootstrap,
                            )
                        raise Pending("Waiting for catalog owner approval.")
                    if registration and not record["payload"].get("binding"):
                        raise Pending("Waiting for the registration proposal to finish.")
                    entry = catalog.apps[intent.plan.app_id]
                    source = self.worker.source_factory(entry)
                    metadata = source.repo("GET", "")
                    if (
                        str(metadata["id"]) != entry.source.repository_id
                        or metadata.get("private")
                        or metadata.get("full_name", "").lower()
                        != intent.plan.source_repository.lower()
                        or metadata.get("default_branch") != intent.plan.source_branch
                    ):
                        raise ValueError("Source repository binding changed")
                    collaborators = source.pages("collaborators", affiliation="all")
                    push = any(
                        str(u["id"]) == intent.requester_user_id
                        and u.get("permissions", {}).get("push")
                        for u in collaborators
                    )
                    self.source_reviewers = {
                        str(u["id"])
                        for u in collaborators
                        if str(u["id"]) in entry.access.owner_user_ids
                        and u.get("permissions", {}).get("push")
                    }
                    authorize(entry, intent.requester_user_id, "dev", push)
                    if intent.requester_user_id not in entry.access.owner_user_ids:
                        raise ValueError("Preparation owner grant was revoked")
                    plan = make_plan(
                        entry, catalog, delivery, bootstrap, policy, intent.plan.source_commit
                    )
                    if canonical(plan.model_dump()) != canonical(intent.plan.model_dump()):
                        raise ValueError("Current setup inputs differ from the signed review")
                    state = self.process(intent, entry, source, delivery, issuer, policy)
                    result.append({"setup_id": rid, "app_id": entry.app_id, "state": state})
                except Pending as exc:
                    result.append({"setup_id": rid, "state": "waiting", "reason": str(exc)})
                except (ValueError, KeyError, OSError, subprocess.SubprocessError):
                    result.append(
                        {
                            "setup_id": rid,
                            "state": "blocked",
                            "reason": "Authorization, source, review or policy "
                            "needs a fresh setup review.",
                        }
                    )
                latest = result[-1]
                self.worker.platform.repo(
                    "POST",
                    "statuses/" + ref["object"]["sha"],
                    {
                        "context": "aegis/dev-setup",
                        "state": "success"
                        if latest["state"] == "ready"
                        else "error"
                        if latest["state"] == "blocked"
                        else "pending",
                        "description": "DEV target prepared; deployment requires confirmation."
                        if latest["state"] == "ready"
                        else "Setup requires attention. Refresh and review the current plan."
                        if latest["state"] == "blocked"
                        else "Setup is waiting for review or CI checks.",
                    },
                )
            self.write_state({"updated_at": datetime.now(UTC).isoformat(), "items": result})
            return result

    def merge_registration(self, payload, intent, issuer, policy, catalog, delivery, bootstrap):
        """Finish only the exact signed catalog proposal after a real owner review."""
        binding = payload.get("binding")
        if not binding:
            raise Pending("Waiting for the registration proposal to finish.")
        public = LiveConfig.model_validate(
            strict_json(
                self.worker.platform.file(
                    "policies/portal-system.json",
                    self.worker.platform.repo("GET", "git/ref/heads/main")["object"]["sha"],
                )
            )["configuration"]
        )
        if (
            digest(public.model_dump()) != payload["policy_hash"]
            or intent.requester_user_id not in public.onboarding_user_ids
            or intent.requester_user_id not in public.allowed_owner_user_ids
        ):
            raise ValueError("Current onboarding authorization changed")
        entry = CatalogEntry.model_validate(payload["catalog_entry"])
        draft = Catalog(
            list(catalog.apps.values()) + [entry], list(catalog.clusters.values()), catalog.policy
        )
        expected = make_plan(entry, draft, delivery, bootstrap, policy, intent.plan.source_commit)
        if canonical(expected.model_dump()) != canonical(intent.plan.model_dump()):
            raise ValueError("Registration setup inputs changed")
        source = self.worker.source_factory(entry)
        metadata = source.repo("GET", "")
        collaborators = source.pages("collaborators", affiliation="all")
        if (
            str(metadata["id"]) != entry.source.repository_id
            or metadata.get("private")
            or metadata.get("full_name", "").lower() != intent.plan.source_repository.lower()
            or metadata.get("default_branch") != entry.source.default_branch
            or entry.source.installation_id not in public.source_installation_ids
            or source.repo("GET", "git/ref/heads/" + quote(entry.source.default_branch, safe=""))[
                "object"
            ]["sha"]
            != intent.plan.source_commit
        ):
            raise ValueError("Registration source access or revision changed")
        push = any(
            str(u["id"]) == intent.requester_user_id and u.get("permissions", {}).get("push")
            for u in collaborators
        )
        authorize(entry, intent.requester_user_id, "dev", push)
        pr = self.worker.platform.repo("GET", f"pulls/{binding['number']}")
        if (
            str(pr["base"]["repo"]["id"]) != policy.platform_repository_id
            or pr["head"]["ref"] != "portal-onboarding/" + payload["registration_id"]
            or str(pr["user"]["id"]) != issuer.bot_user_id
            or pr["user"].get("type") != "Bot"
            or (pr["state"] == "closed" and not pr.get("merged_at"))
        ):
            raise ValueError("Catalog proposal identity changed")
        self.verify_pr(
            self.worker.platform,
            pr,
            {f"catalog/apps/{entry.app_id}.json": canonical(payload["catalog_entry"]).decode()},
            "main",
        )
        self.merge(self.worker.platform, pr, self.target_reviewers)
        raise Pending("Catalog approval is merged. Preparation resumes on the next cycle.")

    def write_state(self, state):
        path = self.state_path / "status.json"
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical(state) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)

    @staticmethod
    def files_at(api, files, revision):
        rows = {}
        for path in files:
            try:
                rows[path] = api.file(path, revision)
            except ValueError as exc:
                if "HTTP 404" not in str(exc):
                    raise
                rows[path] = None
        return rows

    def ensure_pr(self, api, bot, branch, base_branch, files, *, source_base=None, title):
        prs = api.pages("pulls", state="all", head=api.repository.split("/")[0] + ":" + branch)
        if len(prs) > 1:
            raise ValueError("Duplicate preparation proposals")
        if prs:
            pr = api.repo("GET", "pulls/" + str(prs[0]["number"]))
            self.verify_pr(api, pr, files, base_branch)
            if pr["state"] == "closed" and not pr.get("merged_at"):
                raise ValueError("Setup proposal was closed without merging")
            return pr
        base = api.repo("GET", "git/ref/heads/" + quote(base_branch, safe=""))["object"]["sha"]
        existing = self.files_at(api, files, base)
        conflicts = [
            p
            for p, content in existing.items()
            if content is not None and not plan_bytes_equal(p, content, files[p])
        ]
        if conflicts:
            raise ValueError("Existing configuration conflicts with reviewed setup")
        changed = {p: v for p, v in files.items() if not plan_bytes_equal(p, existing[p], v)}
        if not changed:
            return None
        if source_base and source_base != base:
            raise ValueError("Source advanced before pipeline preparation")
        refs = api.repo("GET", "git/matching-refs/heads/" + branch)
        if refs:
            if len(refs) != 1 or refs[0]["ref"] != "refs/heads/" + branch:
                raise ValueError("Ambiguous preparation branch")
            head = refs[0]["object"]["sha"]
            after = self.files_at(api, files, head)
            if any(not plan_bytes_equal(p, after[p], v) for p, v in files.items()):
                raise ValueError("Existing preparation branch differs")
            difference = api.repo("GET", "compare/" + base + "..." + head)
            if set(f["filename"] for f in difference["files"]) != set(changed):
                raise ValueError("Preparation branch contains unrelated changes")
        else:
            tree = api.repo("GET", "git/commits/" + base)["tree"]["sha"]
            tree = api.repo(
                "POST",
                "git/trees",
                {
                    "base_tree": tree,
                    "tree": [
                        {"path": p, "mode": "100644", "type": "blob", "content": v}
                        for p, v in changed.items()
                    ],
                },
            )["sha"]
            head = api.repo(
                "POST", "git/commits", {"message": title, "tree": tree, "parents": [base]}
            )["sha"]
            api.repo("POST", "git/refs", {"ref": "refs/heads/" + branch, "sha": head})
        pr = bot.repo(
            "POST",
            "pulls",
            {
                "title": title,
                "head": branch,
                "base": base_branch,
                "body": "Exact signed portal DEV preparation. Review these files in the portal. "
                "This setup does not select a release or authorize deployment.",
            },
        )
        self.verify_pr(api, pr, files, base_branch)
        return pr

    @staticmethod
    def verify_pr(api, pr, files, base_branch):
        if (
            pr["base"]["ref"] != base_branch
            or str(pr["head"]["repo"]["id"]) != str(pr["base"]["repo"]["id"])
            or pr.get("changed_files", 0) > 32
        ):
            raise ValueError("Preparation PR scope changed")
        changed = api.pages(f"pulls/{pr['number']}/files")
        if len(changed) > 32 or any(
            f["filename"] not in files
            or f["status"] not in {"added", "modified"}
            or "previous_filename" in f
            for f in changed
        ):
            raise ValueError("Preparation PR contains unrelated files")
        for path, expected in files.items():
            if not plan_bytes_equal(path, api.file(path, pr["head"]["sha"]), expected):
                raise ValueError("Preparation PR does not contain the exact reviewed files")

    @staticmethod
    def approved(api, pr, reviewers):
        latest = {}
        for review in api.pages(f"pulls/{pr['number']}/reviews"):
            if review["state"] in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
                latest[str(review["user"]["id"])] = review
        return any(
            uid in reviewers
            and r["state"] == "APPROVED"
            and r.get("commit_id") == pr["head"]["sha"]
            and r["user"].get("type") == "User"
            and uid != str(pr["user"]["id"])
            for uid, r in latest.items()
        )

    def merge(self, api, pr, reviewers, *, pipeline=False, entry=None):
        if pr is None or pr.get("merged_at"):
            return True
        if not self.approved(api, pr, reviewers):
            raise Pending("Review the setup proposals in the portal.")
        if pipeline:
            runs = api.repo(
                "GET", f"actions/runs?head_sha={pr['head']['sha']}&event=pull_request&per_page=10"
            )["workflow_runs"]
            runs = [
                r
                for r in runs
                if r.get("path") == ".github/workflows/ci.yml"
                and r.get("head_sha") == pr["head"]["sha"]
            ]
            if not runs or runs[0].get("status") != "completed":
                raise Pending("Pipeline validation is running.")
            if runs[0].get("conclusion") != "success":
                raise Pending("Pipeline validation needs attention; inspect its CI results.")
        latest = api.repo("GET", f"pulls/{pr['number']}")
        if latest["head"]["sha"] != pr["head"]["sha"]:
            raise ValueError("Proposal changed before merge")
        if latest.get("mergeable_state") not in {"clean", "has_hooks", "unstable"}:
            raise Pending("GitHub checks or branch policy are still pending.")
        try:
            result = api.repo(
                "PUT",
                f"pulls/{pr['number']}/merge",
                {"sha": pr["head"]["sha"], "merge_method": "squash"},
            )
        except ValueError as exc:
            if any(code in str(exc) for code in ("HTTP 405", "HTTP 409")):
                raise Pending("GitHub requires a current review or successful checks.") from None
            raise
        if not result.get("merged"):
            raise Pending("GitHub has not merged this setup yet.")
        return True

    def process(self, intent, entry, source, delivery, issuer, policy):
        plan = intent.plan
        branch = "aegis-setup/" + intent.setup_id
        source_bot = self.bot_factory(
            entry.source.installation_id, entry.source.repository_id, source.repository
        )
        target_bot = self.bot_factory(
            None, delivery.gitops_repository_id, delivery.gitops_repository
        )
        # Source workflow bytes use only the explicitly authorized operator credential.
        pipeline_pr = self.ensure_pr(
            source,
            source_bot,
            branch,
            entry.source.default_branch,
            plan.workflow_files,
            source_base=plan.source_commit,
            title=f"Prepare {entry.app_id} pipeline for DEV",
        )
        target_pr = self.ensure_pr(
            self.worker.gitops,
            target_bot,
            branch,
            "main",
            plan.target_files,
            title=f"Prepare {entry.app_id} DEV target",
        )
        if pipeline_pr and not pipeline_pr.get("merged_at"):
            source_head = source.repo(
                "GET", "git/ref/heads/" + quote(entry.source.default_branch, safe="")
            )["object"]["sha"]
            if source_head != plan.source_commit:
                raise ValueError(
                    "Source changed before pipeline installation; review current setup"
                )
        expected_bot = issuer.bot_user_id
        if any(
            pr and (str(pr["user"]["id"]) != expected_bot or pr["user"].get("type") != "Bot")
            for pr in (pipeline_pr, target_pr)
        ):
            raise ValueError("Setup PR must be authored by the trusted portal App")
        # Independent reviews are required for both scopes. No auto-approval is generated.
        self.merge(source, pipeline_pr, self.source_reviewers, pipeline=True, entry=entry)
        self.merge(self.worker.gitops, target_pr, self.target_reviewers)
        self.prepare_target(entry, plan)
        sha = source.repo("GET", "git/ref/heads/" + quote(entry.source.default_branch, safe=""))[
            "object"
        ]["sha"]
        actual = self.files_at(source, plan.workflow_files, sha)
        if any(not plan_bytes_equal(p, actual[p], v) for p, v in plan.workflow_files.items()):
            raise ValueError("Installed pipeline differs from setup plan")
        source.repo(
            "POST",
            "statuses/" + sha,
            {
                "state": "success",
                "context": f"aegis/{entry.app_id}/dev-setup",
                "description": "setupfp:"
                + digest(
                    {
                        "entry": plan.catalog_entry_hash,
                        "files": plan.target_files,
                        "policy": plan.setup_policy_hash,
                    }
                ).split(":")[1],
            },
        )
        if intent.setup_id not in self.completed:
            self.completed[intent.setup_id] = {"ready_at": datetime.now(UTC).isoformat()}
            self.save_completed()
        # Cache preparation validates published release evidence; it never starts a workload.
        releases = source.repo("GET", "releases?per_page=5")
        latest = next((r for r in releases if not r.get("draft") and not r.get("prerelease")), None)
        if latest and str(latest["id"]) != self.completed[intent.setup_id].get("cached_release_id"):
            self.agent.prepare(entry.app_id, str(latest["id"]))
            self.completed[intent.setup_id]["cached_release_id"] = str(latest["id"])
            self.save_completed()
        self.activate_after_signed_deployment(entry, delivery)
        return "ready"

    def save_completed(self):
        path = self.state_path / "completed.json"
        temporary = path.with_suffix(".tmp")
        fd = os.open(temporary, os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical(self.completed) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)

    def prepare_target(self, entry, plan):
        head = self.worker.gitops.repo("GET", "git/ref/heads/main")["object"]["sha"]
        actual = self.files_at(self.worker.gitops, plan.target_files, head)
        if any(not plan_bytes_equal(p, actual[p], v) for p, v in plan.target_files.items()):
            raise ValueError("Merged target configuration differs from reviewed setup")
        resources = [
            strict_json(v.encode())
            for p, v in plan.target_files.items()
            if p.endswith(".json") and p.startswith(("clusters/", "argocd/projects/"))
        ]
        # Never apply the Argo Application during preparation: that could deploy source.
        selected = [
            r
            for r in resources
            if r["kind"] in {"Namespace", "ResourceQuota", "LimitRange", "AppProject"}
        ]
        for resource in sorted(
            selected,
            key=lambda r: {"Namespace": 0, "ResourceQuota": 1, "LimitRange": 2, "AppProject": 3}[
                r["kind"]
            ],
        ):
            self.safe_apply(resource, entry)

    def safe_apply(self, resource, entry):
        target = entry.environments["dev"]
        kind, metadata = resource["kind"], resource["metadata"]
        allowed = {
            "Namespace": target.namespace,
            "ResourceQuota": "aegis-budget",
            "LimitRange": "aegis-container-limits",
            "AppProject": target.argo_project,
            "Application": target.argo_application,
        }
        if kind not in allowed or metadata["name"] != allowed[kind]:
            raise ValueError("Unapproved Kubernetes resource")
        namespace = (
            None
            if kind == "Namespace"
            else "argocd"
            if kind in {"AppProject", "Application"}
            else target.namespace
        )
        if metadata.get("namespace") != namespace:
            raise ValueError("Resource namespace differs from the registered target")
        # Refuse to adopt a pre-existing object owned by another app or environment.
        query = (
            self.agent.kube
            + (["-n", namespace] if namespace else [])
            + ["get", kind.lower(), metadata["name"], "--ignore-not-found", "-o", "json"]
        )
        existing = subprocess.check_output(query, text=True)
        if existing:
            labels = strict_json(existing.encode())["metadata"].get("labels", {})
            if (
                labels.get("aegis.io/app") != entry.app_id
                or labels.get("aegis.io/environment") != "dev"
            ):
                raise ValueError("Existing resource is not owned by this registered DEV target")
        subprocess.run(
            self.agent.kube + ["apply", "--dry-run=server", "-f", "-"],
            input=canonical(resource),
            check=True,
            capture_output=True,
        )
        subprocess.run(
            self.agent.kube + ["apply", "-f", "-"],
            input=canonical(resource),
            check=True,
            capture_output=True,
        )

        observed_raw = subprocess.check_output(query, text=True)
        if not observed_raw:
            raise ValueError("The prepared resource is not observable")
        observed = strict_json(observed_raw.encode())
        labels = observed["metadata"].get("labels", {})
        if any(labels.get(key) != value for key, value in metadata.get("labels", {}).items()):
            raise ValueError("Prepared resource labels differ from the approved target")
        if kind == "Namespace":
            if observed.get("status", {}).get("phase") != "Active" or observed["metadata"].get(
                "deletionTimestamp"
            ):
                raise Pending("DEV namespace is still becoming active.")
        elif canonical(observed.get("spec", {})) != canonical(resource["spec"]):
            raise ValueError("Observed target permissions differ from the reviewed setup")

    def activate_after_signed_deployment(self, entry, delivery):
        target = entry.environments["dev"]
        _head, files, anchor = self.worker.target_files(entry, "dev")
        current = current_state(entry, "dev", files, anchor, digest(delivery.model_dump()))
        if current is None:
            return  # Preparation has no signed release selection, so it must not deploy.
        pointer_path = target.values_path.rsplit("/", 1)[0] + "/release.json"
        pointer = strict_json(files[pointer_path])
        binding_path = f"argocd/applications/{target.argo_application}.json"
        binding = pointer["desired_state"]["controller_bindings"][binding_path]
        existing = subprocess.check_output(
            self.agent.kube
            + [
                "-n",
                "argocd",
                "get",
                "application",
                target.argo_application,
                "--ignore-not-found",
                "-o",
                "json",
            ],
            text=True,
        )
        if existing:
            live = strict_json(existing.encode())
            labels = live["metadata"].get("labels", {})
            if (
                live["spec"] != binding["spec"]
                or labels.get("aegis.io/app") != entry.app_id
                or labels.get("aegis.io/environment") != "dev"
            ):
                raise ValueError(
                    "Existing Argo Application differs from its current reviewed binding"
                )
            return  # Read-only observation needs no new deployment authorization.
        rid = pointer["delivery_id"]
        _revision, catalog, policy, trust, bootstrap = self.worker.snapshot()
        record_ref = self.worker.platform.repo("GET", "git/ref/heads/portal-requests/" + rid)[
            "object"
        ]["sha"]
        record = strict_json(self.worker.platform.file("record.json", record_ref))
        issue = self.worker.platform.repo(
            "GET", "issues/" + str(record["payload"]["binding"]["number"])
        )
        intent = verify_request(record, issue, trust, rid, datetime.now(UTC))
        if intent.expected_desired_fingerprint is not None:
            # Existing controller bindings remain under the established deployment path.
            return
        if intent.model_dump() != pointer["intent"]:
            raise ValueError("Desired state does not match the signed delivery request")
        source = self.worker.source_factory(entry)
        collaborators = source.pages("collaborators", affiliation="all")
        push = any(
            str(u["id"]) == intent.requester_user_id and u.get("permissions", {}).get("push")
            for u in collaborators
        )
        release = source.repo("GET", "releases/" + intent.release_id)
        assets = [a for a in release["assets"] if a["name"] == "release.json"]
        if len(assets) != 1:
            raise ValueError("Missing admitted release receipt")
        raw = source.repo("GET", "releases/assets/" + str(assets[0]["id"]), raw=True)
        evidence = ReleaseEvidence.model_validate(strict_json(raw))
        run = source.repo(
            "GET", f"actions/runs/{evidence.workflow_run_id}/attempts/{evidence.run_attempt}"
        )
        before = {p: v for p, v in files.items() if p not in {target.values_path, pointer_path}}
        expected = proposal(
            intent=intent,
            catalog=catalog,
            catalog_revision=intent.catalog_revision,
            policy=policy,
            bootstrap_policy=bootstrap,
            chart=CHARTS / entry.versions.chart_version,
            raw_receipt=raw,
            release=release,
            repository=source.repo("GET", ""),
            run=run,
            source_push=push,
            source_comparison=None,
            git_files=before,
            current_anchor=None,
            cache_statuses=source.pages(f"commits/{evidence.source_commit}/statuses"),
            now=datetime.now(UTC),
        )
        if any(files.get(p) != value for p, value in expected.items()):
            raise ValueError(
                "Merged DEV bytes differ from the independently admitted signed request"
            )
        binding = pointer["desired_state"]["controller_bindings"][
            f"argocd/applications/{target.argo_application}.json"
        ]
        self.safe_apply(binding, entry)
