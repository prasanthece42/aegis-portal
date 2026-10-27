"""Bounded GitHub transport. Credentials never enter URLs, responses or logs."""

import base64
import hashlib
import json
import os
import threading
import time
from pathlib import Path
from urllib.parse import quote, urlencode

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.config import LiveConfig
from app.delivery_github import DeliveryGitHub
from app.errors import PortalError
from app.security import Session, b64, canonical, strict_json


class GitHub(DeliveryGitHub):
    def __init__(self, config: LiveConfig, client: httpx.Client | None = None):
        self.config = config
        self.client = client or httpx.Client(timeout=15, follow_redirects=False)
        self.private_key = serialization.load_pem_private_key(
            Path(os.environ["AEGIS_APP_PRIVATE_KEY_FILE"]).read_bytes(), password=None
        )
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise ValueError("GitHub App requires an RSA private key")
        self.client_secret = os.environ["AEGIS_GITHUB_CLIENT_SECRET"]
        self.tokens: dict[tuple, tuple[str, float]] = {}
        self.lock = threading.RLock()

    def api(self, method: str, path: str, token: str, *, allow=(), **kwargs):
        if not path.startswith("/") or path.startswith("//"):
            raise ValueError("GitHub API path must be relative")
        try:
            response = self.client.request(
                method,
                "https://api.github.com" + path,
                headers={
                    "Authorization": "Bearer " + token,
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2026-03-10",
                },
                **kwargs,
            )
        except httpx.HTTPError as exc:
            raise PortalError(
                503, "GITHUB_UNAVAILABLE", "GitHub is unavailable; retry safely.", True
            ) from exc
        if response.status_code in allow:
            return response
        if response.status_code == 429 or (
            response.status_code == 403
            and (
                "Retry-After" in response.headers
                or response.headers.get("X-RateLimit-Remaining") == "0"
            )
        ):
            raise PortalError(
                429, "GITHUB_THROTTLED", "GitHub rate limit reached; retry later.", True
            )
        if response.status_code >= 400:
            raise PortalError(
                503,
                "GITHUB_OPERATION_FAILED",
                "GitHub could not complete the operation; check App permissions and availability.",
                response.status_code >= 500,
            )
        return response

    def installation_token(
        self, installation: str, repository_ids: list[str], permissions: dict
    ) -> str:
        cache_key = (
            installation,
            tuple(sorted(repository_ids)),
            tuple(sorted(permissions.items())),
        )
        with self.lock:
            cached = self.tokens.get(cache_key)
            if cached and cached[1] > time.time():
                return cached[0]
            now = int(time.time())
            header = b64(canonical({"alg": "RS256", "typ": "JWT"}))
            payload = b64(canonical({"iat": now - 60, "exp": now + 540, "iss": self.config.app_id}))
            unsigned = (header + "." + payload).encode()
            signature = self.private_key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
            jwt = unsigned.decode() + "." + b64(signature)
            token = self.api(
                "POST",
                f"/app/installations/{installation}/access_tokens",
                jwt,
                json={
                    "repository_ids": [int(x) for x in repository_ids],
                    "permissions": permissions,
                },
            ).json()["token"]
            self.tokens[cache_key] = (token, time.time() + 3000)
            return token

    def platform_token(self, *, write=False) -> str:
        permissions = {
            "contents": "write" if write else "read",
            "pull_requests": "write" if write else "read",
        }
        return self.installation_token(
            self.config.platform_installation_id, [self.config.platform_repository_id], permissions
        )

    def paginate(self, path: str, token: str, collection: str | None = None, **params) -> list:
        items = []
        for page in range(1, 11):
            response = self.api(
                "GET", path, token, params={**params, "per_page": 100, "page": page}
            )
            value = response.json()
            items.extend(value[collection] if collection else value)
            if 'rel="next"' not in response.headers.get("Link", ""):
                return items
        raise PortalError(
            503, "DISCOVERY_LIMIT", "Repository discovery exceeded the bounded page budget."
        )

    def oauth_url(self, state: str, verifier: str) -> str:
        return "https://github.com/login/oauth/authorize?" + urlencode(
            {
                "client_id": self.config.client_id,
                "redirect_uri": self.config.public_origin + "/auth/github/callback",
                "state": state,
                "code_challenge": b64(hashlib.sha256(verifier.encode()).digest()),
                "code_challenge_method": "S256",
            }
        )

    def exchange(self, code: str, verifier: str) -> tuple[dict, str, int]:
        try:
            response = self.client.post(
                "https://github.com/login/oauth/access_token",
                headers={"Accept": "application/json"},
                json={
                    "client_id": self.config.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "code_verifier": verifier,
                    "redirect_uri": self.config.public_origin + "/auth/github/callback",
                },
            )
            response.raise_for_status()
            data = response.json()
            token = data["access_token"]
            expires = int(data["expires_in"])
            if expires <= 0:
                raise ValueError("Expired user token")
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            raise PortalError(
                401, "SIGN_IN_FAILED", "GitHub sign-in failed or expiring tokens are not enabled."
            ) from exc
        user = self.api("GET", "/user", token).json()
        return user, token, min(expires, 28800)

    def repositories(self, session: Session) -> list[dict]:
        result = []
        installations = self.paginate("/user/installations", session.user_token, "installations")
        for installation in installations:
            iid = str(installation["id"])
            if iid not in self.config.source_installation_ids:
                continue
            repos = self.paginate(
                f"/user/installations/{iid}/repositories", session.user_token, "repositories"
            )
            for repo in repos:
                if str(repo["id"]) in {
                    self.config.platform_repository_id,
                    self.config.gitops_repository_id,
                }:
                    continue
                if repo["private"] or not repo.get("permissions", {}).get("push"):
                    continue
                result.append(
                    {
                        "repository_id": str(repo["id"]),
                        "installation_id": iid,
                        "full_name": repo["full_name"],
                        "default_branch": repo["default_branch"],
                    }
                )
        return result

    def source(self, session: Session, repository_id: str) -> dict:
        choices = {r["repository_id"]: r for r in self.repositories(session)}
        if repository_id not in choices:
            raise PortalError(
                404, "REPOSITORY_UNAVAILABLE", "No eligible repository is available with this ID."
            )
        result = choices[repository_id]
        token = self.installation_token(
            result["installation_id"], [repository_id], {"contents": "read"}
        )
        owner, name = result["full_name"].split("/")
        result.update(owner=owner, name=name)
        result["source_commit"] = self.api(
            "GET",
            f"/repos/{owner}/{name}/commits/{quote(result['default_branch'], safe='')}",
            token,
        ).json()["sha"]
        return result

    def file(self, repository: str, path: str, ref: str, token: str) -> bytes | None:
        response = self.api(
            "GET",
            f"/repos/{repository}/contents/{quote(path, safe='/')}",
            token,
            params={"ref": ref},
            allow=(404,),
        )
        if response.status_code == 404:
            return None
        data = response.json()
        if not isinstance(data, dict) or data.get("type") != "file" or data.get("size", 0) > 32768:
            raise PortalError(
                422, "FILE_UNSUPPORTED", "Detected configuration file exceeds supported bounds."
            )
        if data.get("encoding") != "base64":
            raise PortalError(422, "FILE_UNSUPPORTED", "Configuration content is unavailable.")
        return base64.b64decode(data["content"])

    def detection(self, source: dict) -> dict:
        token = self.installation_token(
            source["installation_id"], [source["repository_id"]], {"contents": "read"}
        )
        repo, sha = source["full_name"], source["source_commit"]
        paths = [
            "Dockerfile",
            "pyproject.toml",
            "requirements.txt",
            "uv.lock",
            ".github/workflows/ci.yml",
        ]
        files = {path: self.file(repo, path, sha, token) for path in paths}
        return {
            "source_commit": sha,
            "dockerfile_present": files["Dockerfile"] is not None,
            "dependency_lock_present": files["requirements.txt"] is not None
            or files["uv.lock"] is not None,
            "pipeline_file_present": files[".github/workflows/ci.yml"] is not None,
            "pipeline_validated": False,
            "message": (
                "File presence is preliminary detection; approved pipeline validation "
                "and operator target setup remain required."
            ),
        }

    def catalog(self) -> list[dict]:
        token = self.platform_token()
        response = self.api(
            "GET",
            f"/repos/{self.config.platform_repository}/contents/catalog/apps",
            token,
            params={"ref": self.config.platform_branch},
            allow=(404,),
        )
        if response.status_code == 404:
            return []
        files = response.json()
        if not isinstance(files, list) or len(files) > 100:
            raise PortalError(
                503, "CATALOG_UNAVAILABLE", "Catalog exceeds the initial supported budget."
            )
        return [
            strict_json(
                self.file(
                    self.config.platform_repository, f["path"], self.config.platform_branch, token
                )
            )
            for f in files
            if f["type"] == "file" and f["name"].endswith(".json")
        ]

    def journal(self, registration_id: str) -> tuple[str, dict] | None:
        branch = self.journal_branch(registration_id)
        token = self.platform_token()
        response = self.api(
            "GET",
            f"/repos/{self.config.platform_repository}/git/ref/heads/{branch}",
            token,
            allow=(404,),
        )
        if response.status_code == 404:
            return None
        sha = response.json()["object"]["sha"]
        data = self.file(self.config.platform_repository, "record.json", sha, token)
        if data is None:
            raise PortalError(503, "JOURNAL_INVALID", "Request journal is incomplete.")
        return sha, strict_json(data)

    def save_journal(self, registration_id: str, record: dict, parent: str | None) -> bool:
        token, repo = self.platform_token(write=True), self.config.platform_repository
        tree = self.api(
            "POST",
            f"/repos/{repo}/git/trees",
            token,
            json={
                "tree": [
                    {
                        "path": "record.json",
                        "mode": "100644",
                        "type": "blob",
                        "content": canonical(record).decode(),
                    }
                ]
            },
        ).json()["sha"]
        commit = self.api(
            "POST",
            f"/repos/{repo}/git/commits",
            token,
            json={
                "message": "Record portal registration " + registration_id,
                "tree": tree,
                "parents": [parent] if parent else [],
            },
        ).json()["sha"]
        branch = "heads/" + self.journal_branch(registration_id)
        if parent:
            response = self.api(
                "PATCH",
                f"/repos/{repo}/git/refs/{branch}",
                token,
                json={"sha": commit, "force": False},
                allow=(409, 422),
            )
        else:
            response = self.api(
                "POST",
                f"/repos/{repo}/git/refs",
                token,
                json={"ref": "refs/" + branch, "sha": commit},
                allow=(409, 422),
            )
        return response.status_code not in {409, 422}

    @staticmethod
    def journal_branch(operation_id: str) -> str:
        import re

        if not re.fullmatch(r"(?:reg|req)-[0-9a-f]{64}", operation_id):
            raise ValueError("Invalid journal identity")
        prefix = "portal-requests/" if operation_id.startswith("req-") else "portal-registrations/"
        return prefix + operation_id

    def registration_pr(self, registration_id: str, entry: dict) -> dict:
        repo, token = self.config.platform_repository, self.platform_token(write=True)
        branch = "portal-onboarding/" + registration_id
        existing = self.paginate(
            f"/repos/{repo}/pulls", token, state="all", head=repo.split("/")[0] + ":" + branch
        )
        if existing:
            pr = existing[0]
            if str(pr["user"]["id"]) != self.config.platform_bot_user_id:
                raise PortalError(
                    409, "PR_ISSUER_INVALID", "Existing onboarding PR has an unexpected author."
                )
            content = self.file(
                repo, "catalog/apps/" + entry["app_id"] + ".json", pr["head"]["sha"], token
            )
            if (
                content is None
                or strict_json(content) != entry
                or pr["base"]["ref"] != self.config.platform_branch
            ):
                raise PortalError(
                    409,
                    "REGISTRATION_CHANGED",
                    "Existing PR differs from the confirmed registration.",
                )
            self.verify_registration_scope(pr, branch, entry, token)
            return {"number": pr["number"], "url": pr["html_url"], "state": pr["state"]}
        head = self.api(
            "GET",
            f"/repos/{repo}/git/ref/heads/{quote(self.config.platform_branch, safe='/')}",
            token,
        ).json()["object"]["sha"]
        created = self.api(
            "POST",
            f"/repos/{repo}/git/refs",
            token,
            json={"ref": "refs/heads/" + branch, "sha": head},
            allow=(422,),
        )
        # On recovery, verify existing content instead of rewriting a pending registration.
        path = "catalog/apps/" + entry["app_id"] + ".json"
        if created.status_code == 422:
            content = self.file(repo, path, branch, token)
            if content is not None and strict_json(content) != entry:
                raise PortalError(
                    409,
                    "REGISTRATION_CHANGED",
                    "Existing onboarding branch differs from the confirmed registration.",
                )
        else:
            content = None
        if content is None:
            self.api(
                "PUT",
                f"/repos/{repo}/contents/{path}",
                token,
                json={
                    "message": "Register " + entry["app_id"],
                    "branch": branch,
                    "content": base64.b64encode(
                        (json.dumps(entry, indent=2) + "\n").encode()
                    ).decode(),
                },
            )
        pr = self.api(
            "POST",
            f"/repos/{repo}/pulls",
            token,
            json={
                "head": branch,
                "base": self.config.platform_branch,
                "title": "Register " + entry["app_id"],
                "body": "Portal registration: "
                + registration_id
                + "\n\nRequires platform review, pipeline onboarding and operator target setup. "
                "Does not deploy workloads.",
            },
            allow=(422,),
        )
        if pr.status_code == 422:
            # A concurrent creator may have completed the same deterministic PR.
            existing = self.paginate(
                f"/repos/{repo}/pulls", token, state="all", head=repo.split("/")[0] + ":" + branch
            )
            if not existing:
                raise PortalError(
                    503,
                    "PR_PENDING",
                    "Registration PR could not be confirmed; retry the same submission.",
                    True,
                )
            data = existing[0]
        else:
            data = pr.json()
        if str(data["user"]["id"]) != self.config.platform_bot_user_id:
            raise PortalError(
                409, "PR_ISSUER_INVALID", "Registration PR issuer did not match the configured App."
            )
        self.verify_registration_scope(data, branch, entry, token)
        return {"number": data["number"], "url": data["html_url"], "state": data["state"]}

    def verify_registration_scope(self, pr: dict, branch: str, entry: dict, token: str):
        expected_path = "catalog/apps/" + entry["app_id"] + ".json"
        if (
            pr["head"]["ref"] != branch
            or str(pr["head"]["repo"]["id"]) != self.config.platform_repository_id
            or pr["base"]["ref"] != self.config.platform_branch
            or str(pr["base"]["repo"]["id"]) != self.config.platform_repository_id
        ):
            raise PortalError(
                409, "PR_SCOPE_INVALID", "Registration PR targets unapproved bindings."
            )
        files = self.paginate(
            f"/repos/{self.config.platform_repository}/pulls/{pr['number']}/files", token
        )
        if (
            len(files) != 1
            or files[0]["filename"] != expected_path
            or files[0]["status"] not in {"added", "modified"}
        ):
            raise PortalError(409, "PR_SCOPE_INVALID", "Registration PR changes unexpected paths.")
        content = self.file(
            self.config.platform_repository, expected_path, pr["head"]["sha"], token
        )
        if content is None or strict_json(content) != entry:
            raise PortalError(409, "REGISTRATION_CHANGED", "Registration PR content changed.")

    def journal_ids(self) -> list[str]:
        refs = self.paginate(
            f"/repos/{self.config.platform_repository}/git/matching-refs/heads/portal-registrations/",
            self.platform_token(),
        )
        ids = [ref["ref"].rsplit("/", 1)[-1] for ref in refs]
        if len(ids) > 100:
            raise PortalError(
                503, "JOURNAL_BUDGET", "Registration history exceeds the initial 100-record budget."
            )
        return ids

    def registration_status(self, binding: dict) -> dict:
        pr = self.api(
            "GET",
            f"/repos/{self.config.platform_repository}/pulls/{binding['number']}",
            self.platform_token(),
        ).json()
        if str(pr["user"]["id"]) != self.config.platform_bot_user_id:
            raise PortalError(
                503, "PR_ISSUER_INVALID", "Registration review issuer could not be verified."
            )
        return {**binding, "state": pr["state"], "merged": bool(pr.get("merged_at"))}

    def close(self):
        self.client.close()
