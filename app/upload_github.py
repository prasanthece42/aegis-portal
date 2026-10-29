"""GitHub import operations: no workflow writes, merges, dispatches or deployment."""

from urllib.parse import quote

from app.errors import PortalError


class UploadGitHub:
    def upload_destination(self, session, organization, name, owner_type="Organization"):
        self.validate_session(session)
        if owner_type == "User":
            user = self.api("GET", "/user", session.user_token).json()
            if (
                str(user.get("id")) != session.user_id
                or user.get("login", "").lower() != organization.lower()
            ):
                raise PortalError(
                    403,
                    "UPLOAD_OWNER_FORBIDDEN",
                    "Personal repositories can only be created in your configured GitHub account.",
                )
        else:
            membership = self.api(
                "GET", f"/user/memberships/orgs/{organization}", session.user_token
            ).json()
            if membership.get("state") != "active" or membership.get("role") != "admin":
                raise PortalError(
                    403,
                    "UPLOAD_ORG_FORBIDDEN",
                    "Repository creation currently requires organization owner access.",
                )
        # The destination must have an installation approved by platform policy.
        installs = self.paginate("/user/installations", session.user_token, "installations")
        approved = [
            i
            for i in installs
            if str(i["id"]) in self.config.source_installation_ids
            and i.get("account", {}).get("login", "").lower() == organization.lower()
            and i.get("repository_selection") == "all"
        ]
        if not approved:
            raise PortalError(
                409,
                "UPLOAD_APP_ACCESS",
                "The allowed account needs an approved GitHub App installation "
                "covering all repositories before creation.",
            )
        if not any(
            i.get("permissions", {}).get("repository_creation") == "write" for i in approved
        ):
            raise PortalError(
                409,
                "UPLOAD_CREATION_PERMISSION_REQUIRED",
                "Enable and approve Repository creation: write for the GitHub App, "
                "then sign in again before creating a repository.",
            )
        response = self.api(
            "GET", f"/repos/{organization}/{name}", session.user_token, allow=(404,)
        )
        if response.status_code != 404:
            raise PortalError(
                409, "REPOSITORY_EXISTS", "Repository name is already in use. Choose another name."
            )

    def upload_repository(self, session, record, save):
        repo = record["organization"] + "/" + record["name"]
        user_token = session.user_token
        # No second create after an ambiguous response, even if a repository is later deleted.
        if not record.get("creation_attempted"):
            if record.get("owner_type") == "User":
                self.upload_destination(session, record["organization"], record["name"], "User")
            else:
                self.upload_destination(session, record["organization"], record["name"])
            record["creation_attempted"] = True
            save()
            response = self.api(
                "POST",
                "/user/repos"
                if record.get("owner_type") == "User"
                else f"/orgs/{record['organization']}/repos",
                user_token,
                allow=(401, 403, 404, 422),
                json={
                    "name": record["name"],
                    "private": False,
                    "auto_init": True,
                    "description": record["marker"],
                },
            )
            if response.status_code in {401, 403, 404, 422}:
                record["creation_attempted"] = False
                save()
                raise PortalError(
                    409,
                    "UPLOAD_CREATION_DENIED",
                    "GitHub rejected creation. Check organization policy and the App's "
                    "explicit repository-creation authorization, then resume.",
                )
            result = response.json()
            record["repository"] = {
                "repository_id": str(result["id"]),
                "full_name": result["full_name"],
                "default_branch": result["default_branch"],
            }
            record["status"] = "repository_created"
            save()
        result = self.api("GET", f"/repos/{repo}", user_token, allow=(404,))
        if result.status_code == 404:
            raise PortalError(
                409,
                "UPLOAD_CREATION_UNCERTAIN",
                "Creation was attempted but the repository is not visible. "
                "Retry recovery later or ask an operator to inspect GitHub. "
                "No second repository will be created.",
            )
        result = result.json()
        if (
            result.get("description") != record["marker"]
            or result.get("private")
            or result.get("full_name", "").lower() != repo.lower()
            or (
                record.get("repository")
                and str(result["id"]) != record["repository"]["repository_id"]
            )
        ):
            raise PortalError(
                409,
                "UPLOAD_REPOSITORY_CHANGED",
                "Repository identity or visibility changed; operator recovery is required.",
            )
        # Current user push access and approved App access, freshly checked before source upload.
        choices = self.repositories(session)
        target = next((r for r in choices if r["repository_id"] == str(result["id"])), None)
        if not target:
            raise PortalError(
                409,
                "UPLOAD_APP_ACCESS",
                "Repository exists. Grant the approved GitHub App and your identity access, "
                "then resume this upload.",
            )
        record["repository"] = target
        if record["status"] == "uploaded":
            return
        record["status"] = "repository_created"
        save()
        token = self.installation_token(
            target["installation_id"], [target["repository_id"]], {"contents": "write"}
        )
        branch = target["default_branch"]
        ref = f"/repos/{repo}/git/refs/heads/{quote(branch, safe='')}"
        head = self.api("GET", ref, token).json()["object"]["sha"]
        if record.get("commit") == head:
            record["status"] = "uploaded"
            save()
            return
        if record.get("initial_head") and head != record["initial_head"]:
            raise PortalError(
                409,
                "UPLOAD_BRANCH_CHANGED",
                "Repository changed during upload; no files were overwritten. "
                "Operator recovery is required.",
            )
        if not record.get("initial_head"):
            initial = self.api("GET", f"/repos/{repo}/git/commits/{head}", token).json()
            initial_tree = self.api(
                "GET", f"/repos/{repo}/git/trees/{initial['tree']['sha']}", token
            ).json()
            if (
                initial.get("parents")
                or initial_tree.get("truncated")
                or [entry["path"] for entry in initial_tree.get("tree", [])] != ["README.md"]
            ):
                raise PortalError(
                    409,
                    "UPLOAD_BRANCH_CHANGED",
                    "The new repository already has other changes. "
                    "Operator recovery is required before importing source.",
                )
        record["initial_head"] = head
        save()
        if not record.get("tree"):
            tree = []
            for path, content in record["files"].items():
                blob = self.api(
                    "POST",
                    f"/repos/{repo}/git/blobs",
                    token,
                    json={"content": content, "encoding": "base64"},
                ).json()
                tree.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
            # Deliberately no base_tree: the final snapshot is exactly the reviewed file list.
            record["tree"] = self.api(
                "POST", f"/repos/{repo}/git/trees", token, json={"tree": tree}
            ).json()["sha"]
            save()
        if not record.get("commit"):
            record["commit"] = self.api(
                "POST",
                f"/repos/{repo}/git/commits",
                token,
                json={
                    "message": "Import reviewed project " + record["marker"],
                    "tree": record["tree"],
                    "parents": [head],
                },
            ).json()["sha"]
            save()
        self.api("PATCH", ref, token, json={"sha": record["commit"], "force": False})
        record["status"] = "uploaded"
        save()
