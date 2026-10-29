import io
import json
import stat
import zipfile

import httpx
import pytest

from app.errors import PortalError
from app.main import create_app
from app.upload_github import UploadGitHub
from app.uploads import MAX_ZIP, inspect_zip


def archive(files=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as z:
        for name, value in (
            files
            or {
                "app/main.py": "from fastapi import FastAPI",
                "requirements.txt": "fastapi==0.162.0",
            }
        ).items():
            z.writestr(name, value)
    return output.getvalue()


def inspect(client, files=None):
    response = client.post(
        "/api/v1/uploads", content=archive(files), headers={"Content-Type": "application/zip"}
    )
    assert response.status_code == 201, response.text
    return response.json()


def review_and_create(client, upload):
    uid = upload["upload_id"]
    review = client.post(f"/api/v1/uploads/{uid}/review", json={"name": "hello-portal"})
    assert review.status_code == 200, review.text
    response = client.post(
        f"/api/v1/uploads/{uid}/confirm", json={"review_token": review.json()["review_token"]}
    )
    assert response.status_code == 200, response.text
    return response.json()


@pytest.mark.parametrize(
    "name", ["../escape", "/etc/config", "C:/app.py", "a/../../b", "a\\b", "a//b", "a/./b"]
)
def test_unsafe_archive_paths_rejected(name):
    with pytest.raises(PortalError):
        inspect_zip(archive({name: "unsafe"}))


def test_symlinks_duplicates_and_path_collisions_rejected():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as z:
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        z.writestr(link, "../outside")
    with pytest.raises(PortalError):
        inspect_zip(output.getvalue())
    for files in ({"README": "a", "readme": "b"}, {"app": "file", "app/main.py": "code"}):
        with pytest.raises(PortalError):
            inspect_zip(archive(files))


def test_limits_and_invalid_zip(portal):
    client, _ = portal
    for body, expected in [(b"not a zip", 422), (b"x" * (MAX_ZIP + 1), 413)]:
        assert (
            client.post(
                "/api/v1/uploads", content=body, headers={"Content-Type": "application/zip"}
            ).status_code
            == expected
        )
    assert client.post("/api/v1/uploads", content=b"{}").status_code == 415
    with pytest.raises(PortalError):
        inspect_zip(archive({"large": b"x" * (1024 * 1024 + 1)}))


def test_exclusions_and_secret_blocking(portal):
    client, app = portal
    files = {
        "sample/app/main.py": "from fastapi import FastAPI",
        "sample/requirements.txt": "fastapi==0.162.0",
        "sample/.env": "password=local",
        "sample/.git/config": "git",
        "sample/.venv/lib.py": "dep",
        "sample/.github/workflows/deploy.yml": "on: push",
        "sample/node_modules/a.js": "dep",
    }
    clean = inspect(client, files)
    assert {f["path"] for f in clean["files"]} == {"app/main.py", "requirements.txt"}
    assert len(clean["excluded"]) == 5
    files["sample/app/main.py"] = "token = '" + "ghp_" + "a" * 36 + "'"
    blocked = inspect(client, files)
    assert blocked["status"] == "blocked"
    assert blocked["blocked"] == ["app/main.py"]
    assert "ghp_" not in json.dumps(blocked)
    assert client.get(f"/api/v1/uploads/{blocked['upload_id']}").status_code == 404
    assert b"ghp_" not in app.state.uploads.path.read_bytes()


def test_upload_to_registration_and_restart_recovery(portal, settings, fields):
    client, app = portal
    upload = inspect(client)
    uid = upload["upload_id"]
    assert client.post(f"/api/v1/uploads/{uid}/resume").status_code == 409
    created = review_and_create(client, upload)
    again = client.post(f"/api/v1/uploads/{uid}/resume").json()
    assert created["repository"] == again["repository"]
    repos = client.get("/api/v1/repositories").json()["items"]
    assert sum(r["full_name"] == "demo/hello-portal" for r in repos) == 1
    fields["repository_id"] = created["repository"]["repository_id"]
    fields["app_id"] = "hello-portal"
    preparation = client.post(f"/api/v1/uploads/{uid}/preparation", json=fields)
    assert preparation.status_code == 200, preparation.text
    proposal = preparation.json()
    assert proposal["installation_method"] == "manual_reviewed_commit"
    assert len(proposal["proposed_files"]) == 2
    assert all("@" + "a" * 40 in f["content"] for f in proposal["proposed_files"])
    assert "requirements-prod.txt" in " ".join(proposal["missing_requirements"])
    preview = client.post("/api/v1/registration-validations", json=fields)
    assert preview.status_code == 200, preview.text
    assert app.state.service.backend.catalog() == []
    # No catalog proposal, release or deployment happens because of upload.
    assert app.state.service.backend.journal_ids() == []
    from fastapi.testclient import TestClient

    with TestClient(create_app(settings)) as restarted:
        restarted.post("/auth/demo", headers={"Origin": "http://testserver"})
        assert restarted.get(f"/api/v1/uploads/{uid}").json()["status"] == "uploaded"
        assert any(
            r["repository_id"] == fields["repository_id"]
            for r in restarted.get("/api/v1/repositories").json()["items"]
        )


def test_auth_csrf_and_private_visibility(portal):
    client, app = portal
    upload = inspect(client)
    uid = upload["upload_id"]
    assert (
        client.post(
            f"/api/v1/uploads/{uid}/review", json={"name": "test", "visibility": "private"}
        ).status_code
        == 422
    )
    assert (
        client.post(
            f"/api/v1/uploads/{uid}/review", json={"name": "test"}, headers={"X-CSRF-Token": "bad"}
        ).status_code
        == 403
    )
    sid = app.state.sessions.create("2", "other", "demo-token")
    client.cookies.set("aegis_demo_session", sid)
    assert client.get(f"/api/v1/uploads/{uid}").status_code == 403
    client.cookies.clear()
    assert client.get(f"/api/v1/uploads/{uid}").status_code == 401


class Provider(UploadGitHub):
    def __init__(self, fail=None):
        self.fail = fail
        self.calls = []
        self.repo = None
        self.head = "initial"
        self.visible = True

    def upload_destination(self, session, org, name):
        if self.repo:
            raise AssertionError("A recovery must not repeat destination creation checks")

    def repositories(self, session):
        return (
            [
                {
                    "repository_id": "123",
                    "installation_id": "903",
                    "full_name": "demo/hello-portal",
                    "default_branch": "main",
                }
            ]
            if self.visible
            else []
        )

    def installation_token(self, iid, ids, permissions):
        assert permissions == {"contents": "write"}
        return "scoped"

    def api(self, method, path, token, **kwargs):
        self.calls.append((method, path, kwargs.get("json")))
        if method == "POST" and path == "/orgs/demo/repos":
            self.repo = {
                "id": 123,
                "full_name": "demo/hello-portal",
                "private": False,
                "description": kwargs["json"]["description"],
                "default_branch": "main",
            }
            if self.fail == "create":
                self.fail = None
                raise PortalError(503, "LOST", "Lost create response", True)
            return httpx.Response(201, json=self.repo)
        if method == "GET" and path == "/repos/demo/hello-portal":
            return httpx.Response(200 if self.repo else 404, json=self.repo or {})
        if method == "GET" and "/git/refs/" in path:
            return httpx.Response(200, json={"object": {"sha": self.head}})
        if method == "GET" and path.endswith("/git/commits/initial"):
            return httpx.Response(200, json={"parents": [], "tree": {"sha": "initial-tree"}})
        if method == "GET" and path.endswith("/git/trees/initial-tree"):
            return httpx.Response(200, json={"tree": [{"path": "README.md"}], "truncated": False})
        if method == "PATCH":
            assert kwargs["json"]["force"] is False
            self.head = kwargs["json"]["sha"]
            if self.fail == "ref":
                self.fail = None
                raise PortalError(503, "LOST", "Lost ref response", True)
            return httpx.Response(200, json={})
        if path.endswith(("/blobs", "/trees", "/commits")):
            return httpx.Response(201, json={"sha": path.rsplit("/", 1)[1]})
        raise AssertionError((method, path))


@pytest.mark.parametrize("failure", ["create", "ref"])
def test_real_adapter_lost_response_recovery_never_duplicates(portal, failure):
    client, app = portal
    upload = inspect(client)
    uid = upload["upload_id"]
    review = client.post(f"/api/v1/uploads/{uid}/review", json={"name": "hello-portal"}).json()
    provider = Provider(failure)
    app.state.uploads.demo = False
    app.state.uploads.backend = provider
    response = client.post(
        f"/api/v1/uploads/{uid}/confirm", json={"review_token": review["review_token"]}
    )
    assert response.status_code == 503
    recovered = client.post(f"/api/v1/uploads/{uid}/resume")
    assert recovered.status_code == 200, recovered.text
    assert recovered.json()["status"] == "uploaded"
    assert sum(path == "/orgs/demo/repos" for _, path, _ in provider.calls) == 1
    assert not any("workflows" in path or "dispatch" in path for _, path, _ in provider.calls)
    assert client.post(f"/api/v1/uploads/{uid}/resume").status_code == 200


def test_app_access_failure_shows_created_repository(portal):
    client, app = portal
    uid = inspect(client)["upload_id"]
    review = client.post(f"/api/v1/uploads/{uid}/review", json={"name": "hello-portal"}).json()
    provider = Provider()
    provider.visible = False
    app.state.uploads.demo = False
    app.state.uploads.backend = provider
    assert (
        client.post(
            f"/api/v1/uploads/{uid}/confirm", json={"review_token": review["review_token"]}
        ).status_code
        == 409
    )
    record = client.get(f"/api/v1/uploads/{uid}").json()
    assert record["repository"]["full_name"] == "demo/hello-portal"
    assert record["status"] == "repository_created"
    provider.visible = True
    assert client.post(f"/api/v1/uploads/{uid}/resume").json()["status"] == "uploaded"
    assert sum(path == "/orgs/demo/repos" for _, path, _ in provider.calls) == 1


def test_excluded_root_is_not_unwrapped_into_source():
    for prefix in (".git", "node_modules", ".venv", ".env"):
        result = inspect_zip(
            archive({f"{prefix}/main.py": "code", f"{prefix}/requirements.txt": "deps"})
        )
        assert result["files"] == {}
        assert not result["python_supported"]
    workflows = inspect_zip(archive({".github/workflows/ci.yml": "on: push"}))
    assert workflows["files"] == {}


def test_archive_expansion_bomb_and_entry_budget():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("zeros.txt", b"0" * (512 * 1024))
    with pytest.raises(PortalError):
        inspect_zip(output.getvalue())
    with pytest.raises(PortalError):
        inspect_zip(archive({f"{i}.py": "x" for i in range(501)}))


def test_changed_review_and_organization_fail_closed(portal):
    client, app = portal
    uid = inspect(client)["upload_id"]
    first = client.post(f"/api/v1/uploads/{uid}/review", json={"name": "first"}).json()
    second = client.post(f"/api/v1/uploads/{uid}/review", json={"name": "second"}).json()
    assert (
        client.post(
            f"/api/v1/uploads/{uid}/confirm", json={"review_token": first["review_token"]}
        ).status_code
        == 409
    )
    app.state.uploads.organization = "changed-org"
    assert (
        client.post(
            f"/api/v1/uploads/{uid}/confirm", json={"review_token": second["review_token"]}
        ).status_code
        == 409
    )
    assert client.get(f"/api/v1/uploads/{uid}").json()["status"] == "inspected"


def test_no_create_retry_when_ambiguous_repository_not_visible(portal):
    client, app = portal
    uid = inspect(client)["upload_id"]
    review = client.post(f"/api/v1/uploads/{uid}/review", json={"name": "hello-portal"}).json()
    provider = Provider("create")
    app.state.uploads.demo = False
    app.state.uploads.backend = provider
    assert (
        client.post(
            f"/api/v1/uploads/{uid}/confirm", json={"review_token": review["review_token"]}
        ).status_code
        == 503
    )
    provider.repo = None
    response = client.post(f"/api/v1/uploads/{uid}/resume")
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "UPLOAD_CREATION_UNCERTAIN"
    assert sum(path == "/orgs/demo/repos" for _, path, _ in provider.calls) == 1
    assert client.delete(f"/api/v1/uploads/{uid}").status_code == 409


def test_parallel_confirmations_and_restart_reuse_reservation(portal):
    from concurrent.futures import ThreadPoolExecutor

    from app.uploads import UploadService

    client, app = portal
    uid = inspect(client)["upload_id"]
    review = client.post(f"/api/v1/uploads/{uid}/review", json={"name": "hello-portal"}).json()
    service = app.state.uploads
    provider = Provider()
    service.demo, service.backend = False, provider
    other = UploadService(service.config, provider, service.signer, service.path, "demo")
    session = app.state.sessions.get(client.cookies.get("aegis_demo_session"))
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(lambda s: s.confirm(session, uid, review["review_token"]), [service, other])
        )
    assert all(r["status"] == "uploaded" for r in results)
    assert sum(path == "/orgs/demo/repos" for _, path, _ in provider.calls) == 1
    assert other.resume(session, uid)["repository"] == results[0]["repository"]
    assert client.delete(f"/api/v1/uploads/{uid}").status_code == 200
    assert client.get(f"/api/v1/uploads/{uid}").status_code == 404


@pytest.mark.parametrize(
    "content",
    [
        "-----BEGIN PRIVATE KEY-----",
        "aws_secret_access_key = '" + "a" * 40 + "'",
        "database_url = 'postgresql://user:hardcoded-password@db/app'",
        "token = '" + "a" * 40 + "'",
    ],
)
def test_common_credentials_blocked(content):
    record = inspect_zip(archive({"main.py": content, "requirements.txt": "fastapi"}))
    assert record["blocked"] == ["main.py"]


def test_environment_reference_is_not_a_hardcoded_secret():
    record = inspect_zip(
        archive({"main.py": 'password = os.environ.get("PASSWORD")', "requirements.txt": "fastapi"})
    )
    assert record["blocked"] == []


@pytest.mark.parametrize(
    "role,selection,installation,exists,expected",
    [
        ("member", "all", "903", False, "UPLOAD_ORG_FORBIDDEN"),
        ("admin", "selected", "903", False, "UPLOAD_APP_ACCESS"),
        ("admin", "all", "999", False, "UPLOAD_APP_ACCESS"),
        ("admin", "all", "903", True, "REPOSITORY_EXISTS"),
        ("admin", "all", "903", False, None),
    ],
)
def test_live_destination_authorization(role, selection, installation, exists, expected):
    from types import SimpleNamespace

    class DestinationProvider(UploadGitHub):
        config = SimpleNamespace(source_installation_ids=["903"])

        def validate_session(self, session):
            assert session.user_token == "user-token"

        def paginate(self, path, token, collection):
            return [
                {
                    "id": installation,
                    "account": {"login": "demo"},
                    "repository_selection": selection,
                    "permissions": {"repository_creation": "write"},
                }
            ]

        def api(self, method, path, token, **kwargs):
            assert method == "GET"
            if path.startswith("/user/memberships/"):
                return httpx.Response(200, json={"state": "active", "role": role})
            return httpx.Response(200 if exists else 404, json={})

    provider = DestinationProvider()
    session = SimpleNamespace(user_token="user-token")
    if expected:
        with pytest.raises(PortalError) as error:
            provider.upload_destination(session, "demo", "hello-portal")
        assert error.value.code == expected
    else:
        provider.upload_destination(session, "demo", "hello-portal")


def test_personal_destination_checks_verified_owner_and_creation_permission():
    from types import SimpleNamespace

    class PersonalProvider(UploadGitHub):
        config = SimpleNamespace(source_installation_ids=["903"])
        permission = "write"
        login = "demo"

        def validate_session(self, session):
            pass

        def paginate(self, path, token, collection):
            return [
                {
                    "id": "903",
                    "account": {"login": "demo"},
                    "repository_selection": "all",
                    "permissions": {"repository_creation": self.permission},
                }
            ]

        def api(self, method, path, token, **kwargs):
            if path == "/user":
                return httpx.Response(200, json={"id": 1, "login": self.login})
            assert path == "/repos/demo/new-app"
            return httpx.Response(404, json={})

    provider = PersonalProvider()
    session = SimpleNamespace(user_id="1", user_token="user-token")
    provider.upload_destination(session, "demo", "new-app", "User")
    provider.permission = "read"
    with pytest.raises(PortalError) as error:
        provider.upload_destination(session, "demo", "new-app", "User")
    assert error.value.code == "UPLOAD_CREATION_PERMISSION_REQUIRED"
    provider.login = "another-owner"
    with pytest.raises(PortalError) as error:
        provider.upload_destination(session, "demo", "new-app", "User")
    assert error.value.code == "UPLOAD_OWNER_FORBIDDEN"


def test_personal_creation_uses_user_endpoint(portal):
    client, app = portal
    uid = inspect(client)["upload_id"]
    review = client.post(f"/api/v1/uploads/{uid}/review", json={"name": "hello-portal"}).json()

    class PersonalCreationProvider(Provider):
        def upload_destination(self, session, org, name, owner_type="Organization"):
            assert owner_type == "User"

        def api(self, method, path, token, **kwargs):
            if method == "POST" and path == "/user/repos":
                result = super().api(method, "/orgs/demo/repos", token, **kwargs)
                self.calls[-1] = (method, path, kwargs.get("json"))
                return result
            return super().api(method, path, token, **kwargs)

    provider = PersonalCreationProvider()
    app.state.uploads.demo = False
    app.state.uploads.backend = provider
    app.state.uploads.owner_type = "User"
    with app.state.uploads.db() as db:
        record = app.state.uploads.load(
            db, uid, app.state.sessions.get(client.cookies.get("aegis_demo_session"))
        )
        record["owner_type"] = "User"
        app.state.uploads.save(db, uid, record)
    result = client.post(
        f"/api/v1/uploads/{uid}/confirm", json={"review_token": review["review_token"]}
    )
    assert result.status_code == 200, result.text
    assert result.json()["status"] == "uploaded"
    assert any(path == "/user/repos" for _, path, _ in provider.calls)
    assert not any(path.startswith("/orgs/") for _, path, _ in provider.calls)
