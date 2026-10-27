import base64
import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.demo import DemoBackend, demo_config
from app.errors import PortalError
from app.github import GitHub
from app.main import create_app
from app.security import Signer, unb64


@pytest.fixture
def github_factory(monkeypatch, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path = tmp_path / "app.pem"
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("AEGIS_APP_PRIVATE_KEY_FILE", str(path))
    monkeypatch.setenv("AEGIS_GITHUB_CLIENT_SECRET", "test-client-secret")

    def create(handler):
        return GitHub(demo_config(), httpx.Client(transport=httpx.MockTransport(handler)))

    return create, key


def test_token_is_repository_and_permission_scoped_with_valid_app_jwt(github_factory):
    create, key = github_factory
    requests = []

    def handler(request):
        requests.append(request)
        jwt = request.headers["Authorization"].removeprefix("Bearer ")
        header, payload, signature = jwt.split(".")
        key.public_key().verify(
            unb64(signature), f"{header}.{payload}".encode(), padding.PKCS1v15(), hashes.SHA256()
        )
        body = json.loads(request.content)
        assert body == {"repository_ids": [101], "permissions": {"contents": "read"}}
        assert json.loads(unb64(payload))["iss"] == "99"
        return httpx.Response(201, json={"token": "scoped-installation-token"})

    github = create(handler)
    assert (
        github.installation_token("903", ["101"], {"contents": "read"})
        == "scoped-installation-token"
    )
    assert (
        github.installation_token("903", ["101"], {"contents": "read"})
        == "scoped-installation-token"
    )
    assert len(requests) == 1
    assert "scoped-installation-token" not in str(requests[0].url)


def test_oauth_exchange_uses_pkce_and_rejects_nonexpiring_tokens(github_factory):
    create, _key = github_factory

    def handler(request):
        if request.url.host == "github.com":
            body = json.loads(request.content)
            assert body["code_verifier"] == "original-verifier"
            assert body["client_secret"] == "test-client-secret"
            return httpx.Response(200, json={"access_token": "user-token", "expires_in": 3600})
        assert request.headers["Authorization"] == "Bearer user-token"
        return httpx.Response(200, json={"id": 1, "login": "developer"})

    user, token, lifetime = create(handler).exchange("code", "original-verifier")
    assert (user["id"], token, lifetime) == (1, "user-token", 3600)
    github = create(lambda _request: httpx.Response(200, json={"access_token": "non-expiring"}))
    with pytest.raises(PortalError) as error:
        github.exchange("code", "original-verifier")
    assert error.value.code == "SIGN_IN_FAILED"


def test_git_journal_uses_atomic_reservation_and_nonforce_updates(github_factory, monkeypatch):
    create, _key = github_factory
    seen = []

    def handler(request):
        body = json.loads(request.content)
        seen.append((request.method, request.url.path, body))
        if request.url.path.endswith("/git/trees"):
            assert body["tree"][0]["path"] == "record.json"
            return httpx.Response(201, json={"sha": "tree"})
        if request.url.path.endswith("/git/commits"):
            return httpx.Response(201, json={"sha": "new-commit"})
        if request.method == "PATCH":
            assert body == {"sha": "new-commit", "force": False}
            return httpx.Response(422, json={"message": "not fast forward"})
        assert body["ref"].startswith("refs/heads/portal-registrations/reg-")
        return httpx.Response(201, json={"ref": body["ref"]})

    github = create(handler)
    monkeypatch.setattr(github, "platform_token", lambda **_kwargs: "platform-token")
    assert github.save_journal("reg-" + "a" * 64, {"signed": "record"}, None)
    assert not github.save_journal("reg-" + "a" * 64, {"signed": "record"}, "old-commit")
    commits = [body for _method, path, body in seen if path.endswith("/git/commits")]
    assert commits[0]["parents"] == []
    assert commits[1]["parents"] == ["old-commit"]


def test_rate_limit_and_provider_errors_do_not_expose_body(github_factory):
    create, _key = github_factory
    github = create(
        lambda _request: httpx.Response(
            403, headers={"Retry-After": "60"}, text="secret provider diagnostic"
        )
    )
    with pytest.raises(PortalError) as error:
        github.api("GET", "/user", "private-token")
    assert error.value.status == 429
    assert "secret" not in error.value.message


def test_pagination_is_complete_or_fails_visibly(github_factory):
    create, _key = github_factory
    pages = []

    def handler(request):
        page = int(request.url.params["page"])
        pages.append(page)
        return httpx.Response(
            200,
            json=[{"id": page}],
            headers={"Link": '<https://api.github.com/page>; rel="next"'} if page == 1 else {},
        )

    assert create(handler).paginate("/example", "token") == [{"id": 1}, {"id": 2}]
    assert pages == [1, 2]


def test_existing_registration_pr_cannot_hide_modified_configuration(github_factory, monkeypatch):
    create, _key = github_factory
    github = create(lambda _request: httpx.Response(500))
    monkeypatch.setattr(github, "platform_token", lambda **_kwargs: "platform-token")
    monkeypatch.setattr(
        github,
        "paginate",
        lambda *_args, **_kwargs: [
            {
                "user": {"id": 902},
                "head": {"sha": "a" * 40},
                "base": {"ref": "main"},
            }
        ],
    )
    monkeypatch.setattr(github, "file", lambda *_args: b'{"app_id":"changed"}')
    with pytest.raises(PortalError) as error:
        github.registration_pr("reg-" + "b" * 64, {"app_id": "orders-api"})
    assert error.value.code == "REGISTRATION_CHANGED"


def test_live_oauth_state_is_browser_bound_single_use_and_secure(settings, tmp_path):
    config = demo_config().model_copy(update={"public_origin": "https://portal.example"})
    settings.mode, settings.live, settings.origin = "live", config, config.public_origin
    settings.cookie_name = "__Host-aegis_session"

    class Backend(DemoBackend):
        exchanged = 0

        def oauth_url(self, state, verifier):
            return "https://github.com/login/oauth/authorize?state=" + state

        def exchange(self, code, verifier):
            self.exchanged += 1
            return {"id": 1, "login": "developer"}, "server-only-token", 3600

    backend = Backend(tmp_path / "live-mocked.json")
    signer = Signer(Ed25519PrivateKey.generate(), config.signing_key_id)
    with TestClient(
        create_app(settings, backend, signer), base_url="https://portal.example"
    ) as client:
        start = client.get("/auth/github/start", follow_redirects=False)
        state = parse_qs(urlparse(start.headers["Location"]).query)["state"][0]
        assert "Secure" in start.headers["Set-Cookie"]
        bad = client.get("/auth/github/callback", params={"state": "forged", "code": "code"})
        assert bad.status_code == 401 and backend.exchanged == 0
        good = client.get(
            "/auth/github/callback", params={"state": state, "code": "code"}, follow_redirects=False
        )
        assert good.status_code == 303 and backend.exchanged == 1
        assert "Secure" in good.headers["Set-Cookie"]
        assert "HttpOnly" in good.headers["Set-Cookie"]
        assert client.get("/api/v1/session").json()["login"] == "developer"
        assert "server-only-token" not in client.get("/api/v1/session").text
        assert (
            client.get("/auth/github/callback", params={"state": state, "code": "code"}).status_code
            == 401
        )
        assert client.post("/auth/demo", headers={"Origin": settings.origin}).status_code == 404
        assert client.get("/health", headers={"Host": "127.0.0.1:8000"}).status_code == 200
        assert client.get("/api/v1/session", headers={"Host": "evil.invalid"}).status_code == 400


def test_github_content_read_is_pinned_and_bounded(github_factory):
    create, _key = github_factory

    def handler(request):
        assert request.url.params["ref"] == "a" * 40
        return httpx.Response(
            200,
            json={
                "type": "file",
                "encoding": "base64",
                "size": 3,
                "content": base64.b64encode(b"abc").decode(),
            },
        )

    assert create(handler).file("demo/orders-api", "Dockerfile", "a" * 40, "token") == b"abc"


@pytest.mark.parametrize("extra_path", [False, True])
def test_registration_creates_only_a_scoped_catalog_pr(github_factory, monkeypatch, extra_path):
    create, _key = github_factory
    rid = "reg-" + "a" * 64
    branch = "portal-onboarding/" + rid
    entry = {"app_id": "orders-api", "schema_version": 1}
    pr = {
        "number": 7,
        "user": {"id": 902},
        "state": "open",
        "html_url": "https://github.com/demo/aegis-platform/pull/7",
        "head": {"ref": branch, "sha": "b" * 40, "repo": {"id": 900}},
        "base": {"ref": "main", "repo": {"id": 900}},
    }
    writes = []

    def handler(request):
        path = request.url.path.removeprefix("/repos/demo/aegis-platform")
        if request.method != "GET":
            writes.append((request.method, path, json.loads(request.content)))
        if path == "/pulls" and request.method == "GET":
            return httpx.Response(200, json=[])
        if path == "/git/ref/heads/main":
            return httpx.Response(200, json={"object": {"sha": "c" * 40}})
        if path == "/git/refs":
            assert json.loads(request.content)["ref"] == "refs/heads/" + branch
            return httpx.Response(201, json={"ref": "refs/heads/" + branch})
        if path == "/contents/catalog/apps/orders-api.json":
            if request.method == "PUT":
                assert json.loads(request.content)["branch"] == branch
                return httpx.Response(201, json={"content": {"sha": "blob"}})
            assert request.url.params["ref"] == "b" * 40
            return httpx.Response(
                200,
                json={
                    "type": "file",
                    "size": 100,
                    "encoding": "base64",
                    "content": base64.b64encode(json.dumps(entry).encode()).decode(),
                },
            )
        if path == "/pulls" and request.method == "POST":
            assert json.loads(request.content)["base"] == "main"
            return httpx.Response(201, json=pr)
        if path == "/pulls/7/files":
            files = [{"filename": "catalog/apps/orders-api.json", "status": "added"}]
            if extra_path:
                files.append({"filename": ".github/workflows/unsafe.yml", "status": "added"})
            return httpx.Response(200, json=files)
        raise AssertionError(f"Unexpected GitHub operation {request.method} {path}")

    github = create(handler)
    monkeypatch.setattr(github, "platform_token", lambda **_kwargs: "platform-token")
    if extra_path:
        with pytest.raises(PortalError) as error:
            github.registration_pr(rid, entry)
        assert error.value.code == "PR_SCOPE_INVALID"
    else:
        assert github.registration_pr(rid, entry)["number"] == 7
    assert len(writes) == 3
    assert not any(path.endswith("/merge") for _method, path, _body in writes)
