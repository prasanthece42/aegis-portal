from types import SimpleNamespace

import httpx
from fastapi.testclient import TestClient

from tooling.run_gateway import create_gateway

ORIGIN = "https://localhost:8443"


def gateway(handler, port=12345):
    return TestClient(
        create_gateway(ORIGIN, SimpleNamespace(port=port), transport=httpx.MockTransport(handler)),
        base_url=ORIGIN,
    )


def test_gateway_preserves_oauth_redirect_and_separate_session_cookies():
    seen = []

    def upstream(request):
        seen.append(request)
        return httpx.Response(
            302,
            headers=[
                ("location", "https://github.com/login/oauth/authorize"),
                ("set-cookie", "state=one; Secure; HttpOnly"),
                ("set-cookie", "session=two; Secure; HttpOnly"),
            ],
            stream=httpx.ByteStream(b""),
        )

    with gateway(upstream) as browser_one:
        response = browser_one.get("/auth/github?return=%2F", follow_redirects=False)
    with gateway(upstream) as browser_two:
        browser_two.get("/health", follow_redirects=False)
    assert response.status_code == 302
    assert len(response.headers.get_list("set-cookie")) == 2
    assert response.headers["location"] == "https://github.com/login/oauth/authorize"
    assert seen[0].url.query == b"return=%2F"
    assert seen[0].headers["host"] == "localhost:8443"
    assert "cookie" not in seen[1].headers


def test_gateway_rejects_wrong_host_and_large_requests_before_forwarding():
    def unexpected(request):
        raise AssertionError("Rejected requests must not reach the upstream")

    with gateway(unexpected) as browser:
        assert browser.get("/health", headers={"Host": "attacker.example"}).status_code == 400
        assert browser.post("/api/v1/requests", content=b"x" * 32769).status_code == 413


def test_gateway_preserves_browser_cookie_without_trusting_forwarded_origin():
    def upstream(request):
        assert request.headers["cookie"] == "session=browser"
        assert request.headers["host"] == "localhost:8443"
        assert "forwarded" not in request.headers
        assert "x-forwarded-host" not in request.headers
        return httpx.Response(200, stream=httpx.ByteStream(b'{"status":"ok"}'))

    with gateway(upstream) as browser:
        response = browser.get(
            "/health",
            headers={
                "Cookie": "session=browser",
                "Forwarded": "host=attacker.example",
                "X-Forwarded-Host": "attacker.example",
            },
        )
        assert response.json() == {"status": "ok"}


def test_gateway_returns_retryable_failure_during_restart_or_connection_loss():
    def offline(request):
        raise httpx.ConnectError("private operator details", request=request)

    for port in [None, 12345]:
        with gateway(offline, port=port) as browser:
            response = browser.post("/api/v1/deployment-requests", json={})
            assert response.status_code == 503
            assert response.json()["error"]["retryable"] is True
            assert "private operator" not in response.text


def test_gateway_bounds_upstream_responses():
    def upstream(request):
        return httpx.Response(200, stream=httpx.ByteStream(b"x" * (8 * 1024 * 1024 + 1)))

    with gateway(upstream) as browser:
        assert browser.get("/api/v1/applications").status_code == 503


def test_gateway_allows_bounded_zip_uploads_only_on_upload_endpoint():
    seen = []

    def upstream(request):
        seen.append(request)
        assert request.headers["content-type"] == "application/zip"
        assert len(request.content) == 65536
        return httpx.Response(201, stream=httpx.ByteStream(b'{"inspected":true}'))

    with gateway(upstream) as browser:
        response = browser.post(
            "/api/v1/uploads", content=b"x" * 65536, headers={"Content-Type": "application/zip"}
        )
        assert response.status_code == 201
        assert (
            browser.post("/api/v1/uploads", content=b"x" * (5 * 1024 * 1024 + 1)).status_code == 413
        )
        assert browser.post("/api/v1/registrations", content=b"x" * 65536).status_code == 413
    assert len(seen) == 1
