"""One-time, loopback-only GitHub App manifest handshake. Never a portal login shortcut.

Run with the portal venv. The account owner creates and installs the App in their
browser; the callback stores credentials only in an ignored, private local directory.
"""

import argparse
import html
import json
import os
import re
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def manifest(origin: str, callback: str) -> dict:
    url = urlsplit(origin)
    if (
        url.scheme != "https"
        or not url.hostname
        or url.path
        or url.query
        or url.fragment
        or url.username
        or url.password
    ):
        raise ValueError("Portal origin must be HTTPS with no path or credentials")
    return {
        "name": "Aegis Developer Portal",
        "url": origin,
        "description": "Authorized Aegis catalog and delivery requests; GitOps and Argo deploy.",
        "redirect_url": callback,
        "callback_urls": [origin + "/auth/github/callback"],
        "hook_attributes": {"url": origin + "/github/events", "active": False},
        "public": False,
        "request_oauth_on_install": False,
        "default_events": [],
        "default_permissions": {
            "contents": "write",
            "pull_requests": "write",
            "issues": "write",
            "actions": "write",
            "checks": "read",
            "statuses": "read",
        },
    }


def write_private(path: Path, content: bytes):
    # Refuse overwrites and symlinks; a second setup cannot silently replace live keys.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def store_credentials(directory: Path, data: dict) -> dict:
    required = {"id", "client_id", "client_secret", "pem", "slug", "html_url"}
    if not required.issubset(data) or not str(data["id"]).isdigit():
        raise ValueError("GitHub returned an incomplete App configuration")
    key = serialization.load_pem_private_key(data["pem"].encode(), password=None)
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    if not isinstance(key, RSAPrivateKey):
        raise ValueError("GitHub returned an unexpected key type")
    if directory.exists():
        raise ValueError("Credential directory already exists; choose a new empty location")
    directory.mkdir(mode=0o700, parents=True)
    write_private(directory / "github-app.pem", data["pem"].encode())
    write_private(
        directory / "credentials.json",
        (json.dumps({k: data[k] for k in required - {"pem"}}, indent=2) + "\n").encode(),
    )
    signing = Ed25519PrivateKey.generate()
    write_private(
        directory / "request-signing.pem",
        signing.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )
    public = signing.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    write_private(directory / "request-signing.pub.pem", public)
    return {"app_id": str(data["id"]), "slug": data["slug"], "url": data["html_url"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--origin", default="https://localhost:8443")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--output", type=Path, default=Path(".local/github-app"))
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Use an unprivileged local port")
    if args.output.exists():
        parser.error("Output already exists; existing credentials will not be replaced")
    state = secrets.token_urlsafe(32)
    origin = f"http://127.0.0.1:{args.port}"
    config = manifest(args.origin, origin + "/callback")
    lock = threading.Lock()
    complete = False

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass  # Callback query contains a one-time credential; never log it.

        def respond(self, status, body):
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; form-action https://github.com; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body.encode())

        def do_GET(self):
            nonlocal complete
            if self.headers.get("Host") != f"127.0.0.1:{args.port}":
                return self.respond(400, "Invalid local host")
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            if query.get("state") != [state]:
                return self.respond(403, "Setup link is invalid or expired")
            if url.path == "/":
                body = (
                    "<!doctype html><html lang='en'><meta charset='utf-8'>"
                    "<title>Aegis GitHub App setup</title><h1>Create the Aegis GitHub App</h1>"
                    "<p>Sign in as prasanthece42. This private App requests repository contents, "
                    "pull requests, issues and Actions write access; checks and statuses read "
                    "access. Installation is restricted to repositories you select.</p>"
                    "<p>It has no Kubernetes credentials. PROD requires human review.</p>"
                    f"<form method='post' action='https://github.com/settings/apps/new?state={state}'>"
                    "<input type='hidden' name='manifest' value='"
                    + html.escape(json.dumps(config), quote=True)
                    + "'>"
                    "<button>Create App on GitHub</button></form></html>"
                )
                return self.respond(200, body)
            if url.path != "/callback" or len(query.get("code", [])) != 1:
                return self.respond(404, "Setup page not found")
            code = query["code"][0]
            if not re.fullmatch(r"[A-Za-z0-9_-]{20,200}", code):
                return self.respond(400, "Invalid conversion code")
            with lock:
                if complete:
                    return self.respond(409, "This setup flow has already completed")
                try:
                    response = httpx.post(
                        f"https://api.github.com/app-manifests/{code}/conversions",
                        headers={"Accept": "application/vnd.github+json"},
                        timeout=30,
                        follow_redirects=False,
                    )
                    response.raise_for_status()
                    public = store_credentials(args.output, response.json())
                    complete = True
                except (httpx.HTTPError, ValueError, OSError):
                    return self.respond(
                        503,
                        "Setup could not be stored. Inspect local setup; "
                        "no credential values are shown or logged.",
                    )
            print(
                "App created; credentials stored privately. App ID: " + public["app_id"], flush=True
            )
            link = "https://github.com/apps/" + public["slug"] + "/installations/new"
            self.respond(
                200,
                "<h1>App created</h1><p>Credentials are saved on this workstation.</p>"
                f"<p><a href='{html.escape(link, quote=True)}'>Install the App</a> on "
                "prasanthece42. Select aegis-platform, aegis-portal, aegis-cicd and "
                "aegis-gitops. Enable expiring user tokens in the App settings.</p>",
            )

    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Open {origin}/?state={state}", flush=True)
    print("Setup expires in 1 hour. Keep this process running until App installation.", flush=True)
    timer = threading.Timer(3600, server.shutdown)
    timer.daemon = True
    timer.start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        timer.cancel()
        server.server_close()


if __name__ == "__main__":
    main()
