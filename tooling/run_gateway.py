"""Loopback HTTPS entry point for the configured Kind portal service.

The operator holds the explicit kubeconfig for a fixed Service port forward. The
portal pod receives no Kubernetes credentials. Callback queries and cookies are
never logged, and upstream HTTP clients are isolated per browser request.
"""

import argparse
import json
import re
import select
import ssl
import subprocess
import threading
from pathlib import Path
from urllib.parse import urlsplit

import httpx
import uvicorn
from aegis_platform.local_agent import LocalConfig
from aegis_platform.portal_config import LiveConfig
from aegis_platform.portal_system import NAMESPACE
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

HOP_HEADERS = {
    b"connection",
    b"keep-alive",
    b"proxy-authenticate",
    b"proxy-authorization",
    b"te",
    b"trailer",
    b"transfer-encoding",
    b"upgrade",
    b"content-length",
}


def drain(stream):
    for _line in stream:
        pass


class ServiceForward:
    def __init__(self, config: LocalConfig):
        self.config = config
        self.kube = ["kubectl", "--kubeconfig", config.kubeconfig, "--context", config.context]
        self.port = None
        self.process = None
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.supervise, daemon=True)

    def enrolled(self):
        value = json.loads(
            subprocess.check_output(
                self.kube + ["config", "view", "--minify", "-o", "json"], stderr=subprocess.DEVNULL
            )
        )
        server = urlsplit(value["clusters"][0]["cluster"]["server"])
        if server.scheme != "https" or server.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("Gateway requires the enrolled loopback Kubernetes API")
        uid = subprocess.check_output(
            self.kube + ["get", "namespace", "kube-system", "-o", "jsonpath={.metadata.uid}"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if uid != self.config.cluster_uid:
            raise ValueError("Gateway cluster UID differs from enrollment")

    def supervise(self):
        while not self.stopping.is_set():
            try:
                self.enrolled()
                process = subprocess.Popen(
                    self.kube
                    + [
                        "-n",
                        NAMESPACE,
                        "port-forward",
                        "service/aegis-portal",
                        "0:80",
                        "--address",
                        "127.0.0.1",
                        "--pod-running-timeout=30s",
                    ],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                self.process = process
                if not select.select([process.stdout], [], [], 35)[0]:
                    raise ValueError("Portal Service forward has not become available")
                match = re.search(
                    r"Forwarding from 127\.0\.0\.1:([0-9]+)", process.stdout.readline()
                )
                if not match:
                    raise ValueError("Portal Service forward could not start")
                self.port = int(match[1])
                # kubectl logs every forwarded connection; keep its pipe drained.
                threading.Thread(
                    target=drain,
                    args=(process.stdout,),
                    daemon=True,
                ).start()
                process.wait()
            except (ValueError, KeyError, OSError, subprocess.SubprocessError):
                # No command/provider output: it may contain private operator paths.
                pass
            finally:
                self.port = None
                if self.process and self.process.poll() is None:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                self.process = None
            self.stopping.wait(2)

    def start(self):
        self.enrolled()
        self.thread.start()

    def stop(self):
        self.stopping.set()
        if self.process and self.process.poll() is None:
            self.process.terminate()
        self.thread.join(timeout=5)


def create_gateway(origin, forward, *, transport=None):
    url = urlsplit(origin)
    if url.scheme != "https" or url.hostname not in {"localhost", "127.0.0.1"}:
        raise ValueError("Gateway is restricted to the configured HTTPS loopback origin")
    authority = url.netloc
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    def unavailable():
        return JSONResponse(
            {
                "error": {
                    "code": "PORTAL_RESTARTING",
                    "retryable": True,
                    "message": "Portal is unavailable; retry the same confirmed request.",
                }
            },
            status_code=503,
            headers={"Retry-After": "2", "Cache-Control": "no-store"},
        )

    @app.api_route(
        "/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
    )
    async def proxy(request: Request, path: str):
        if request.headers.get("host", "").lower() != authority.lower():
            return JSONResponse(
                {"error": {"message": "Unrecognized portal origin."}}, status_code=400
            )
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 32768:
                return JSONResponse(
                    {"error": {"message": "Request exceeds 32 KiB."}}, status_code=413
                )
        port = forward.port
        if port is None:
            return unavailable()
        raw_path = request.scope["raw_path"].decode("ascii")
        query = request.scope["query_string"].decode("ascii")
        target = f"http://127.0.0.1:{port}" + raw_path + ("?" + query if query else "")
        headers = [
            (key, value)
            for key, value in request.headers.raw
            if key.lower()
            not in HOP_HEADERS | {b"host", b"forwarded", b"x-forwarded-host", b"x-forwarded-proto"}
        ]
        headers.append((b"host", authority.encode("ascii")))
        try:
            # A shared cookie jar would leak one browser's session into another's request.
            async with httpx.AsyncClient(
                timeout=60, follow_redirects=False, trust_env=False, transport=transport
            ) as client:
                async with client.stream(
                    request.method, target, headers=headers, content=bytes(body)
                ) as upstream:
                    content = bytearray()
                    async for chunk in upstream.aiter_raw():
                        content.extend(chunk)
                        if len(content) > 8 * 1024 * 1024:
                            return unavailable()
                    response = Response(bytes(content), status_code=upstream.status_code)
                    response.raw_headers = [
                        (key, value)
                        for key, value in upstream.headers.raw
                        if key.lower() not in HOP_HEADERS
                    ]
                    if request.method != "HEAD" and upstream.status_code not in {204, 304}:
                        response.raw_headers.append((b"content-length", str(len(content)).encode()))
                    return response
        except httpx.HTTPError:
            return unavailable()

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-config", type=Path, required=True)
    parser.add_argument("--portal-config", type=Path, default=Path(".local/live-config.json"))
    parser.add_argument("--certificate", type=Path, default=Path(".local/tls/localhost.crt"))
    parser.add_argument("--key", type=Path, default=Path(".local/tls/localhost.key"))
    args = parser.parse_args()
    config = LiveConfig.model_validate(json.loads(args.portal_config.read_text()))
    origin = urlsplit(config.public_origin)
    if not origin.port or not 1024 <= origin.port <= 65535:
        parser.error("Use the approved unprivileged loopback HTTPS port")
    forward = ServiceForward(LocalConfig.model_validate(json.loads(args.agent_config.read_text())))
    app = create_gateway(config.public_origin, forward)
    forward.start()
    try:
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=origin.port,
            access_log=False,
            ssl_certfile=str(args.certificate),
            ssl_keyfile=str(args.key),
            ssl_version=ssl.PROTOCOL_TLS_SERVER,
        )
    finally:
        forward.stop()


if __name__ == "__main__":
    main()
