"""Executed inside the production image; no test-only Python dependencies required."""

import json
import os
import subprocess
import time
import urllib.error
import urllib.request

assert os.geteuid() == 10001
process = subprocess.Popen(
    [
        "uvicorn",
        "app.main:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8000",
        "--no-access-log",
    ]
)
try:
    for _attempt in range(100):
        try:
            with urllib.request.urlopen("http://127.0.0.1:8000/health", timeout=1) as response:
                assert json.load(response) == {"status": "ok"}
            break
        except (OSError, urllib.error.URLError):
            if process.poll() is not None:
                raise RuntimeError("Portal exited before readiness") from None
            time.sleep(0.1)
    else:
        raise RuntimeError("Portal health timeout")
    with urllib.request.urlopen("http://127.0.0.1:8000/api/v1/status", timeout=1) as response:
        assert json.load(response)["deployment_enabled"] is False
    with urllib.request.urlopen("http://127.0.0.1:8000/", timeout=1) as response:
        assert b"Aegis" in response.read()
    try:
        urllib.request.urlopen("http://127.0.0.1:8000/ready", timeout=1)
    except urllib.error.HTTPError as error:
        assert error.code == 503
    else:
        raise AssertionError("Unconfigured service must not be ready")
    print("Non-root read-only image: health, static assets and fail-closed configuration passed.")
finally:
    process.terminate()
    process.wait(timeout=5)
