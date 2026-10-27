"""Start the loopback HTTPS portal using locally protected App credentials.

No shell exports, credentials in process arguments, or access-log callback queries.
"""

import json
import os
from pathlib import Path

import uvicorn


def main():
    root = Path(__file__).resolve().parents[1]
    os.chdir(root)
    directory = root / ".local/github-app"
    data = json.loads((directory / "credentials.json").read_text())
    os.environ.update(
        {
            "AEGIS_MODE": "live",
            "AEGIS_CONFIG": str(root / ".local/live-config.json"),
            "AEGIS_APP_PRIVATE_KEY_FILE": str(directory / "github-app.pem"),
            "AEGIS_SIGNING_KEY_FILE": str(directory / "request-signing.pem"),
            "AEGIS_GITHUB_CLIENT_SECRET": data["client_secret"],
        }
    )
    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8443,
        access_log=False,
        ssl_keyfile=str(root / ".local/tls/localhost.key"),
        ssl_certfile=str(root / ".local/tls/localhost.crt"),
    )


if __name__ == "__main__":
    main()
