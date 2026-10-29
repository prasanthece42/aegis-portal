"""Run DEV preparation with an explicitly enrolled operator and workflow-authorized CLI identity."""

import argparse
import base64
import json
import subprocess
import time
from pathlib import Path

import httpx
from aegis_platform.canonical import canonical, strict_json
from aegis_platform.github_api import GitHubAPI
from aegis_platform.local_agent import LocalConfig
from aegis_platform.worker import DeliveryWorker
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from app.config import LiveConfig
from app.setup_worker import SetupWorker


def encoded(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-config", type=Path, required=True)
    parser.add_argument("--portal-config", type=Path, required=True)
    parser.add_argument("--app-key-file", type=Path, required=True)
    parser.add_argument("--state-directory", type=Path, required=True)
    parser.add_argument("--operator-from-gh", action="store_true", required=True)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    config = LiveConfig.model_validate(strict_json(args.portal_config.read_bytes()))
    local = LocalConfig.model_validate(strict_json(args.agent_config.read_bytes()))
    if args.app_key_file.is_symlink() or args.app_key_file.stat().st_mode & 0o077:
        raise ValueError("Use the existing operator-private App key file")
    key = serialization.load_pem_private_key(args.app_key_file.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size < 2048:
        raise ValueError("Expected an enrolled GitHub App RSA key")
    # The CLI identity is explicitly selected, never inherited as portal credentials.
    operator = subprocess.check_output(
        ["gh", "auth", "token", "--hostname", "github.com"], text=True
    ).strip()
    with httpx.Client(
        timeout=20,
        headers={
            "Authorization": "Bearer " + operator,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    ) as client:
        check = client.get("https://api.github.com/user")
        check.raise_for_status()
        if "workflow" not in {
            s.strip() for s in check.headers.get("X-OAuth-Scopes", "").split(",")
        }:
            raise ValueError(
                "The selected operator CLI identity must already authorize workflow installation"
            )
    worker = DeliveryWorker(
        GitHubAPI(operator, config.platform_repository),
        GitHubAPI(operator, config.gitops_repository),
        lambda entry: GitHubAPI(operator, entry.source.owner + "/" + entry.source.name),
        Path(__file__).resolve().parents[1],
    )
    cache = {}

    def bot(installation, repo_id, repo):
        installation = installation or config.gitops_installation_id
        allowed = set(config.source_installation_ids) | {config.gitops_installation_id}
        if installation not in allowed:
            raise ValueError("Preparation installation is not enrolled")
        pair = (installation, repo_id)
        if pair not in cache or cache[pair][1] < time.time():
            now = int(time.time())
            unsigned = (
                encoded(canonical({"alg": "RS256", "typ": "JWT"}))
                + "."
                + encoded(canonical({"iat": now - 60, "exp": now + 300, "iss": config.app_id}))
            )
            jwt = (
                unsigned
                + "."
                + encoded(key.sign(unsigned.encode(), padding.PKCS1v15(), hashes.SHA256()))
            )
            response = httpx.post(
                f"https://api.github.com/app/installations/{installation}/access_tokens",
                headers={
                    "Authorization": "Bearer " + jwt,
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2026-03-10",
                },
                json={
                    "repository_ids": [int(repo_id)],
                    "permissions": {"contents": "read", "pull_requests": "write"},
                },
                timeout=20,
            )
            response.raise_for_status()
            cache[pair] = (response.json()["token"], time.time() + 3000)
        return GitHubAPI(cache[pair][0], repo)

    service = SetupWorker(local, worker, bot, args.state_directory, config.app_id)
    while True:
        try:
            result = service.tick()
            print(json.dumps({"state": "running", "requests": result}), flush=True)
        except (ValueError, KeyError, OSError, subprocess.SubprocessError, httpx.HTTPError):
            print(
                json.dumps(
                    {
                        "state": "unavailable",
                        "reason": "The enrolled preparation service could not verify "
                        "its current policy or provider state.",
                    }
                ),
                flush=True,
            )
            if args.once:
                raise
        if args.once:
            break
        time.sleep(60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
