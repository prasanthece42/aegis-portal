import base64
import json
from pathlib import Path

import pytest
from aegis_platform.portal_system import RUNTIME_CONTRACT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.config import Settings
from app.demo import DemoBackend, demo_config
from app.main import create_app
from app.security import Signer


def test_image_runtime_contract_matches_operator_manifest_contract():
    assert json.loads(Path("app/portal-profile.json").read_text()) == RUNTIME_CONTRACT


@pytest.mark.parametrize("matches", [True, False])
def test_live_readiness_requires_the_expected_signing_public_key(monkeypatch, tmp_path, matches):
    config = demo_config()
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config.model_dump()))
    monkeypatch.setenv("AEGIS_MODE", "live")
    monkeypatch.setenv("AEGIS_CONFIG", str(path))
    key = Ed25519PrivateKey.generate()
    expected_key = key if matches else Ed25519PrivateKey.generate()
    expected = base64.b64encode(
        expected_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    monkeypatch.setenv("AEGIS_SIGNING_PUBLIC_KEY_B64", expected)
    backend = DemoBackend(tmp_path / "records.json")
    signer = Signer(key, config.signing_key_id)
    if matches:
        app = create_app(Settings(), backend=backend, signer=signer)
        with TestClient(app) as client:
            assert client.get("/ready").status_code == 200
            assert (
                client.post("/auth/demo", headers={"Origin": config.public_origin}).status_code
                != 200
            )
    else:
        with pytest.raises(ValueError, match="public binding"):
            create_app(Settings(), backend=backend, signer=signer)
