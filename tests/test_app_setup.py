import stat

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tooling.setup_github_app import manifest, store_credentials, write_private


def test_manifest_keeps_app_private_and_has_no_cluster_or_administration_authority():
    data = manifest("https://localhost:8443", "http://127.0.0.1:8765/callback")
    assert data["public"] is False
    assert data["hook_attributes"]["active"] is False
    assert data["callback_urls"] == ["https://localhost:8443/auth/github/callback"]
    assert "administration" not in data["default_permissions"]
    assert data["default_permissions"]["statuses"] == "read"
    assert data["default_permissions"]["checks"] == "read"
    for origin in ["http://localhost:8443", "https://localhost/path", "https://user@localhost"]:
        with pytest.raises(ValueError):
            manifest(origin, "http://127.0.0.1/callback")


def test_credentials_stay_private_and_existing_keys_are_not_replaced(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    data = {
        "id": 123,
        "client_id": "fixture",
        "client_secret": "fixture-only",
        "pem": pem,
        "slug": "fixture-app",
        "html_url": "https://github.com/apps/fixture-app",
    }
    directory = tmp_path / "app"
    public = store_credentials(directory, data)
    assert set(public) == {"app_id", "slug", "url"}
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for path in directory.iterdir():
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(ValueError):
        store_credentials(directory, data)
    with pytest.raises(FileExistsError):
        write_private(directory / "github-app.pem", b"replacement")
    assert (directory / "github-app.pem").read_text() == pem


def test_private_write_does_not_follow_symlinks(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"original")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(FileExistsError):
        write_private(link, b"replacement")
    assert target.read_bytes() == b"original"
