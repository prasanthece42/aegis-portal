import hashlib
import json
from pathlib import Path
from zipfile import ZipFile

from aegis_platform.contracts import Runtime as SharedRuntime
from aegis_platform.fingerprint import desired_fingerprint as shared_fingerprint

from app.contracts import Runtime
from app.fingerprint import desired_fingerprint


def test_portal_uses_shared_types_and_fingerprint():
    assert Runtime is SharedRuntime
    assert desired_fingerprint is shared_fingerprint
    assert Runtime.__module__ == "aegis_platform.contracts"


def test_vendored_platform_distribution_matches_its_manifest_and_lock_hashes():
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "vendor/aegis-platform.bundle.json").read_text())
    wheel = root / "vendor" / manifest["distribution"]
    wheel_hash = hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert wheel_hash == manifest["wheel_sha256"]
    with ZipFile(wheel) as archive:
        for source, expected in manifest["source_sha256"].items():
            if source.startswith("src/"):
                assert (
                    hashlib.sha256(archive.read(source.removeprefix("src/"))).hexdigest()
                    == expected
                )
    for lock in ["requirements.txt", "requirements-prod.txt"]:
        assert "--hash=sha256:" + wheel_hash in (root / lock).read_text()
