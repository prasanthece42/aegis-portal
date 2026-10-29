"""Bounded ZIP inspection and durable, explicitly confirmed repository imports."""

import base64
import fcntl
import io
import json
import os
import re
import secrets
import sqlite3
import stat
import time
import unicodedata
import zipfile
from contextlib import contextmanager
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.errors import PortalError

MAX_ZIP = 5 * 1024 * 1024
MAX_TOTAL = 10 * 1024 * 1024
MAX_FILE = 1024 * 1024
EXCLUDED = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    "__MACOSX",
    ".aws",
    ".ssh",
}
EXCLUDED_FOLDED = {name.casefold() for name in EXCLUDED}
SECRET = re.compile(
    rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|"
    rb"(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
    rb"github_pat_[A-Za-z0-9_]{20,}|"
    rb"(?i:password|passwd|secret|api[_-]?key|access[_-]?token|secret[_-]?access[_-]?key|"
    rb"session[_-]?token|auth[_-]?token|token)\s*[=:]\s*(?!\s)"
    rb"(?![\"']?(?:os\.|process\.|\$\{|<))[\"']?[^\s\"'<>]{12,}|"
    rb"(?:postgres(?:ql)?|mysql|redis|https?)://[^\s/:]+:[^@\s]+@"
)


class Destination(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
    visibility: str = Field(default="public", pattern="^public$")


class UploadConfirmation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    review_token: str = Field(max_length=10000)


def inspect_zip(body: bytes) -> dict:
    if len(body) > MAX_ZIP:
        raise PortalError(413, "ZIP_TOO_LARGE", "ZIP uploads must be at most 5 MiB.")
    try:
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            infos = archive.infolist()
            if not 1 <= len(infos) <= 500:
                raise ValueError("ZIP must contain between 1 and 500 entries.")
            seen, total, entries = set(), 0, []
            for info in infos:
                name = info.filename.rstrip("/")
                parts = name.split("/")
                normalized = unicodedata.normalize("NFKC", name).casefold()
                mode = info.external_attr >> 16
                if (
                    not name
                    or "\x00" in info.orig_filename
                    or name.startswith("/")
                    or "\\" in name
                    or ":" in name
                    or any(p in {"", ".", ".."} for p in parts)
                    or any(ord(c) < 32 or ord(c) == 127 for c in name)
                    or normalized in seen
                    or len(name) > 240
                    or (stat.S_IFMT(mode) not in {0, stat.S_IFREG, stat.S_IFDIR})
                    or info.flag_bits & 1
                ):
                    raise ValueError("ZIP contains unsafe, duplicate or encrypted paths.")
                seen.add(normalized)
                total += info.file_size
                if (
                    info.file_size > MAX_FILE
                    or total > MAX_TOTAL
                    or info.file_size > max(1, info.compress_size) * 200
                ):
                    raise ValueError("ZIP exceeds expanded size or compression limits.")
                if not info.is_dir():
                    entries.append((name, archive.read(info)))
            # Common enclosing folder is packaging, not part of the repository.
            roots = {name.split("/")[0] for name, _ in entries}
            if (
                len(roots) == 1
                and next(iter(roots)).casefold() not in EXCLUDED_FOLDED | {".github"}
                and not next(iter(roots)).casefold().startswith(".env")
                and all("/" in name for name, _ in entries)
            ):
                entries = [(name.split("/", 1)[1], data) for name, data in entries]
    except (zipfile.BadZipFile, RuntimeError, ValueError, NotImplementedError, EOFError) as exc:
        raise PortalError(
            422, "ZIP_INVALID", "ZIP is invalid or exceeds safe archive limits."
        ) from exc
    file_names = {name.casefold() for name, _ in entries}
    if any(
        "/".join(name.casefold().split("/")[:i]) in file_names
        for name, _ in entries
        for i in range(1, len(name.split("/")))
    ):
        raise PortalError(422, "ZIP_INVALID", "ZIP contains conflicting file and folder paths.")
    files, excluded, blocked = {}, [], []
    for name, data in entries:
        parts = name.split("/")
        if (
            any(p.casefold() in EXCLUDED_FOLDED or p.casefold().startswith(".env") for p in parts)
            or name.casefold().startswith(".github/workflows/")
            or parts[-1].endswith((".pyc", ".pem", ".key", ".p12", ".pfx"))
            or parts[-1] in {".DS_Store", ".netrc", ".npmrc", ".pypirc"}
        ):
            excluded.append(name)
            continue
        if SECRET.search(data):
            blocked.append(name)
        files[name] = base64.b64encode(data).decode()
    python = any(n.endswith(".py") for n in files) and any(
        n in files for n in ("requirements.txt", "pyproject.toml")
    )
    return {
        "files": files,
        "excluded": excluded,
        "blocked": blocked,
        "python_supported": python,
        "detection": {
            "runtime": "python312-web" if python else "unsupported",
            "dockerfile_present": "Dockerfile" in files,
            "dependency_files": [
                n
                for n in files
                if n in {"requirements.txt", "requirements-prod.txt", "pyproject.toml", "uv.lock"}
            ],
            "tests_present": any(n.startswith("tests/") or n.startswith("test_") for n in files),
            "existing_workflows": [n for n in excluded if n.startswith(".github/workflows/")],
        },
    }


class UploadService:
    def __init__(
        self,
        config,
        backend,
        signer,
        path: Path,
        organization: str,
        demo=False,
        owner_type="Organization",
    ):
        self.config, self.backend, self.signer = config, backend, signer
        self.path, self.organization, self.demo = path, organization, demo
        if owner_type not in {"User", "Organization"}:
            raise ValueError("Upload owner type must be User or Organization")
        self.owner_type = owner_type
        if organization and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}", organization):
            raise ValueError("Upload organization must be one GitHub organization login")

    @contextmanager
    def db(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Create with restrictive permissions before writing any project data.
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(fd)
        db = sqlite3.connect(self.path, timeout=30)
        db.execute(
            "CREATE TABLE IF NOT EXISTS uploads "
            "(id TEXT PRIMARY KEY, user TEXT, created REAL, data TEXT)"
        )
        try:
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def operation_lock(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.path) + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
        with os.fdopen(fd, "w") as handle:
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield

    def authorize(self, session):
        if session.user_id not in self.config.onboarding_user_ids:
            raise PortalError(
                403, "ONBOARDING_FORBIDDEN", "Your identity is not enabled for onboarding."
            )
        if hasattr(self.backend, "validate_session"):
            self.backend.validate_session(session)

    def capabilities(self, session):
        self.authorize(session)
        return {
            "organization": self.organization,
            "owner_type": self.owner_type,
            "visibility": ["public"],
            "creation_enabled": bool(self.organization),
            "mode": "demo" if self.demo else "live",
            "max_zip_bytes": MAX_ZIP,
        }

    def save(self, db, uid, record):
        db.execute("UPDATE uploads SET data=? WHERE id=?", (json.dumps(record), uid))
        db.commit()

    def load(self, db, uid, session):
        row = db.execute("SELECT user, data FROM uploads WHERE id=?", (uid,)).fetchone()
        if not row or row[0] != session.user_id:
            raise PortalError(
                404, "UPLOAD_UNAVAILABLE", "Upload is unavailable; inspect your ZIP again."
            )
        return json.loads(row[1])

    def public(self, uid, record):
        return {
            "upload_id": uid,
            **{
                k: v
                for k, v in record.items()
                if k not in {"files", "marker", "initial_head", "tree", "commit", "review"}
            },
            "files": [
                {"path": n, "size": len(base64.b64decode(v))} for n, v in record["files"].items()
            ],
        }

    def inspect(self, session, body):
        self.authorize(session)
        record = inspect_zip(body)
        record.update(
            status="inspected",
            organization=self.organization,
            owner_type=self.owner_type,
            visibility="public",
        )
        uid = secrets.token_hex(24)
        # Blocked source bytes are never persisted.
        if record["blocked"]:
            result = self.public(uid, record)
            result["status"] = "blocked"
            return result
        with self.db() as db:
            db.execute(
                "DELETE FROM uploads WHERE created < ? "
                "AND json_extract(data, '$.status') = 'inspected'",
                (time.time() - 86400,),
            )
            if (
                db.execute(
                    "SELECT COUNT(*) FROM uploads WHERE user=?", (session.user_id,)
                ).fetchone()[0]
                >= 20
            ):
                raise PortalError(
                    429, "UPLOAD_LIMIT", "Remove an earlier upload before inspecting another ZIP."
                )
            db.execute(
                "INSERT INTO uploads VALUES (?, ?, ?, ?)",
                (uid, session.user_id, time.time(), json.dumps(record)),
            )
        return self.public(uid, record)

    def get(self, session, uid):
        self.authorize(session)
        with self.db() as db:
            return self.public(uid, self.load(db, uid, session))

    def delete(self, session, uid):
        self.authorize(session)
        with self.db() as db:
            record = self.load(db, uid, session)
            if record["status"] not in {"inspected", "uploaded"}:
                raise PortalError(
                    409,
                    "UPLOAD_IN_PROGRESS",
                    "Keep this recovery record until repository upload completes.",
                )
            db.execute("DELETE FROM uploads WHERE id=?", (uid,))
        return {"removed": True}

    def preview(self, session, uid, destination):
        self.authorize(session)
        if not self.organization:
            raise PortalError(
                409,
                "UPLOAD_SETUP_REQUIRED",
                "An operator must configure one allowed GitHub account "
                "and authorize repository creation for the GitHub App.",
            )
        with self.db() as db:
            record = self.load(db, uid, session)
            if (
                record["status"] != "inspected"
                or not record["python_supported"]
                or not record["files"]
            ):
                raise PortalError(
                    409,
                    "UPLOAD_NOT_READY",
                    "Inspect a supported Python web app before reviewing creation.",
                )
            if self.demo and any(
                r["full_name"].casefold() == f"{self.organization}/{destination.name}".casefold()
                for r in self.backend.repositories(session)
            ):
                raise PortalError(409, "REPOSITORY_EXISTS", "Repository name is already in use.")
            if not self.demo:
                if self.owner_type == "User":
                    self.backend.upload_destination(
                        session, self.organization, destination.name, "User"
                    )
                else:
                    self.backend.upload_destination(session, self.organization, destination.name)
            record["owner_type"] = self.owner_type
            record["organization"] = self.organization
            record["name"] = destination.name
            record["review"] = secrets.token_hex(16)
            self.save(db, uid, record)
            token = self.signer.review_token(
                {
                    "upload_id": uid,
                    "user_id": session.user_id,
                    "review": record["review"],
                    "organization": self.organization,
                }
            )
            return {**self.public(uid, record), "review_token": token}

    def confirm(self, session, uid, token):
        self.authorize(session)
        try:
            review = self.signer.read_review(token)
            if (
                review["upload_id"] != uid
                or review["user_id"] != session.user_id
                or review["organization"] != self.organization
            ):
                raise ValueError("Review mismatch")
        except (ValueError, KeyError, TypeError):
            raise PortalError(
                409, "UPLOAD_REVIEW_EXPIRED", "Review the destination again before creation."
            ) from None
        with self.operation_lock(), self.db() as db:
            # Serialize across processes; reservations are committed before GitHub mutations.
            db.execute("BEGIN IMMEDIATE")
            record = self.load(db, uid, session)
            if (
                review["review"] != record.get("review")
                or record["organization"] != self.organization
                or record.get("owner_type", "Organization") != self.owner_type
            ):
                raise PortalError(
                    409, "UPLOAD_REVIEW_CHANGED", "Review the current destination again."
                )
            if record["status"] == "inspected":
                record.update(status="creating", marker="aegis-upload-" + secrets.token_hex(24))
                self.save(db, uid, record)
            if self.demo:
                record.update(
                    status="uploaded",
                    repository={
                        "repository_id": str(int(uid[:12], 16)),
                        "installation_id": "903",
                        "full_name": f"demo/{record['name']}",
                        "default_branch": "main",
                    },
                )
                self.save(db, uid, record)
                self.backend.uploaded_repository(record["repository"], record["files"])
            else:
                # Provider adapter independently serializes and durably saves every transition.
                self.backend.upload_repository(session, record, lambda: self.save(db, uid, record))
            return self.public(uid, record)

    def resume(self, session, uid):
        self.authorize(session)
        with self.db() as db:
            record = self.load(db, uid, session)
            if record["status"] == "inspected":
                raise PortalError(409, "UPLOAD_NOT_CONFIRMED", "Review and confirm creation first.")
            token = self.signer.review_token(
                {
                    "upload_id": uid,
                    "user_id": session.user_id,
                    "review": record["review"],
                    "organization": self.organization,
                }
            )
        return self.confirm(session, uid, token)
