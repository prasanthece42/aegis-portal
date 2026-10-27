"""Canonical signed records; opaque server-side sessions and bounded review tokens."""

import base64
import secrets
import threading
import time
from dataclasses import dataclass

from aegis_platform.canonical import canonical, digest, strict_json
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def operation_id(issuer: str, principal: str, scope: str, key: str) -> str:
    return "reg-" + digest([issuer, principal, scope, key]).split(":")[1]


class Signer:
    def __init__(self, key: Ed25519PrivateKey, key_id: str):
        self.key = key
        self.key_id = key_id

    def seal(self, payload: dict) -> dict:
        return {
            "payload": payload,
            "envelope": {
                "algorithm": "Ed25519",
                "key_id": self.key_id,
                "payload_sha256": digest(payload),
                "signature": b64(self.key.sign(canonical(payload))),
            },
        }

    def verify(self, record: dict) -> dict:
        if set(record) != {"payload", "envelope"}:
            raise ValueError("Invalid signed record")
        envelope = record["envelope"]
        if (
            set(envelope) != {"algorithm", "key_id", "payload_sha256", "signature"}
            or envelope["algorithm"] != "Ed25519"
            or envelope["key_id"] != self.key_id
            or envelope["payload_sha256"] != digest(record["payload"])
        ):
            raise ValueError("Untrusted signature envelope")
        try:
            self.key.public_key().verify(unb64(envelope["signature"]), canonical(record["payload"]))
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("Invalid record signature") from exc
        return record["payload"]

    def review_token(self, payload: dict, now: float | None = None) -> str:
        return b64(canonical(self.seal({**payload, "expires_at": int(now or time.time()) + 300})))

    def read_review(self, token: str, now: float | None = None) -> dict:
        payload = self.verify(strict_json(unb64(token)))
        if payload["expires_at"] <= (now or time.time()):
            raise ValueError("Review expired")
        return payload


@dataclass
class Session:
    user_id: str
    login: str
    user_token: str
    csrf: str
    created: float
    touched: float
    provider_expires: float


class Sessions:
    def __init__(self):
        self.records: dict[str, Session] = {}
        self.oauth: dict[str, tuple[str, float]] = {}
        self.lock = threading.RLock()

    def create(self, user_id: str, login: str, token: str, lifetime: int = 28800) -> str:
        now = time.time()
        with self.lock:
            self.prune(now)
            if len(self.records) >= 100:
                raise ValueError("Session capacity reached")
            sid = secrets.token_urlsafe(32)
            self.records[sid] = Session(
                user_id, login, token, secrets.token_urlsafe(32), now, now, now + lifetime
            )
            return sid

    def get(self, sid: str) -> Session | None:
        now = time.time()
        with self.lock:
            self.prune(now)
            value = self.records.get(sid)
            if value:
                value.touched = now
            return value

    def prune(self, now: float):
        self.records = {
            k: v
            for k, v in self.records.items()
            if now - v.created < 28800 and now - v.touched < 1800 and now < v.provider_expires
        }
        self.oauth = {k: v for k, v in self.oauth.items() if now - v[1] < 300}

    def start_oauth(self) -> tuple[str, str]:
        with self.lock:
            self.prune(time.time())
            if len(self.oauth) >= 100:
                raise ValueError("Authorization capacity reached")
            state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(48)
            self.oauth[state] = (verifier, time.time())
            return state, verifier

    def consume_oauth(self, state: str) -> str | None:
        with self.lock:
            self.prune(time.time())
            value = self.oauth.pop(state, None)
            return value[0] if value else None
