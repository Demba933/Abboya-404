from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


class PasswordHasher:
    """PBKDF2-SHA256 password hasher."""

    iterations = 210_000

    @classmethod
    def hash_password(cls, password: str) -> str:
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, cls.iterations)
        return f"pbkdf2_sha256${cls.iterations}${_b64url_encode(salt)}${_b64url_encode(digest)}"

    @classmethod
    def verify(cls, password: str, encoded: str) -> bool:
        algo, iter_str, salt_b64, digest_b64 = encoded.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), _b64url_decode(salt_b64), int(iter_str)
        )
        return hmac.compare_digest(_b64url_encode(digest), digest_b64)


@dataclass(frozen=True)
class AuthClaims:
    sub: str
    role: str
    business_id: str | None
    exp: int


class TokenSigner:
    """Minimal HMAC-signed token format compatible with JWT payload layout."""

    def __init__(self, secret: str):
        self.secret = secret.encode("utf-8")

    def issue(self, subject: str, role: str, business_id: str | None, ttl_minutes: int = 60) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        exp = int((datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).timestamp())
        payload = {"sub": subject, "role": role, "business_id": business_id, "exp": exp}
        signing_input = f"{_b64url_encode(json.dumps(header).encode())}.{_b64url_encode(json.dumps(payload).encode())}"
        signature = hmac.new(self.secret, signing_input.encode("utf-8"), hashlib.sha256).digest()
        return f"{signing_input}.{_b64url_encode(signature)}"

    def verify(self, token: str) -> AuthClaims:
        head, payload, signature = token.split(".")
        signing_input = f"{head}.{payload}"
        expected = hmac.new(self.secret, signing_input.encode("utf-8"), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, _b64url_decode(signature)):
            raise ValueError("invalid signature")
        claims_data = json.loads(_b64url_decode(payload))
        if int(claims_data["exp"]) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("token expired")
        return AuthClaims(**claims_data)


def hash_phone(phone: str, pepper: str) -> tuple[str, str]:
    normalized = "".join(ch for ch in phone if ch.isdigit() or ch == "+")
    digest = hashlib.sha256(f"{pepper}:{normalized}".encode("utf-8")).hexdigest()
    return digest, normalized[-4:]
