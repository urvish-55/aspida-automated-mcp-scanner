"""API-key authentication for the scanner's own API.

Why: the API can start scans against network targets and exposes scan results, so it
must not be reachable by anyone who merely finds the port.

Design
- One shared secret ("API key"). Source of truth, in order:
    1. ``API_KEY`` environment variable (must be >= 16 characters);
    2. ``data/api_key`` (created on first start with a random 256-bit token, mode 0600).
  The key is NEVER logged. Only the file path is logged on creation.
- Clients send ``Authorization: Bearer <key>`` or ``X-API-Key: <key>``.
- Verification hashes both sides and uses ``hmac.compare_digest`` (constant time).
- Failed attempts are rate limited per client IP (see ApiKeyAuthMiddleware) to blunt guessing.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from functools import lru_cache
from pathlib import Path

from backend.core.config import DATA_DIR, get_settings
import logging

MIN_KEY_LENGTH = 16
KEY_FILE = DATA_DIR / "api_key"
log = logging.getLogger("scanner.auth")


class AuthConfigError(RuntimeError):
    pass


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def _load_or_create_key(env_key: str, key_file: Path) -> str:
    if env_key:
        if len(env_key) < MIN_KEY_LENGTH:
            raise AuthConfigError(f"API_KEY must be at least {MIN_KEY_LENGTH} characters")
        return env_key
    if key_file.is_file():
        stored = key_file.read_text(encoding="utf-8").strip()
        if len(stored) >= MIN_KEY_LENGTH:
            return stored
    key_file.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(token + "\n")
    log.warning(f"generated a new API key and stored it at {key_file} (read it from there; it is never logged)")
    return token


@lru_cache(maxsize=4)
def _expected_digest(env_key: str, key_file: str) -> bytes:
    return _digest(_load_or_create_key(env_key, Path(key_file)))


def expected_digest() -> bytes:
    return _expected_digest(get_settings().api_key, str(KEY_FILE))


def reset_auth_cache() -> None:
    _expected_digest.cache_clear()


def extract_presented_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            return token.strip()
    if x_api_key and x_api_key.strip():
        return x_api_key.strip()
    return None


def is_valid_key(presented: str | None) -> bool:
    if not presented or len(presented) > 512:
        return False
    return hmac.compare_digest(_digest(presented), expected_digest())
