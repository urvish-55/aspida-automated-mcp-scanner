"""Secure upload handling for MCP configuration files.

Rules (all enforced server-side):
- extension allowlist (.json / .jsonc / .txt), content-based JSON validation
- hard size limit (settings.max_upload_size_bytes)
- content must parse as JSON; malformed content is rejected with a clear error
- files are stored under data/uploads with generated random names — the
  original filename is never used on disk (no traversal, no collisions)
- uploads are data-only: they are parsed, never executed, never served back
  as executable content
"""

from __future__ import annotations

import json
import re
import secrets
from pathlib import Path

from backend.core.config import UPLOAD_DIR, get_settings

ALLOWED_EXTENSIONS = {".json", ".jsonc", ".txt"}


class UploadValidationError(Exception):
    pass


def validate_upload(filename: str, content: bytes) -> Path:
    settings = get_settings()
    if len(content) > settings.max_upload_size_bytes:
        raise UploadValidationError(
            f"upload of {len(content)} bytes exceeds the {settings.max_upload_size_bytes} byte limit"
        )
    if not content.strip():
        raise UploadValidationError("upload is empty")

    suffix = Path(filename or "").suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise UploadValidationError(
            f"extension '{suffix or '(none)'}' not allowed; allowed: {sorted(ALLOWED_EXTENSIONS)}"
        )

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UploadValidationError("upload is not valid UTF-8 text") from exc
    try:
        json.loads(text)
    except json.JSONDecodeError as exc:
        raise UploadValidationError(f"upload is not valid JSON: {exc}") from exc

    # Generated name only: original filename never touches the disk.
    safe_name = f"{secrets.token_hex(12)}.json"
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    dest = UPLOAD_DIR / safe_name
    # Defense-in-depth: assert the resolved path stays inside the upload dir.
    if not dest.resolve().is_relative_to(UPLOAD_DIR.resolve()):
        raise UploadValidationError("resolved upload path escaped the upload directory")
    dest.write_bytes(content)
    return dest


def resolve_upload_path(stored_name: str) -> Path:
    """Resolve a stored upload name for reading; rejects traversal attempts."""
    if not re.fullmatch(r"[0-9a-f]{24}\.json", stored_name):
        raise UploadValidationError("invalid stored filename")
    path = (UPLOAD_DIR / stored_name).resolve()
    if not path.is_relative_to(UPLOAD_DIR.resolve()):
        raise UploadValidationError("path traversal detected")
    if not path.is_file():
        raise UploadValidationError("stored upload not found")
    return path


async def read_upload(stored_name: str) -> str:
    path = resolve_upload_path(stored_name)
    return path.read_text(encoding="utf-8")
