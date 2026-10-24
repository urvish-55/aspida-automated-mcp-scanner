"""Structured JSON logging with mandatory secret redaction.

Rule: no API keys, passwords, tokens, Authorization headers, or private-key
material may ever reach a log sink. Redaction is defensive (pattern-based) in
addition to the discipline of never logging sensitive fields.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import MutableMapping
from datetime import datetime, timezone
from typing import Any

# Field names whose values must never appear in logs.
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(api[_-]?key|secret|password|passwd|token|authorization|credential|private[_-]?key)"
)

# Best-effort redaction of key=value / "key":"value" fragments that slipped in
# through free-form message text.
_INLINE_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<key>(api[_-]?key|bearer\s+[a-z0-9\-._]+|password|passwd|secret|token|authorization))
    (\s*[=:]\s*)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s,;&]+)
    """
)

_REDACTED = "[REDACTED]"


def redact_text(text: str) -> str:
    return _INLINE_SECRET_RE.sub(lambda m: f"{m.group('key')}={_REDACTED}", text)


def _redact_value(value: object, depth: int = 0) -> object:
    if depth > 6:
        return "[TRUNCATED]"
    if isinstance(value, dict):
        return {
            k: (_REDACTED if _SENSITIVE_KEY_RE.search(str(k)) else _redact_value(v, depth + 1))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact_value(v, depth + 1) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


class JsonFormatter(logging.Formatter):
    """Emits one JSON object per log line with scan-correlation fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }
        extra = getattr(record, "scan_ctx", None)
        if isinstance(extra, dict):
            redacted = _redact_value(extra)
            if isinstance(redacted, dict):
                payload.update(redacted)
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(debug: bool = False) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.handlers[:] = [handler]
    for noisy in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


class ScanLogger(logging.LoggerAdapter):
    """Logger adapter attaching scan_id/stage context to every record."""

    def __init__(self, logger: logging.Logger, scan_id: str, stage: str = "") -> None:
        super().__init__(logger, {})
        self._ctx = {"scan_id": scan_id, "stage": stage}

    def with_stage(self, stage: str) -> "ScanLogger":
        return ScanLogger(self.logger, str(self._ctx["scan_id"]), stage)

    def process(self, msg: str, kwargs: MutableMapping[str, Any]) -> tuple[str, MutableMapping[str, Any]]:
        kwargs.setdefault("extra", {})
        kwargs["extra"]["scan_ctx"] = {**self._ctx, **kwargs["extra"].get("scan_ctx", {})}
        return redact_text(msg), kwargs


def get_scan_logger(scan_id: str, stage: str = "") -> ScanLogger:
    return ScanLogger(logging.getLogger("scanner"), scan_id, stage)
