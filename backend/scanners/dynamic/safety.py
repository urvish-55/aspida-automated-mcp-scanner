"""SafetyController: enforces the guardrails that make dynamic testing
"safe by default".

Every probe call goes through check_and_reserve(), which:
- refuses to run when safe_mode is off but payload/request caps still apply
- enforces global max request count, payload size cap, per-test timeout,
  minimum interval between requests (rate limit)
- records an audit entry for every request attempt (sent or refused)
- supports cooperative cancellation from the API layer

Refusals are surfaced to the report as skipped/error test outcomes with an
explicit reason — never silently dropped.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from backend.core.config import get_settings


class SafetyViolation(Exception):
    """A requested probe exceeded a safety limit and was refused."""


class ScanCancelled(Exception):
    pass


@dataclass
class AuditEntry:
    timestamp: float
    event: str  # request_allowed | request_refused | budget_exhausted | cancelled
    reason: str
    test_id: str = ""
    tool: str = ""
    payload_size: int = 0


@dataclass
class SafetyController:
    max_requests: int
    max_payload_bytes: int
    per_test_timeout: float
    min_interval: float  # seconds between requests (rate limit)
    safe_mode: bool
    allow_local: bool = False  # may the dynamic target be a local/private host?
    cancelled: asyncio.Event = field(default_factory=asyncio.Event)

    requests_sent: int = 0
    requests_refused: int = 0
    audit: list[AuditEntry] = field(default_factory=list)
    _last_request: float = 0.0

    @classmethod
    def from_settings(
        cls, *, dynamic_enabled: bool, safe_mode: bool, allow_local: bool | None = None
    ) -> "SafetyController":
        s = get_settings()
        if not dynamic_enabled:
            raise ValueError("SafetyController should only be created when dynamic testing is enabled")
        return cls(
            max_requests=s.max_dynamic_requests,
            max_payload_bytes=s.max_payload_size_bytes,
            per_test_timeout=s.per_test_timeout_seconds,
            min_interval=1.0 / s.dynamic_rate_limit_per_second,
            safe_mode=safe_mode,
            allow_local=s.allow_local_targets if allow_local is None else allow_local,
        )

    # ------------------------------------------------------------------
    @property
    def budget_remaining(self) -> int:
        return max(0, self.max_requests - self.requests_sent)

    def raise_if_cancelled(self) -> None:
        if self.cancelled.is_set():
            raise ScanCancelled("scan cancelled by operator")

    async def check_and_reserve(self, *, test_id: str, tool: str, payload_size: int) -> None:
        """Reserve budget for one request or raise SafetyViolation."""
        self.raise_if_cancelled()
        if self.requests_sent >= self.max_requests:
            self.requests_refused += 1
            self.audit.append(
                AuditEntry(time.time(), "budget_exhausted", f"max requests ({self.max_requests}) reached", test_id, tool)
            )
            raise SafetyViolation(f"request budget exhausted ({self.max_requests} max)")
        if payload_size > self.max_payload_bytes:
            self.requests_refused += 1
            self.audit.append(
                AuditEntry(time.time(), "request_refused", f"payload {payload_size}B exceeds cap {self.max_payload_bytes}B", test_id, tool, payload_size)
            )
            raise SafetyViolation(f"payload of {payload_size} bytes exceeds cap of {self.max_payload_bytes} bytes")

        # rate limiting: wait until at least min_interval since last request
        now = time.monotonic()
        wait = self._last_request + self.min_interval - now
        if wait > 0:
            await asyncio.sleep(wait)
            now = time.monotonic()
        self.raise_if_cancelled()
        self._last_request = now
        self.requests_sent += 1
        self.audit.append(AuditEntry(time.time(), "request_allowed", "ok", test_id, tool, payload_size))

    async def run_with_timeout(self, coro, *, test_id: str):
        """Run a probe coroutine under the per-test timeout."""
        self.raise_if_cancelled()
        try:
            return await asyncio.wait_for(coro, timeout=self.per_test_timeout)
        except asyncio.TimeoutError:
            raise SafetyViolation(f"probe timed out after {self.per_test_timeout}s") from None

    def cancel(self) -> None:
        self.cancelled.set()
        self.audit.append(AuditEntry(time.time(), "cancelled", "operator requested cancellation"))

    def audit_summary(self) -> dict[str, Any]:
        return {
            "requests_sent": self.requests_sent,
            "requests_refused": self.requests_refused,
            "max_requests": self.max_requests,
            "max_payload_bytes": self.max_payload_bytes,
            "per_test_timeout_seconds": self.per_test_timeout,
            "min_request_interval_seconds": round(self.min_interval, 4),
            "safe_mode": self.safe_mode,
            "cancelled": self.cancelled.is_set(),
        }
