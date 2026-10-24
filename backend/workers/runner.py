"""In-process background job registry.

Scans run as asyncio tasks owned by the API process (single-worker dev
deployment; see ARCHITECTURE.md for the multi-worker roadmap). The registry
supports cooperative cancellation: the cancel event is created by the caller
and shared with the pipeline, so cancelling signals the SafetyController and
stage checkpoints, which persist a 'cancelled' status.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from backend.core.logging import get_scan_logger


@dataclass
class RunningScan:
    task: asyncio.Task | None = None
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)


class ScanRunner:
    def __init__(self) -> None:
        self._running: dict[str, RunningScan] = {}

    def start(self, scan_id: str, coro, cancel_event: asyncio.Event | None = None) -> None:  # type: ignore[no-untyped-def]
        if scan_id in self._running:
            return
        entry = RunningScan(cancel_event=cancel_event or asyncio.Event())
        task = asyncio.create_task(coro, name=f"scan-{scan_id}")
        entry.task = task
        self._running[scan_id] = entry
        task.add_done_callback(lambda _t: self._running.pop(scan_id, None))

    def cancel_event_for(self, scan_id: str) -> asyncio.Event | None:
        entry = self._running.get(scan_id)
        return entry.cancel_event if entry else None

    def cancel(self, scan_id: str) -> bool:
        entry = self._running.get(scan_id)
        if not entry:
            return False
        entry.cancel_event.set()
        if entry.task and not entry.task.done():
            entry.task.cancel()
        get_scan_logger(scan_id, "runner").info("scan cancellation requested")
        return True

    def is_running(self, scan_id: str) -> bool:
        entry = self._running.get(scan_id)
        return bool(entry and entry.task and not entry.task.done())

    @property
    def running_ids(self) -> list[str]:
        return [sid for sid, e in self._running.items() if e.task and not e.task.done()]


runner = ScanRunner()
