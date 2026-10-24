"""Semantic analysis abstraction.

The semantic layer is strictly OPTIONAL and never authoritative:
- It annotates findings with a second opinion (agreement/disagreement).
- It can surface candidate observations that the deterministic rules then
  re-verify; it can NEVER create a confirmed finding by itself.
- Any failure (no provider, network error, bad output, timeout) yields
  status="unavailable" plus a reason, and the scan continues normally.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

SemanticStatus = Literal["unavailable", "completed", "skipped", "error"]


@dataclass
class SemanticObservation:
    """A semantic-layer opinion about one finding (or a free-text observation)."""

    rule_id: str  # finding it refers to, or "" for general observations
    stance: Literal["agrees", "disagrees", "unclear"]
    note: str
    provider: str


@dataclass
class SemanticResult:
    status: SemanticStatus
    provider: str = "disabled"
    reason: str = ""  # when unavailable/error: the honest explanation
    observations: list[SemanticObservation] = field(default_factory=list)
    general_notes: list[str] = field(default_factory=list)


class SemanticProvider(Protocol):
    name: str

    async def review_findings(
        self, findings: list[dict[str, Any]], tool_context: list[dict[str, Any]]
    ) -> tuple[list[SemanticObservation], list[str]]:
        """Return (per-finding observations, general notes). May raise."""
        ...
