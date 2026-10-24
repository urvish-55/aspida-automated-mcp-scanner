"""Semantic engine: selects the configured provider, runs the review, and
guarantees a well-formed SemanticResult under every failure mode."""

from __future__ import annotations

from backend.core.config import get_settings
from backend.core.logging import get_scan_logger
from backend.scanners.semantic.base import SemanticResult
from backend.scanners.semantic.providers import (
    DisabledProvider,
    ExternalLLMProvider,
    OllamaProvider,
    SemanticProviderError,
    parse_review_response,
)


def build_provider():
    settings = get_settings()
    if settings.llm_provider == "local":
        return OllamaProvider(settings.llm_endpoint, settings.llm_model, settings.llm_timeout_seconds)
    if settings.llm_provider == "external":
        try:
            return ExternalLLMProvider(
                settings.llm_endpoint, settings.llm_model, settings.llm_api_key, settings.llm_timeout_seconds
            )
        except SemanticProviderError as exc:
            return _MisconfiguredProvider(str(exc))
    return DisabledProvider()


class _MisconfiguredProvider:
    """Stand-in used when configuration is incomplete; yields honest unavailability."""

    name = "misconfigured"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    async def review_findings(self, findings, tool_context):  # type: ignore[no-untyped-def]
        raise SemanticProviderError(self.reason)


async def run_semantic_analysis(findings: list[dict], tool_context: list[dict]) -> SemanticResult:
    """Never raises. Status is one of: completed | unavailable | error | skipped."""
    settings = get_settings()
    log = get_scan_logger("semantic", "semantic_analysis")
    if not settings.semantic_analysis_enabled:
        return SemanticResult(status="skipped", provider="disabled", reason="semantic analysis disabled for this scan")
    provider = build_provider()
    if isinstance(provider, DisabledProvider):
        return SemanticResult(status="unavailable", provider="disabled", reason="no LLM provider configured (LLM_PROVIDER=disabled); deterministic analysis is unaffected")
    try:
        raw = await provider.review_findings(findings, tool_context)
        observations, notes = raw if isinstance(raw, tuple) else await parse_review_response(raw, provider.name)
        return SemanticResult(status="completed", provider=provider.name, observations=observations, general_notes=notes)
    except SemanticProviderError as exc:
        log.info(f"semantic provider unavailable: {exc}")
        return SemanticResult(status="unavailable", provider=getattr(provider, "name", "unknown"), reason=str(exc))
    except Exception as exc:  # noqa: BLE001 - semantic layer must never break a scan
        log.error(f"semantic analysis failed unexpectedly: {type(exc).__name__}")
        return SemanticResult(status="error", provider=getattr(provider, "name", "unknown"), reason=f"{type(exc).__name__}: {exc}")
