"""Concrete semantic providers. All are optional adapters:

- DisabledProvider: default. Always "unavailable" with a clear reason.
- OllamaProvider: local LLM (Mode B) via the Ollama HTTP API on localhost.
- ExternalLLMProvider: any OpenAI-compatible chat API (Mode C), key via env.

Every provider degrades gracefully: failures raise SemanticProviderError which
the engine converts into status="unavailable"/"error" — never into fake output.
Prompts are strictly scoped: they receive finding titles/descriptions and tool
metadata, never secrets or env values (env values are never ingested anywhere).
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from backend.scanners.semantic.base import SemanticObservation


class SemanticProviderError(Exception):
    pass


class DisabledProvider:
    name = "disabled"

    async def review_findings(
        self, findings: list[dict[str, Any]], tool_context: list[dict[str, Any]]
    ) -> tuple[list[SemanticObservation], list[str]]:
        raise SemanticProviderError("semantic analysis is disabled (no provider configured)")


class _HTTPChatProvider:
    """Shared plumbing for OpenAI-style chat endpoints (Ollama exposes one)."""

    name = "http"

    def __init__(self, endpoint: str, model: str, api_key: str = "", timeout: float = 20.0) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    async def _chat(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": 0,
            "stream": False,
        }
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=False) as client:
                resp = await client.post(self.endpoint, json=payload, headers=self._headers())
        except httpx.HTTPError as exc:
            raise SemanticProviderError(f"provider unreachable: {type(exc).__name__}") from exc
        if resp.status_code != 200:
            raise SemanticProviderError(f"provider returned HTTP {resp.status_code}")
        try:
            body = resp.json()
        except json.JSONDecodeError as exc:
            raise SemanticProviderError("provider returned non-JSON body") from exc
        try:
            return body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise SemanticProviderError(f"unexpected provider response shape: {exc}") from exc

    async def review_findings(
        self, findings: list[dict[str, Any]], tool_context: list[dict[str, Any]]
    ) -> str:
        """Returns the raw provider text; the engine parses it defensively."""
        if not findings:
            return '{"assessments":[],"general_notes":["no findings to review"]}'
        return await self._chat(SYSTEM_PROMPT, _build_user_prompt(findings, tool_context))


SYSTEM_PROMPT = (
    "You are a security analyst reviewing findings from an MCP (Model Context Protocol) "
    "server scanner. For each finding, judge whether the presented evidence supports the "
    "claimed severity, using only the provided information. Be skeptical: if evidence is "
    "insufficient, say so. Respond ONLY with JSON of the form "
    '{"assessments":[{"rule_id":"...","stance":"agrees|disagrees|unclear","note":"..."}],'
    '"general_notes":["..."]}. Do not invent facts not present in the input.'
)


def _build_user_prompt(findings: list[dict[str, Any]], tool_context: list[dict[str, Any]]) -> str:
    compact = [
        {
            "rule_id": f.get("rule_id"),
            "severity": f.get("severity"),
            "status": f.get("status"),
            "title": f.get("title"),
            "description": (f.get("description") or "")[:600],
            "evidence_summaries": [e.get("summary", "")[:200] for e in (f.get("evidence") or [])[:5]],
        }
        for f in findings[:30]
    ]
    tools = [{"name": t.get("name"), "description": (t.get("description") or "")[:300]} for t in tool_context[:30]]
    return json.dumps({"findings": compact, "tools": tools}, ensure_ascii=False)


class OllamaProvider(_HTTPChatProvider):
    """Local LLM through Ollama's OpenAI-compatible endpoint. No API key."""

    name = "local"

    def __init__(self, endpoint: str, model: str, timeout: float) -> None:
        # endpoint example: http://127.0.0.1:11434/v1/chat/completions
        super().__init__(endpoint or "http://127.0.0.1:11434/v1/chat/completions", model or "llama3.2", timeout=timeout)


class ExternalLLMProvider(_HTTPChatProvider):
    """External OpenAI-compatible API through the adapter. Key comes from env."""

    name = "external"

    def __init__(self, endpoint: str, model: str, api_key: str, timeout: float) -> None:
        if not endpoint:
            raise SemanticProviderError("external LLM provider requires LLM_ENDPOINT")
        if not api_key:
            raise SemanticProviderError("external LLM provider requires LLM_API_KEY")
        super().__init__(endpoint, model or "gpt-4o-mini", api_key=api_key, timeout=timeout)


async def parse_review_response(
    raw: str, provider_name: str
) -> tuple[list[SemanticObservation], list[str]]:
    """Parse the provider's JSON output defensively; malformed output is an error."""
    text = raw.strip()
    # strip markdown fences if present
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SemanticProviderError(f"provider output was not valid JSON: {exc}") from exc
    observations = [
        SemanticObservation(
            rule_id=str(a.get("rule_id", "")),
            stance=a.get("stance", "unclear") if a.get("stance") in ("agrees", "disagrees", "unclear") else "unclear",
            note=str(a.get("note", ""))[:1000],
            provider=provider_name,
        )
        for a in data.get("assessments", [])[:50]
        if isinstance(a, dict)
    ]
    notes = [str(n)[:1000] for n in data.get("general_notes", [])[:10] if isinstance(n, str)]
    return observations, notes
