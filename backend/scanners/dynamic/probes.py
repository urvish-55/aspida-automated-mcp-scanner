"""SchemaProbeGenerator + InputValidationTester: build INERT probe arguments.

Safety invariants for every probe generated here:
- No destructive payloads: no rm/format/kill/etc. ever appear in payloads.
- Command-injection probes use `echo <MARKER>` only; the marker string is a
  random per-scan nonce, so a hit is unambiguous evidence of execution.
- Path-traversal probes read well-known harmless files (passwd/win.ini) and are
  capped by the payload controller.
- Oversized probes are bounded by the configured payload cap.
Every probe carries its rationale and the exact response indicators that would
constitute evidence, so outcomes are explainable.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

from backend.scanners.dynamic.connector import MCPTool
from backend.scanners.static.schema_analyzer import _iter_params

MARKER_PREFIX = "MCPPENTEST"


@dataclass
class Probe:
    test_id: str
    test_name: str
    family: str  # path_traversal|command_injection|oversized|malformed|schema_violation
    tool_name: str
    arguments: dict[str, Any]
    rationale: str
    success_indicators: list[str] = field(default_factory=list)  # markers meaning "validation bypassed"
    rejection_indicators: list[str] = field(default_factory=list)  # markers meaning "tool rejected input"

    @property
    def payload_size(self) -> int:
        import json

        try:
            return len(json.dumps(self.arguments, default=str).encode("utf-8"))
        except (TypeError, ValueError):
            return 0


def _first_string_param(schema: dict[str, Any], matcher) -> str | None:
    """Return the first top-level parameter path matching the predicate."""
    for path, prop, _req in _iter_params(schema):
        name = path.split(".")[-1]
        depth = path.count(".")
        if depth == 0 and isinstance(prop, dict) and prop.get("type", "string") in ("string", None) and matcher(name):
            return path
    return None


def _fill_other_required(schema: dict[str, Any], skip: str) -> dict[str, Any]:
    """Best-effort fill of other required params with inert values so the probe
    reaches the vulnerable code path instead of dying on missing args."""
    args: dict[str, Any] = {}
    for path, prop, required in _iter_params(schema):
        if path != skip and required and path.count(".") == 0:
            t = prop.get("type", "string")
            if t == "string":
                args[path] = "mcp-pentest"
            elif t == "integer" or t == "number":
                args[path] = 1
            elif t == "boolean":
                args[path] = False
            elif t == "array":
                args[path] = []
            elif t == "object":
                args[path] = {}
    return args


def is_path_like(name: str) -> bool:
    n = name.lower()
    return any(tok in n for tok in ("path", "file", "filename", "filepath", "dir", "folder", "location", "target_path"))


def is_shell_like(name: str) -> bool:
    n = name.lower()
    return any(tok in n for tok in ("command", "cmd", "exec", "shell", "script", "args", "interpreter"))


TRAVERSAL_PAYLOADS: tuple[tuple[str, str], ...] = (
    ("../../../etc/passwd", "unix passwd file"),
    ("..\\..\\..\\windows\\win.ini", "windows win.ini"),
    ("..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal"),
    ("/etc/passwd", "absolute path escape"),
)


class ProbeGenerator:
    def __init__(self, marker_secret: str | None = None) -> None:
        nonce = secrets.token_hex(4)
        self.marker = f"{MARKER_PREFIX}_{marker_secret or nonce}"
        self._seq = 0

    def _tid(self, family: str) -> str:
        self._seq += 1
        return f"DYN-{family[:4].upper()}-{self._seq:03d}"

    # ------------------------------------------------------------------
    def traversal_probes(self, tool: MCPTool) -> list[Probe]:
        probes: list[Probe] = []
        param = _first_string_param(tool.input_schema, is_path_like)
        if not param:
            return probes
        for payload, what in TRAVERSAL_PAYLOADS:
            args = _fill_other_required(tool.input_schema, param)
            args[param] = payload
            probes.append(
                Probe(
                    test_id=self._tid("path"),
                    test_name=f"Path traversal ({what}) on '{param}'",
                    family="path_traversal",
                    tool_name=tool.name,
                    arguments=args,
                    rationale=(
                        f"Parameter '{param}' accepts a filesystem-looking path. A traversal payload "
                        f"probes whether the server restricts resolution to an allowlisted root. "
                        f"The payload only reads a well-known harmless file."
                    ),
                    success_indicators=["root:x:0:0:", "daemon:", "[fonts]", "[extensions]"],
                    rejection_indicators=["traversal", "outside", "allowlist", "not allowed", "invalid path", "denied", "escape"],
                )
            )
        return probes

    def command_injection_probes(self, tool: MCPTool) -> list[Probe]:
        probes: list[Probe] = []
        param = _first_string_param(tool.input_schema, is_shell_like)
        if not param:
            return probes
        inert_payloads = (
            f"; echo {self.marker}",
            f"$(echo {self.marker})",
            f"`echo {self.marker}`",
            f"&& echo {self.marker}",
            f"| echo {self.marker}",
            f"\necho {self.marker}",
        )
        for payload in inert_payloads:
            args = _fill_other_required(tool.input_schema, param)
            args[param] = payload
            probes.append(
                Probe(
                    test_id=self._tid("cmdi"),
                    test_name=f"Command injection (inert echo marker) on '{param}'",
                    family="command_injection",
                    tool_name=tool.name,
                    arguments=args,
                    rationale=(
                        f"Parameter '{param}' carries shell-like input. The probe appends an inert "
                        f"`echo {self.marker}` (harmless by construction). If the marker text is "
                        f"returned in the response, the input reached a shell. Nothing destructive "
                        f"is ever sent."
                    ),
                    success_indicators=[self.marker],
                    rejection_indicators=["invalid", "not allowed", "rejected", "metacharacter", "disallowed", "error"],
                )
            )
        return probes

    def oversized_probes(self, tool: MCPTool, max_payload_bytes: int) -> list[Probe]:
        probes: list[Probe] = []
        param = _first_string_param(tool.input_schema, lambda n: True)
        if not param:
            return probes
        # bounded: half the payload cap, at most 64 KiB
        size = min(max_payload_bytes // 2, 64 * 1024)
        args = _fill_other_required(tool.input_schema, param)
        args[param] = "A" * size
        probes.append(
            Probe(
                test_id=self._tid("size"),
                test_name=f"Oversized input ({size} bytes) on '{param}'",
                family="oversized",
                tool_name=tool.name,
                arguments=args,
                rationale=(
                    f"Parameter '{param}' is a string with no maxLength constraint in the schema. "
                    f"A bounded oversized value checks whether server-side size validation exists. "
                    f"Size is capped well below the scan payload limit ({max_payload_bytes}B)."
                ),
                success_indicators=[],
                rejection_indicators=["too long", "too large", "invalid", "length", "size", "limit", "exceed", "413"],
            )
        )
        return probes

    def malformed_probes(self, tool: MCPTool) -> list[Probe]:
        """Wrong types, null, empty, missing required, unexpected extra field."""
        probes: list[Probe] = []
        schema = tool.input_schema
        string_param = _first_string_param(schema, lambda n: True)
        required_params = [
            p for p, prop, req in _iter_params(schema) if req and p.count(".") == 0
        ]

        if string_param:
            for wrong, label in ((12345, "integer into string param"), (None, "null value"), ("", "empty string")):
                if wrong is None and "null" in str(schema.get("type", "")).lower():
                    continue
                args = _fill_other_required(schema, string_param)
                args[string_param] = wrong
                probes.append(
                    Probe(
                        test_id=self._tid("malf"),
                        test_name=f"Malformed input ({label}) on '{string_param}'",
                        family="malformed",
                        tool_name=tool.name,
                        arguments=args,
                        rationale=f"Sends {label} to verify server-side type validation.",
                        success_indicators=[],
                        rejection_indicators=["invalid", "type", "required", "expected", "validation", "error"],
                    )
                )

        # unexpected extra field
        args = _fill_other_required(schema, "")
        args["__pentest_probe_field__"] = self.marker
        probes.append(
            Probe(
                test_id=self._tid("malf"),
                test_name="Unexpected extra field",
                family="malformed",
                tool_name=tool.name,
                arguments=args,
                rationale="Sends an undeclared field to check whether the server rejects unknown properties.",
                success_indicators=[],
                rejection_indicators=["unknown", "unexpected", "invalid", "additionalproperties", "error"],
            )
        )

        # missing required fields (only if something is required):
        # fill every required param EXCEPT the first, genuinely omitting it
        if required_params:
            args = _fill_other_required(schema, required_params[0])
            probes.append(
                Probe(
                    test_id=self._tid("malf"),
                    test_name=f"Missing required field '{required_params[0]}'",
                    family="malformed",
                    tool_name=tool.name,
                    arguments=args,
                    rationale="Omits a required parameter to verify the server rejects incomplete input.",
                    success_indicators=[],
                    rejection_indicators=["required", "missing", "invalid", "error"],
                )
            )
        return probes

    def schema_violation_probes(self, tool: MCPTool) -> list[Probe]:
        probes: list[Probe] = []
        schema = tool.input_schema
        for path, prop, _req in list(_iter_params(schema))[:6]:
            if path.count(".") != 0 or not isinstance(prop, dict):
                continue
            if "enum" in prop and isinstance(prop["enum"], list) and prop["enum"]:
                args = _fill_other_required(schema, path)
                args[path] = "__invalid_enum_value__"
                probes.append(
                    Probe(
                        test_id=self._tid("viol"),
                        test_name=f"Enum violation on '{path}'",
                        family="schema_violation",
                        tool_name=tool.name,
                        arguments=args,
                        rationale="Sends a value outside the declared enum to test schema enforcement.",
                        success_indicators=[],
                        rejection_indicators=["enum", "invalid", "expected", "error", "must be"],
                    )
                )
            if "pattern" in prop and isinstance(prop["pattern"], str):
                args = _fill_other_required(schema, path)
                args[path] = "!!!violation!!!"
                probes.append(
                    Probe(
                        test_id=self._tid("viol"),
                        test_name=f"Pattern violation on '{path}'",
                        family="schema_violation",
                        tool_name=tool.name,
                        arguments=args,
                        rationale="Sends a value that violates the declared pattern to test schema enforcement.",
                        success_indicators=[],
                        rejection_indicators=["pattern", "invalid", "match", "error", "must"],
                    )
                )
        return probes

    def probes_for_tool(self, tool: MCPTool, *, max_payload_bytes: int) -> list[Probe]:
        probes: list[Probe] = []
        probes.extend(self.traversal_probes(tool))
        probes.extend(self.command_injection_probes(tool))
        probes.extend(self.oversized_probes(tool, max_payload_bytes))
        probes.extend(self.malformed_probes(tool))
        probes.extend(self.schema_violation_probes(tool))
        return probes
