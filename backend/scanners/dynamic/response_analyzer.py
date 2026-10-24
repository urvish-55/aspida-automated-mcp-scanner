"""ResponseAnalyzer: turns a raw probe result into a structured verdict.

Evidence rules (deliberately conservative):
- Command injection family: CONFIRMED only if the unique per-scan marker appears
  in the response (unambiguous execution evidence). Otherwise "passed".
- Path traversal family: CONFIRMED if a sentinel file's distinctive content
  appears; "passed" if the server rejected; "suspected finding" if the server
  returned a non-rejection but also no sentinel (ambiguous, honestly reported).
- Validation families (oversized/malformed/schema_violation): a finding is
  raised when the server ACCEPTS invalid input without any rejection indicator;
  this indicates missing server-side validation. Severity: low/medium.
Nothing here invents success: ambiguity is preserved as ambiguity.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from backend.scanners.dynamic.probes import Probe
from backend.scanners.dynamic.connector import CallResult


@dataclass
class ProbeOutcome:
    probe: Probe
    call: CallResult
    verdict: str  # finding | passed | error | ambiguous
    severity: str = "info"
    title: str = ""
    evidence_detail: dict = field(default_factory=dict)
    note: str = ""


class ResponseAnalyzer:
    def analyze(self, probe: Probe, call: CallResult) -> ProbeOutcome:
        if not call.ok:
            return ProbeOutcome(
                probe=probe,
                call=call,
                verdict="error",
                title=f"{probe.test_name}: transport/protocol error",
                evidence_detail={"error": call.error, "http_status": call.raw_status},
                note="The probe could not be completed; this is NOT a security pass or fail.",
            )

        text = call.content_text or ""
        if call.structured is not None:
            text += "\n" + str(call.structured)
        lowered = text.lower()

        hit_success = next((ind for ind in probe.success_indicators if ind.lower() in lowered), None)
        hit_rejection = next((ind for ind in probe.rejection_indicators if ind.lower() in lowered), None)

        if probe.family == "command_injection":
            if hit_success:
                return ProbeOutcome(
                    probe, call, "finding", "critical",
                    f"Command injection confirmed on tool '{probe.tool_name}'",
                    {
                        "marker": hit_success,
                        "reason": "The inert echo marker injected via the parameter was returned in "
                                  "the tool response, proving the input reached a command interpreter.",
                        "payload": probe.arguments,
                    },
                )
            if hit_rejection:
                return ProbeOutcome(probe, call, "passed", note=f"Server rejected the payload ('{hit_rejection}').")
            return ProbeOutcome(
                probe, call, "ambiguous", "info",
                f"Command injection probe inconclusive on '{probe.tool_name}'",
                {"response_excerpt": text[:400]},
                note="No marker and no explicit rejection; the tool likely ignored or echoed the input. "
                     "Treated as inconclusive, not as a pass.",
            )

        if probe.family == "path_traversal":
            if hit_success:
                return ProbeOutcome(
                    probe, call, "finding", "critical",
                    f"Path traversal confirmed on tool '{probe.tool_name}'",
                    {
                        "sentinel": hit_success,
                        "reason": "Distinctive content of a system sentinel file appeared in the "
                                  "response, proving the path escaped the intended root.",
                        "payload": probe.arguments,
                    },
                )
            if hit_rejection:
                return ProbeOutcome(probe, call, "passed", note=f"Server rejected the path ('{hit_rejection}').")
            return ProbeOutcome(
                probe, call, "ambiguous", "medium",
                f"Path traversal probe inconclusive on '{probe.tool_name}'",
                {"response_excerpt": text[:400]},
                note="No sentinel content and no explicit rejection. The tool may have returned its "
                     "own error text; treated as inconclusive.",
            )

        # validation families: oversized / malformed / schema_violation
        # Calibration: accepting an empty string or an unknown extra field is
        # common in benign servers and is NOT reported as a finding (recorded
        # as a passed check with a note). Accepting a wrong-typed value, null
        # for a required string, or a value violating enum/pattern/size limits
        # indicates missing server-side validation and IS reported.
        benign_acceptable = (
            probe.family == "malformed"
            and ("(empty string)" in probe.test_name or "Unexpected extra field" in probe.test_name)
        )
        if hit_rejection:
            return ProbeOutcome(probe, call, "passed", note=f"Input rejected ('{hit_rejection}').")
        if hit_success:
            return ProbeOutcome(
                probe, call, "finding", "medium",
                f"Server accepted invalid input on '{probe.tool_name}'",
                {"payload": probe.arguments, "response_excerpt": text[:400]},
            )
        if call.is_error:
            return ProbeOutcome(probe, call, "passed", note="Tool reported an error result (input likely rejected).")
        if benign_acceptable:
            return ProbeOutcome(
                probe, call, "passed",
                note="Server accepted the value; acceptance of empty/extra fields is common and "
                     "recorded informationally, not as a validation finding.",
            )
        return ProbeOutcome(
            probe, call, "finding", "low",
            f"Missing input validation on '{probe.tool_name}' ({probe.family})",
            {
                "payload": probe.arguments,
                "response_excerpt": text[:400],
                "reason": "The server accepted malformed/invalid input without any rejection "
                          "signal, indicating absent server-side validation for this field.",
            },
        )
