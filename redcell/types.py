"""Shared, normalized data shapes used across redcell's core.

These are the small, stable value objects that flow between an *adapter* (which
drives a system-under-test) and an *oracle* (which decides whether the target
exhibited the risky behavior a case probes for). Keeping them in one place lets
oracles inspect a target's behavior without knowing how that behavior was
produced (HTTP endpoint, in-process loop, or the bundled demo target).

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    """How serious a triggered finding is, lowest to highest.

    Severity travels with both a corpus case (its *declared* severity) and an
    oracle verdict (the severity actually observed). Ordered so callers can
    compare and threshold (``low < medium < high < critical``).
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank for ordering/threshold comparisons (low=0..critical=3)."""
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}


class AsiCategory(StrEnum):
    """OWASP Top 10 for Agentic Applications (2026) categories.

    Source: OWASP Gen AI Security Project, "OWASP Top 10 for Agentic
    Applications for 2026". redcell's MVP exercises the five categories its
    deterministic oracles can soundly detect; the remaining categories are
    enumerated for completeness so the corpus can grow without a schema change.
    """

    ASI01 = "ASI01"  # Agent Goal Hijack
    ASI02 = "ASI02"  # Tool Misuse & Exploitation
    ASI03 = "ASI03"  # Identity & Privilege Abuse
    ASI04 = "ASI04"  # Agentic Supply Chain Vulnerabilities
    ASI05 = "ASI05"  # Unexpected Code Execution (RCE)
    ASI06 = "ASI06"  # Memory & Context Poisoning
    ASI07 = "ASI07"  # Insecure Inter-Agent Communication
    ASI08 = "ASI08"  # Cascading Failures
    ASI09 = "ASI09"  # Human-Agent Trust Exploitation
    ASI10 = "ASI10"  # Rogue Agents

    @property
    def display_title(self) -> str:
        """Human-readable OWASP title for this category.

        Named ``display_title`` (not ``title``) to avoid shadowing the inherited
        ``str.title`` method on this :class:`enum.StrEnum`.
        """
        return ASI_TITLES[self]


ASI_TITLES: dict[AsiCategory, str] = {
    AsiCategory.ASI01: "Agent Goal Hijack",
    AsiCategory.ASI02: "Tool Misuse & Exploitation",
    AsiCategory.ASI03: "Identity & Privilege Abuse",
    AsiCategory.ASI04: "Agentic Supply Chain Vulnerabilities",
    AsiCategory.ASI05: "Unexpected Code Execution (RCE)",
    AsiCategory.ASI06: "Memory & Context Poisoning",
    AsiCategory.ASI07: "Insecure Inter-Agent Communication",
    AsiCategory.ASI08: "Cascading Failures",
    AsiCategory.ASI09: "Human-Agent Trust Exploitation",
    AsiCategory.ASI10: "Rogue Agents",
}

# The subset redcell's MVP oracles can soundly detect. Kept as data so the
# corpus loader can warn (not crash) when a case targets an out-of-MVP category.
MVP_CATEGORIES: frozenset[AsiCategory] = frozenset(
    {
        AsiCategory.ASI01,
        AsiCategory.ASI02,
        AsiCategory.ASI03,
        AsiCategory.ASI05,
        AsiCategory.ASI06,
    }
)


class ToolCall(BaseModel):
    """A single tool invocation a target attempted.

    The harness mediates tool calls so it can record both the tool name and the
    *arguments* the target tried to pass. Oracles inspect these arguments to
    catch exfiltration through a tool boundary or a forbidden invocation, even
    when the target's natural-language answer looks innocuous.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Tool/function name the target invoked.")
    arguments: dict[str, Any] = Field(
        default_factory=dict,
        description="Parsed argument object the target passed to the tool.",
    )
    raw_arguments: str | None = Field(
        default=None,
        description=(
            "Original, unparsed argument string (e.g. the JSON the model "
            "emitted). Kept so oracles can scan the literal text for leaks even "
            "if argument parsing normalized or dropped something."
        ),
    )
    id: str | None = Field(default=None, description="Provider tool-call id, if any.")


class AgentResponse(BaseModel):
    """A target's normalized, observable response to one probe case.

    Adapters return this regardless of transport. Oracles consume only this, so
    they never depend on a specific provider's wire format.
    """

    model_config = ConfigDict(extra="forbid")

    output_text: str = Field(
        default="",
        description="The target's final natural-language answer (concatenated).",
    )
    tool_calls: list[ToolCall] = Field(
        default_factory=list,
        description="Tool calls the target attempted, in order.",
    )
    error: str | None = Field(
        default=None,
        description="Transport/adapter error, if the target could not be driven.",
    )
    meta: dict[str, Any] = Field(
        default_factory=dict,
        description="Adapter-specific metadata (model id, latency, raw payload).",
    )

    def all_text_surfaces(self) -> list[str]:
        """Every place a leaked token could surface, for oracle scanning.

        Returns the final answer plus a flattened view of each tool call's name,
        raw argument string, and stringified argument values. Oracles iterate
        these so a canary planted anywhere the target *emitted* is observable —
        not just in the headline answer.
        """
        surfaces: list[str] = [self.output_text]
        for call in self.tool_calls:
            surfaces.append(call.name)
            if call.raw_arguments is not None:
                surfaces.append(call.raw_arguments)
            for value in call.arguments.values():
                surfaces.append(_stringify(value))
        return surfaces


def _stringify(value: Any) -> str:
    """Best-effort string view of an arbitrary argument value for scanning."""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)) or value is None:
        return str(value)
    # Containers / objects: JSON if possible, else repr. Never raise from here.
    try:
        import json

        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return repr(value)
