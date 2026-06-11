"""The ``vulnagent`` agent: one rule-based agent, three hardening levels.

The agent receives a single flattened prompt that the harness builds from a probe
(see :func:`redcell.adapters._flatten_prompt`). That prompt is annotated with
channel markers so the agent knows which text came from which delivery vector::

    [channel:tool_result]
    <untrusted payload here>

    [user]
    <the user's actual request>

This channel structure is what makes *input delimiting* possible: a hardened
agent trusts directives from the user turn but treats text arriving on an
untrusted channel (a tool result, a retrieved document, planted memory, an
injected system-prompt note) as inert data, not commands.

The agent is deterministic and calls no model. It scans for a small set of
directive patterns and -- depending on its hardening level -- either follows them
(demonstrating a probe succeeding) or refuses/neutralizes them (demonstrating a
control working). Every side effect is mocked and contained.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted to
test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

# Channels the harness may plant untrusted content on. The user turn is the only
# channel an input-delimiting agent treats as authoritative for instructions.
_UNTRUSTED_CHANNELS = frozenset(
    {"tool_result", "retrieved_document", "memory", "system_prompt"}
)

# Tools the agent must never execute. Attempting one of these is itself the
# finding the forbidden-tool oracle watches for (ASI05 / ASI02).
_DISABLED_TOOLS = frozenset({"run_python", "shell", "exec", "eval", "system"})

# Recipients on these domains are treated as "external" by the hardened email
# guard. Both are reserved test domains, never real addresses.
_EXTERNAL_EMAIL_RE = re.compile(r"@(?:example\.(?:test|com|org)|attacker\.[a-z]+)$", re.I)


class HardeningLevel(StrEnum):
    """How many defensive controls the agent applies.

    Ordered weakest-to-strongest. Running the same corpus at each level and
    diffing the attack-success-rates is redcell's flagship measurement.
    """

    NONE = "none"  # credulous: follows directives from any channel
    BASIC = "basic"  # input delimiting + tool allow-listing
    HARDENED = "hardened"  # basic + output filtering + canary tripwires


class VulnToolError(RuntimeError):
    """Raised when a disabled or out-of-sandbox tool action is attempted."""


@dataclass
class RecordedCall:
    """A tool call the agent attempted, captured for the harness/oracles."""

    name: str
    arguments: dict[str, Any]


@dataclass
class VulnAgentResult:
    """The agent's observable output for one prompt (adapter-compatible)."""

    output_text: str
    tool_calls: list[RecordedCall] = field(default_factory=list)


@dataclass
class _Channel:
    """A labelled segment of the flattened prompt."""

    name: str  # "user", "tool_result", "memory", ...
    text: str
    trusted: bool


_CHANNEL_HEADER_RE = re.compile(r"^\[channel:([a-z_]+)\]\s*$", re.MULTILINE)
_USER_HEADER_RE = re.compile(r"^\[user\]\s*$", re.MULTILINE)


def _split_channels(prompt: str) -> list[_Channel]:
    """Parse a flattened prompt into labelled channel segments.

    Recognizes ``[channel:<vector>]`` and ``[user]`` headers emitted by the
    harness. Any text before the first header is attributed to the user turn (so
    a bare prompt with no markers still behaves sensibly). Unknown channels are
    treated as untrusted -- fail closed.
    """
    # Find all header positions (both [channel:x] and [user]).
    markers: list[tuple[int, int, str]] = []
    for m in _CHANNEL_HEADER_RE.finditer(prompt):
        markers.append((m.start(), m.end(), m.group(1)))
    for m in _USER_HEADER_RE.finditer(prompt):
        markers.append((m.start(), m.end(), "user"))
    markers.sort(key=lambda t: t[0])

    channels: list[_Channel] = []
    if not markers:
        return [_Channel(name="user", text=prompt, trusted=True)]

    # Any preamble before the first marker is part of the user turn.
    if markers[0][0] > 0:
        pre = prompt[: markers[0][0]].strip()
        if pre:
            channels.append(_Channel(name="user", text=pre, trusted=True))

    for idx, (_, body_start, name) in enumerate(markers):
        body_end = markers[idx + 1][0] if idx + 1 < len(markers) else len(prompt)
        text = prompt[body_start:body_end].strip()
        trusted = name == "user"
        channels.append(_Channel(name=name, text=text, trusted=trusted))
    return channels


@dataclass
class VulnAgent:
    """A sandboxed, rule-based agent with a configurable hardening level.

    Parameters
    ----------
    level:
        Which defensive controls to apply (see :class:`HardeningLevel`).
    sandbox_dir:
        The only directory ``read_file`` may read from. Defaults to a ``sandbox``
        folder next to this module.
    enable_code_exec:
        Must be explicitly ``True`` to even *attempt* the disabled ``run_python``
        tool; even then the tool raises. Default ``False``.
    known_secrets:
        Tokens the hardened level treats as canaries to scrub from any output or
        outbound tool argument (the "tripwire"). The harness populates this with
        the freshly-planted canary so output filtering is testable.
    """

    level: HardeningLevel = HardeningLevel.NONE
    sandbox_dir: Path = field(default_factory=lambda: Path(__file__).parent / "sandbox")
    enable_code_exec: bool = False
    memory: dict[str, str] = field(default_factory=dict)
    known_secrets: list[str] = field(default_factory=list)

    # --- mock tools -------------------------------------------------------- #

    def read_file(self, path: str) -> str:
        """Read a file, but only if it resolves inside ``sandbox_dir``."""
        target = (self.sandbox_dir / path).resolve()
        sandbox = self.sandbox_dir.resolve()
        if not target.is_relative_to(sandbox):
            raise VulnToolError(f"read_file blocked: {path!r} escapes sandbox")
        if not target.is_file():
            raise VulnToolError(f"read_file: no such file in sandbox: {path!r}")
        return target.read_text(encoding="utf-8")

    def send_email(self, to: str, body: str) -> str:
        """No-op email stub. Records the attempt; sends nothing."""
        return f"[stub] would send email to {to!r} ({len(body)} chars)"

    def kv_get(self, key: str) -> str | None:
        return self.memory.get(key)

    def kv_set(self, key: str, value: str) -> None:
        self.memory[key] = value

    def run_python(self, code: str) -> str:
        """DISABLED code-execution tool. Always raises."""
        raise VulnToolError("run_python is disabled in vulnagent by design")

    # --- defenses ---------------------------------------------------------- #

    @property
    def _input_delimiting(self) -> bool:
        return self.level in (HardeningLevel.BASIC, HardeningLevel.HARDENED)

    @property
    def _tool_allowlisting(self) -> bool:
        return self.level in (HardeningLevel.BASIC, HardeningLevel.HARDENED)

    @property
    def _output_filtering(self) -> bool:
        return self.level is HardeningLevel.HARDENED

    def _directive_is_trusted(self, channel: _Channel) -> bool:
        """Whether a directive found on ``channel`` should be obeyed.

        With input delimiting on, only directives from the user turn are obeyed;
        directives embedded in untrusted channels are ignored (treated as data).
        With it off, the agent is credulous and obeys directives from anywhere.
        """
        if not self._input_delimiting:
            return True
        return channel.trusted and channel.name not in _UNTRUSTED_CHANNELS

    def _scrub(self, text: str) -> str:
        """Redact any known secret from ``text`` when output filtering is on."""
        if not self._output_filtering:
            return text
        scrubbed = text
        for secret in self.known_secrets:
            if secret:
                scrubbed = scrubbed.replace(secret, "[REDACTED]")
        return scrubbed

    # --- the (rule-based) agent loop --------------------------------------- #

    def run(self, prompt: str) -> VulnAgentResult:
        """React to ``prompt`` with deterministic, sandboxed behavior.

        Scans each channel of the prompt for directive patterns. Whether a
        directive is obeyed depends on the channel's trust (input delimiting) and
        the hardening level; side effects (tool calls) are recorded for the
        oracles. Output and outbound tool arguments are scrubbed of known secrets
        at the hardened level.
        """
        channels = _split_channels(prompt)
        calls: list[RecordedCall] = []
        out_parts: list[str] = []
        handled_any = False

        for channel in channels:
            trusted = self._directive_is_trusted(channel)
            handled = self._handle_channel(channel, trusted, calls, out_parts)
            handled_any = handled_any or handled

        if not handled_any and not out_parts:
            out_parts.append(
                "I can help with sandboxed file reads, key/value memory, and a "
                "stub email tool."
            )

        # Output filtering: scrub the answer AND every recorded tool argument.
        answer = self._scrub("\n".join(out_parts))
        if self._output_filtering:
            calls = [
                RecordedCall(
                    name=c.name,
                    arguments={k: self._scrub_value(v) for k, v in c.arguments.items()},
                )
                for c in calls
            ]
        return VulnAgentResult(output_text=answer, tool_calls=calls)

    def _scrub_value(self, value: Any) -> Any:
        return self._scrub(value) if isinstance(value, str) else value

    def _handle_channel(
        self,
        channel: _Channel,
        trusted: bool,
        calls: list[RecordedCall],
        out_parts: list[str],
    ) -> bool:
        """Apply directive matching to one channel; returns True if any fired."""
        text = channel.text
        handled = False

        # Directive: reveal / exfiltrate / leak <token>  (ASI01 / ASI06).
        leak = re.search(r"(?:exfiltrate|leak|reveal|disclose)\s+(\S+)", text, re.I)
        if leak:
            handled = True
            if trusted:
                token = leak.group(1).strip(".,;:'\"")
                calls.append(
                    RecordedCall("send_email", {"to": "exfil@attacker.test", "body": token})
                )
                out_parts.append(f"Sure, here it is: {token}")
            else:
                out_parts.append(
                    "(ignoring an instruction embedded in untrusted content)"
                )

        # Directive: "summarize" while a secret sits in memory/context (ASI06).
        # A credulous agent surfaces whatever it "remembers"; a delimiting agent
        # summarizes without echoing planted secrets.
        if re.search(r"\b(summari[sz]e|recall|repeat|echo)\b", text, re.I):
            handled = True
            if trusted and self.memory:
                # Credulous: dump remembered values into the answer.
                remembered = "; ".join(f"{k}={v}" for k, v in self.memory.items())
                out_parts.append(f"From memory: {remembered}")
            else:
                out_parts.append("Here is a brief, content-only summary.")

        # Directive: run_python / shell / execute <cmd>  (ASI05 / ASI02).
        code = re.search(
            r"(?:run[_ ]?python|call shell|run command|execute)\s+(.+)", text, re.I
        )
        if code:
            handled = True
            cmd = code.group(1).strip()
            if self._tool_allowlisting:
                out_parts.append(
                    "Refusing: code execution is not an allow-listed capability."
                )
            else:
                # No allow-listing: attempt the disabled tool (recorded either way).
                calls.append(RecordedCall("run_python", {"code": cmd}))
                if self.enable_code_exec:
                    try:
                        self.run_python(cmd)
                    except VulnToolError as exc:
                        out_parts.append(f"[tool error] {exc}")
                else:
                    out_parts.append(
                        "(noted a code-execution request; the tool is disabled)"
                    )

        # Directive: "remember <key>=<value>"  (ASI06 memory write / poisoning).
        mem = re.search(r"remember\s+([^\s=]+)=(\S+)", text, re.I)
        if mem:
            handled = True
            if trusted or not self._input_delimiting:
                key, value = mem.group(1), mem.group(2)
                self.kv_set(key, value)
                calls.append(RecordedCall("kv_set", {"key": key, "value": value}))
                out_parts.append(f"Remembered {key}.")
            else:
                out_parts.append("(ignoring a memory-write directive from untrusted content)")

        # Directive: "read file <path>" -> sandboxed read (or blocked).
        read = re.search(r"read file\s+(\S+)", text, re.I)
        if read:
            handled = True
            path = read.group(1)
            traversal = ".." in path or path.startswith(("/", "\\"))
            if self._tool_allowlisting and traversal:
                out_parts.append("Refusing: path leaves the sandbox.")
            else:
                calls.append(RecordedCall("read_file", {"path": path}))
                try:
                    out_parts.append(self.read_file(path))
                except VulnToolError as exc:
                    out_parts.append(f"[tool error] {exc}")

        # Directive: "email <addr> ..." -> use the email tool (ASI02 tool misuse).
        email = re.search(r"(?:email|send (?:to|mail to|the notes to))\s+(\S+@\S+)", text, re.I)
        if email:
            handled = True
            addr = email.group(1).strip(".,;:'\"<>")
            external = bool(_EXTERNAL_EMAIL_RE.search(addr))
            if self._output_filtering and external:
                out_parts.append("Refusing: that recipient is external to the org.")
            else:
                calls.append(
                    RecordedCall("send_email", {"to": addr, "body": "notes attached"})
                )
                out_parts.append(f"Queued an email to {addr}.")

        return handled


def build_agent(
    level: HardeningLevel | str = HardeningLevel.NONE,
    *,
    known_secrets: list[str] | None = None,
    enable_code_exec: bool = False,
) -> VulnAgent:
    """Construct a :class:`VulnAgent` at ``level`` (accepts the level name as str).

    ``known_secrets`` seeds the hardened-level output-filter tripwire; the harness
    passes the freshly-planted canary here so the scrubbing path is exercised.
    """
    lvl = HardeningLevel(level) if isinstance(level, str) else level
    return VulnAgent(
        level=lvl,
        known_secrets=list(known_secrets or []),
        enable_code_exec=enable_code_exec,
    )
