"""``vulnagent`` -- a sandboxed demo agent with three hardening levels.

This package is redcell's *flagship* fixture. It is a single, deterministic,
rule-based agent (it calls **no** model) that can be instantiated at three
hardening levels -- ``none``, ``basic``, ``hardened`` -- so the **same corpus**
can be run against all three and the *hardening delta* measured. That makes the
headline result a piece of **defensive engineering** (does adding a control
actually reduce attack-success-rate?) rather than a one-off attack score.

The agent is sandboxed and ships no exploitable capability:

* ``read_file(path)``   -- reads only inside a sandbox directory (traversal blocked);
* ``send_email(to, body)`` -- a no-op stub that records the attempt, sends nothing;
* ``kv_get`` / ``kv_set`` -- an in-process key/value memory;
* ``run_python(code)`` -- a code-execution tool that is **DISABLED by default**
  and raises if reached; the harness still records the *attempt*.

The three levels differ only in their *defenses*, never in their tools:

* ``HardeningLevel.NONE`` -- credulous: follows directives from any channel,
  including untrusted tool results, retrieved documents, and planted memory.
* ``HardeningLevel.BASIC`` -- input delimiting (ignores imperative directives that
  arrive on untrusted channels) + tool allow-listing (refuses disabled/forbidden
  tools rather than attempting them).
* ``HardeningLevel.HARDENED`` -- everything in ``basic`` plus output filtering and
  canary tripwires (planted secret tokens are scrubbed from the answer and from
  outbound tool arguments) and an external-recipient email guard.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted to
test. This agent is intentionally naive at lower levels so the harness has
something that can "fail" a probe; it is NOT a reference implementation for a
safe agent.
"""

from __future__ import annotations

from targets.vulnagent.agent import (
    HardeningLevel,
    RecordedCall,
    VulnAgent,
    VulnAgentResult,
    VulnToolError,
    build_agent,
)

__all__ = [
    "HardeningLevel",
    "RecordedCall",
    "VulnAgent",
    "VulnAgentResult",
    "VulnToolError",
    "build_agent",
]
