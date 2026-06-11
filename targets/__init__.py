"""In-repo, deliberately-simple SANDBOXED demo target.

This package exists ONLY to validate that redcell's harness wires up end-to-end
(corpus -> adapter -> oracle -> report). It is not a realistic agent and it ships
no exploitable capability:

* its tools are mocks -- a sandbox-directory file read, a no-op email stub, and an
  in-memory key/value store;
* any code-execution path is DISABLED by default and raises if reached.

The demo agent is intentionally *naive* about untrusted input so the harness has
something that can "fail" a probe, demonstrating that the oracles fire. Do not
treat it as a reference for how to build a safe agent.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.
"""

from __future__ import annotations

from targets.demo_agent import DemoAgent, DemoToolError

__all__ = ["DemoAgent", "DemoToolError"]
