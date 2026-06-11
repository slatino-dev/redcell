# Targets

An **in-repo, deliberately-simple SANDBOXED demo target** — a small,
purpose-built agent used only to validate that the harness wiring works
end-to-end (corpus → adapter → oracle → report). It exists so contributors can
run redcell with no API keys and no network.

`demo_agent.py` defines `DemoAgent`, a deterministic, rule-driven stand-in (it
calls **no** model). Its tools are mocks:

- `read_file(path)` — reads a file, but **only inside** the `sandbox/` directory
  (path traversal is blocked).
- `send_email(to, body)` — a **no-op stub**; records the attempt, sends nothing.
- `memory_get` / `memory_set` — an in-process dict.
- `shell(cmd)` — a code-execution tool that is **DISABLED by design** and always
  raises. The harness still records the *attempt* (so the forbidden-tool oracle
  can flag it) without ever executing anything.

The agent is intentionally **naive** about untrusted input so the harness has
something that can "fail" a probe, demonstrating that the oracles fire. It is
**not** a reference for how to build a safe agent.

It is driven via the `AgentLoopAdapter` in `redcell.adapters`. This package is
**not** part of the installed `redcell` wheel; it ships with the source tree only.

> ETHICS / SCOPE: For authorized testing of systems you own or are permitted to test.
