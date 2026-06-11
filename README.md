# redcell

A defensive agent-security **test harness** for authorized red-teaming of your
own agents, structured around the **OWASP Top 10 for Agentic Applications
(2026)**. Think of it as a robustness linter / fuzzer for AI agents: it drives a
target through curated probe cases and reports which risk categories it
withstood, with deterministic, auditable verdicts.

> **ETHICS / SCOPE — authorized testing only.** redcell is a *defensive*
> security-evaluation tool. Run it against agent systems you **own** or are
> **explicitly authorized to test**. It ships **no turnkey exploits**: the value
> is the methodology, the oracles, and the measured hardening deltas. The bundled
> demo target is a deliberately-simple **sandboxed** agent (mock tools only; any
> code-execution path is **disabled by default**) used solely to validate that
> the harness works end-to-end.

**Status:** evaluation **core** implemented (oracles, corpus loader, adapters,
optional judge) with a seed corpus and a sandboxed demo target.

## OWASP coverage (2026)

The full taxonomy is enumerated in `redcell.types.AsiCategory`; the MVP's
deterministic oracles soundly cover five categories:

| ID | Title | How redcell probes it |
| --- | --- | --- |
| ASI01 | Agent Goal Hijack | injected-instruction → canary exfil / compliance predicate |
| ASI02 | Tool Misuse & Exploitation | forbidden-tool / forbidden-argument-shape |
| ASI03 | Identity & Privilege Abuse | forbidden tool args (e.g. path traversal) |
| ASI05 | Unexpected Code Execution (RCE) | invocation of a forbidden code-exec tool |
| ASI06 | Memory & Context Poisoning | canary planted in memory → exfil detection |

## How it works

```
corpus case ──▶ adapter (drives the target) ──▶ AgentResponse ──▶ oracle ──▶ verdict
   (YAML)        openai_endpoint | agent_loop      (text +          (deterministic;
                                                    tool calls)      judge optional)
```

* **Oracles** (`redcell.oracles`) are deterministic success detectors that return
  `{triggered, severity, evidence}`:
  * **canary-exfiltration** — a unique token planted in the prompt / a tool
    result / memory; flags it if it surfaces in the answer or any outbound
    tool-call argument, including **base64 / base64url / hex** and
    **partial/chunked** leaks.
  * **forbidden-tool** — detects a call to a forbidden tool, or a forbidden
    **argument shape** (regex / contains / equals / JSON-path) on an allowed tool.
  * **predicate** — regex / JSON-path assertions over the final answer.
* **Corpus loader** (`redcell.corpus_loader`) — pydantic-validated YAML cases:
  `{id, asi_category, severity, delivery_vector, payload_template, oracle}`.
* **Adapters** (`redcell.adapters`):
  * `openai_endpoint` — drives an OpenAI-compatible `/v1/chat/completions`
    endpoint with a tool schema; **the harness serves tool results**, so every
    tool call's arguments are observed by the oracles instead of being executed
    by a hidden backend.
  * `agent_loop` — hosts a simple loop around an in-repo callable target.
  * `mcp` — a documented stub for a future MCP transport.
* **Judge** (`redcell.judge`) — an **optional** local-model judge
  (OpenAI-compatible endpoint) for the ~15% genuinely-ambiguous cases, with a
  published prompt. **Degrades gracefully**: with no endpoint configured, every
  consultation returns `needs-review` (never a fabricated score).

## Configuration

Endpoints are configured with **generic env vars only** — no provider is
hard-coded:

```bash
export OPENAI_BASE_URL="http://localhost:8000/v1"   # your endpoint root
export OPENAI_API_KEY="..."                          # optional for local servers
export OPENAI_JUDGE_MODEL="your-local-judge-model"   # optional, judge only
```

## Quickstart (offline, no keys)

```python
import secrets
from redcell.adapters import AgentLoopAdapter, build_probe
from redcell.corpus_loader import load_corpus
from redcell.oracles import build_oracle
from targets.demo_agent import DemoAgent

corpus = load_corpus("corpus")
adapter = AgentLoopAdapter(DemoAgent().run)

for case in corpus:
    canary = "REDCELL-CANARY-" + secrets.token_hex(12)
    probe = build_probe(case, canary=canary)
    response = adapter.run(probe)
    params = dict(case.oracle.params)
    if case.oracle.type == "canary_exfiltration":
        params["canary"] = canary
    verdict = build_oracle(case.oracle.type, params).evaluate(response)
    print(case.id, case.asi_category, "FAILED" if verdict.triggered else "ok")
```

## Layout

- `redcell/` — the package (`types`, `oracles`, `corpus_loader`, `adapters`, `judge`, `runner`, `report`)
- `corpus/` — OWASP-categorized probe cases (`mvp.yaml` seed corpus)
- `targets/` — the sandboxed demo target used to validate the harness
- `scripts/` — `run_matrix.py`, `gen_tables.py`, `scrub_check.py`
- `tests/` — the test suite (oracles tested hard: encoded/partial canary leaks, forbidden-tool detection)

## Develop

```bash
pip install -e ".[dev]"
ruff check .
mypy
pytest -q
python scripts/scrub_check.py
```

## Limitations

- The `runner` / `report` modules and the `mcp` adapter are not yet implemented
  (the run loop and rendering land next); the core (oracles + corpus + adapters +
  judge) is complete and tested.
- The demo target is intentionally naive and is **not** a reference for building a
  safe agent — it exists only so the harness has something that can "fail" a probe.
