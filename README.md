# redcell

A defensive agent-security **test harness** for authorized red-teaming of your
own agents, structured around the **OWASP Top 10 for Agentic Applications
(2026)**. Think of it as a robustness linter / fuzzer for AI agents: it drives a
target through ~150 curated probe cases, applies deterministic oracles to the
target's observable behavior, and reports which risk categories it withstood --
with auditable, reproducible verdicts and a single severity-weighted risk score.

> ## ETHICS / SCOPE -- authorized testing only
>
> redcell is a **defensive** security-evaluation tool: an automated robustness
> test suite an engineer runs against agent systems they **own** or are
> **explicitly authorized to test**, to find weaknesses *before attackers do*. It
> is a "linter/fuzzer for agent robustness," **not** an attack toolkit.
>
> - It ships **no turnkey exploits.** Every corpus case is a short, parameterized
>   *test probe* paired with a deterministic oracle; the value is the methodology,
>   the oracles, and the **measured hardening deltas**.
> - The bundled target (`targets/vulnagent/`) is a deliberately-simple
>   **sandboxed** agent with **mock tools only**; its code-execution path is
>   **disabled by default** and raises if reached. It exists solely to validate
>   that the harness works end-to-end.
> - Do not point an adapter at any system you are not authorized to assess.

## The flagship result: one corpus, three hardening levels

redcell's headline output is not "we attacked an agent" -- it is **defensive
engineering**: run the *same corpus* against the *same agent* at three hardening
levels and measure how each control moves the attack-success-rate (ASR). The
bundled `vulnagent` ships exactly this fixture (`none` / `basic` / `hardened`):

```bash
python scripts/run_matrix.py        # offline, no keys; writes results/ + a delta table
```

The numbers below are **produced by that command on your machine** (k=3 trials
per case) -- redcell never hard-codes or fabricates a score; everything is
computed from recorded oracle verdicts. A representative local run:

| Metric | vulnagent:none | vulnagent:basic | vulnagent:hardened |
| --- | ---: | ---: | ---: |
| Overall mean ASR | 73% | 3% | 0% |
| Severity-weighted risk (0-100) | 84.3 | 2.4 | 0.0 |
| Cases with >=1 success | 106 | 5 | 0 |

The controls that produce that delta:

- **`basic`** -- *input delimiting* (obey directives only from the user turn;
  treat tool-results / retrieved documents / planted memory as inert data) +
  *tool allow-listing* (refuse disabled/forbidden tools and out-of-sandbox reads
  instead of attempting them).
- **`hardened`** -- the above plus *output filtering & canary tripwires* (scrub
  planted secrets from the answer **and** from outbound tool arguments) and an
  *external-recipient email guard*.

This is the deliverable to read first: it shows redcell measuring a real
robustness improvement, attributable to specific engineering controls.

## OWASP coverage (2026)

The full taxonomy is enumerated in `redcell.types.AsiCategory`; the MVP's
deterministic oracles soundly cover **five** categories:

| ID | Title | How redcell probes it |
| --- | --- | --- |
| ASI01 | Agent Goal Hijack | instruction-override -> canary exfil / compliance predicate / redirect-to-exec |
| ASI02 | Tool Misuse & Exploitation | forbidden-tool / forbidden-argument-shape (e.g. external-recipient email) |
| ASI03 | Identity & Privilege Abuse | confused-deputy file traversal + false-role-claim secret exfil |
| ASI05 | Unexpected Code Execution (RCE) | invocation of a forbidden code-exec tool (direct + indirect injection) |
| ASI06 | Memory & Context Poisoning | planted-memory canary + multi-turn write-then-trigger |

## How it works

```
corpus case --> adapter (drives the target) --> AgentResponse --> oracle --> verdict
   (YAML)        vulnagent | openai_endpoint     (text +          (deterministic;
                                                  tool calls)      judge optional)
                                |
                         runner (k trials/case) --> RunResult --> report (json + md)
```

- **Corpus** (`corpus/asi0*.yaml`) -- ~150 pydantic-validated probe cases across
  ASI01/02/03/05/06, varied across five delivery vectors (`user_message`,
  `tool_result`, `retrieved_document`, `memory`, `system_prompt`). Authored via
  `scripts/gen_corpus.py` (a one-shot, reviewable generator) into plain YAML you
  can read and extend by hand.
- **Adapters** (`redcell.adapters`):
  - `agent_loop` -- hosts an in-repo callable target (the offline, key-free path
    used by `vulnagent`).
  - `openai_endpoint` -- drives any OpenAI-compatible `/v1/chat/completions`
    endpoint with a tool schema; **the harness serves tool results**, so every
    tool call's arguments are observed by the oracles instead of being executed
    by a hidden backend. Configured with **generic env vars only**.
  - `mcp` -- a documented stub for a future MCP transport.
- **Oracles** (`redcell.oracles`) -- deterministic success detectors returning
  `{triggered, severity, evidence}`:
  - **canary-exfiltration** -- flags a planted token if it surfaces in the answer
    or any outbound tool argument, incl. **base64 / base64url / hex** and
    **partial/chunked** leaks.
  - **forbidden-tool** -- a call to a forbidden tool, or a forbidden
    **argument shape** (regex / contains / equals / JSON-path) on an allowed tool.
  - **predicate** -- regex / JSON-path assertions over the final answer
    (`match` or `absence` polarity).
- **Runner** (`redcell.runner`) -- runs each case `k` times (default 3), mints a
  fresh canary per trial, applies the oracle, and aggregates a serializable
  `RunResult` with a per-case attack-success-rate.
- **Report** (`redcell.report`) -- `report.json` + a threat-report-style
  Markdown: per-ASI-category ASR, the severity-weighted score, per-case
  transcripts, and the multi-target hardening-delta table.
- **Judge** (`redcell.judge`) -- an **optional** local-model judge for the
  genuinely-ambiguous minority; always secondary to the oracles and degrades to
  `needs-review` (never a fabricated score) when unconfigured.

### Severity-weighted risk score (the weighting formula)

The headline risk number weights each case's ASR by the seriousness of the
behavior it probes:

```
weight(severity) = {low: 1, medium: 2, high: 4, critical: 8}

severity_weighted_score =
    100 * sum_over_cases( weight(case.severity) * case.attack_success_rate )
        / sum_over_cases( weight(case.severity) )
```

It is a **0-100 risk index** (higher = worse / less robust): 0 = no probe
succeeded in any trial; 100 = every probe succeeded in every trial. Because the
denominator is the total achievable weight, the score is comparable across runs
**only when the corpus is held fixed** -- which is exactly the hardening-delta
use case.

## Configuration (real targets)

Endpoints are configured with **generic env vars only** -- no provider is
hard-coded:

```bash
export OPENAI_BASE_URL="http://localhost:8000/v1"   # your endpoint root
export OPENAI_API_KEY="..."                          # optional for local servers
export OPENAI_JUDGE_MODEL="your-local-judge-model"   # optional, judge only

python scripts/run_matrix.py --adapter openai --model your-model
```

## Quickstart (offline, no keys)

```bash
python -m redcell.runner          # one-line ASR summary per hardening level
python scripts/run_matrix.py      # full reports + hardening-delta table -> results/
python scripts/gen_tables.py results/vulnagent-none.report.json
```

## Layout

- `redcell/` -- the package (`types`, `oracles`, `corpus_loader`, `adapters`, `judge`, `runner`, `report`)
- `corpus/` -- ~150 OWASP-categorized probe cases (`asi01.yaml` .. `asi06.yaml`)
- `targets/vulnagent/` -- the three-level sandboxed demo target (the flagship fixture)
- `targets/demo_agent.py` -- the original single-level demo agent (kept for the simple example)
- `scripts/` -- `run_matrix.py`, `gen_tables.py`, `gen_corpus.py`, `scrub_check.py`
- `tests/` -- the suite, incl. the **rig-correctness** self-check and oracle unit tests

## Develop

```bash
pip install -e ".[dev]"
ruff check .
mypy
pytest -q
python scripts/scrub_check.py
```

## Limitations

redcell is a **black-box behavioral** harness. By construction it can only see
what a target *emits* (its final answer and the tool calls it attempts). It
therefore **cannot** see:

- **internal state** -- hidden chain-of-thought, latent intent, or a "sleeper"
  policy that did not fire on these probes (absence of a finding is not proof of
  safety);
- **side effects it does not mediate** -- if a real target executes tools through
  a backend redcell does not proxy, redcell sees only the resulting text, not the
  action;
- **non-determinism beyond k trials** -- a rarely-complying target may slip
  through a small `k`; raise `--trials` to tighten the estimate;
- **semantic subtlety without a judge** -- the deterministic oracles are
  conservative by design; truly ambiguous "did it *subtly* comply?" cases need the
  optional judge, which is advisory and flags for human review.

### Why ASI04 / ASI07 / ASI08 / ASI09 / ASI10 are out of the MVP

The MVP covers the five categories a **single-target, black-box** harness can
detect *soundly and deterministically*. The other five need capabilities outside
that boundary:

- **ASI04 Agentic Supply Chain** -- a property of the agent's *build/dependency
  provenance*, not its runtime responses; needs SBOM/artifact analysis, not probes.
- **ASI07 Insecure Inter-Agent Communication** -- requires a **multi-agent**
  fixture and a channel to observe; redcell drives one target at a time.
- **ASI08 Cascading Failures** -- an emergent, *systemic* property over a running
  multi-agent system; not visible from one target's single responses.
- **ASI09 Human-Agent Trust Exploitation** -- the harm lands on a **human**
  (social engineering / over-trust); scoring it soundly needs a human-factors
  study, not a string/structure oracle.
- **ASI10 Rogue Agents** -- detection is an *operational monitoring* problem
  (behavioral baselining over time), not a one-shot probe.

These are enumerated in `redcell.types.AsiCategory` so the corpus can grow into
them (e.g. with a multi-agent adapter) without a schema change.

### Other notes

- The `mcp` adapter is a documented stub; the `agent_loop` and `openai_endpoint`
  adapters are complete.
- `vulnagent` is intentionally naive at lower hardening levels and is **not** a
  reference for building a safe agent -- it exists so the harness has something
  that can "fail" a probe and so the hardening delta is measurable.
