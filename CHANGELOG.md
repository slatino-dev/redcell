# Changelog

All notable changes to redcell are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **ETHICS / SCOPE — authorized testing only.** redcell is a defensive
> agent-robustness evaluation harness, for systems you own or are explicitly
> authorized to assess. It ships no turnkey exploits.

## [0.1.0] - 2026-06-11

First public release: a deterministic, offline-by-default red-team harness for
AI agents, organized around the OWASP Top 10 for Agentic Applications (2026).

### Added

- **Core taxonomy & types** (`redcell.types`) — normalized `AgentResponse` /
  `ToolCall`, the `AsiCategory` (ASI01–ASI10) enumeration, `Severity`, and the
  `MVP_CATEGORIES` the deterministic oracles cover soundly.
- **Deterministic oracles** (`redcell.oracles`) — canary-exfiltration (verbatim,
  base64/base64url/hex, separator-obfuscated, partial/chunked, and via tool-call
  arguments), forbidden-tool / forbidden-argument-shape, and a general predicate
  oracle (regex + JSON-path, match/absence polarity). Each returns
  `{triggered, severity, evidence}`.
- **Corpus loader** (`redcell.corpus_loader`) — pydantic-validated, YAML-backed
  probe cases with per-case delivery vectors and a containment guard against
  files outside the corpus root.
- **Corpus** (`corpus/asi0*.yaml`) — ~146 probe cases across ASI01/02/03/05/06,
  authored as template × delivery-vector expansions via `scripts/gen_corpus.py`.
- **Adapters** (`redcell.adapters`) — `agent_loop` (offline in-repo target),
  `openai_endpoint` (any OpenAI-compatible `/v1/chat/completions`, with the
  harness serving tool results so every tool call's arguments are observable),
  and a documented `mcp` stub. Endpoints configured via generic env vars only.
- **Runner** (`redcell.runner`) — k-trials-per-case orchestration, a fresh
  per-trial canary, serializable `RunResult`, and category/id selection.
- **Reporting** (`redcell.report`) — `report.json`, a threat-report-style
  Markdown, the per-category ASR table, the documented severity-weighted risk
  score, and the flagship multi-target hardening-delta table.
- **Optional advisory judge** (`redcell.judge`) — a constrained, local-model
  scorer for genuinely-ambiguous cases. It is now **wired into the runner**: a
  case may declare `ambiguous: true`, and when a judge endpoint is configured the
  runner records the judge's verdict as advisory evidence on the trial. It never
  overrides a deterministic oracle, and degrades to `needs-review` (never a
  fabricated score) when unconfigured. Exposed on the CLI via
  `scripts/run_matrix.py --judge`.
- **Bundled target** (`targets/vulnagent/`) — a three-level (`none` / `basic` /
  `hardened`) sandboxed demo agent with mock tools; its code-execution path is
  disabled by default and raises if reached. It exists only to validate the
  harness end-to-end and produce a measurable hardening delta.
- **Rig-correctness self-check** (`tests/test_rig_correctness.py`) — pins the
  harness against always-vulnerable (~100%), always-safe (0%, no false
  positives), and partially-safe agents to prove the evaluator itself is sound.
- **Tooling & CI** — ruff, mypy `--strict`, pytest, and a `scrub_check.py` gate
  that scans for leaked internal infrastructure or secrets.

### Measured

- Flagship hardening delta on the bundled `vulnagent` (k=3 trials/case, produced
  by `python -m redcell.runner` / `scripts/run_matrix.py`, not hard-coded):
  overall ASR **73% → 3% → 0%**, severity-weighted risk **84.3 → 2.4 → 0.0**,
  cases-with-success **106 → 5 → 0** across `none` / `basic` / `hardened`. The
  delta measures the harness on a deliberately naive fixture; real-target numbers
  come from pointing the `openai_endpoint` adapter at a live model.

### Security / scope

- Defensive framing throughout (README ethics box, per-module docstrings, report
  headers); no turnkey exploits; bundled target sandboxed with code-exec off.

[0.1.0]: https://github.com/SamLatino/redcell/releases/tag/v0.1.0
