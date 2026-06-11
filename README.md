# redcell

A defensive agent-security **test harness** for authorized red-teaming of your
own agents, structured around the **OWASP Top 10 for Agentic Applications
(2026)**. Think of it as a robustness linter for AI agents: it drives a target
through curated probe cases and reports which risk categories it withstood.

> **ETHICS / SCOPE:** For authorized testing of systems you own or are permitted to test.

**Status:** scaffolding — core lands next.

This is a security *testing / evaluation* tool, not an attack kit. The corpus is
a defensive benchmark of behaviors an agent should resist; it ships no exploits
and is added in a later phase.

## Layout

- `redcell/` — the package (`adapters`, `corpus_loader`, `oracles`, `runner`, `report`, `judge`)
- `corpus/` — OWASP-categorized probe cases (empty for now)
- `targets/` — in-repo demo target used to validate the harness (empty for now)
- `scripts/` — `run_matrix.py`, `gen_tables.py`, `scrub_check.py`
- `tests/` — test suite

## Limitations

_TBD._
