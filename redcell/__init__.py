"""redcell — a defensive agent-security test harness.

redcell is an evaluation tool for *authorized* red-team testing of agentic
applications you own or are permitted to assess. It is organized around the
OWASP Top 10 for Agentic Applications (2026) and behaves like a robustness
linter for AI agents: it drives a target agent through curated probe cases,
applies oracles to its observable behavior, and reports which risk categories
the agent withstood.

This package is a *test/eval* harness, not an attack kit. It does not ship
exploits; the corpus is a defensive benchmark of behaviors an agent should
resist, added in a later phase.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.

Public surface (to be filled in as the core lands):
    - adapters: bind a target agent to the harness
    - corpus_loader: load OWASP-categorized probe cases
    - oracles: decide pass/fail from observable agent behavior
    - runner: orchestrate the test matrix
    - report: render results
    - judge: optional model-assisted scoring
"""

__version__ = "0.0.0"

__all__ = ["__version__"]
