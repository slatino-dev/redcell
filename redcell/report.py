"""Reporting — render run results for humans and machines.

This module turns a ``RunResult`` into readable output: a rich terminal
summary (pass/fail per OWASP category, coverage, notable verdicts) and
machine-readable exports (JSON, and tables consumed by ``scripts/gen_tables``).
Reporting is presentation-only; it draws no conclusions the oracles did not
already record, and it never fabricates scores or benchmark numbers.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.

TODO (later phase):
    - Rich console summary grouped by OWASP Top 10 (2026) category.
    - JSON export of the full run record (stable schema, versioned).
    - Markdown/CSV table emitters for ``scripts/gen_tables``.
    - A non-zero exit policy when any category falls below threshold.
"""

# TODO: implement reporting in a later phase. Scaffold only.
