"""Corpus loader — read and validate OWASP-categorized probe cases.

The corpus is redcell's defensive benchmark: a set of probe cases, each tagged
with an OWASP Top 10 for Agentic Applications (2026) category, describing a
behavior a well-behaved agent should resist or handle safely. This module reads
those case files from ``corpus/``, validates them against a schema, and yields
typed case objects for the runner. It does not contain payloads itself — cases
are data, added in a later phase.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.

TODO (later phase):
    - Define the ProbeCase pydantic model (id, owasp_category, intent,
      inputs, expected_oracle, tags, provenance).
    - Load YAML/JSON case files from a corpus directory; validate + dedupe.
    - Expose iteration + filtering by OWASP category / tag / id.
    - Enforce that loaded content stays inside the declared corpus root.
"""

# TODO: implement corpus loading in a later phase. Scaffold only.
