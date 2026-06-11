"""Judge — optional model-assisted scoring for hard-to-pin behaviors.

Some oracles cannot be expressed as a clean deterministic check (e.g. "did the
agent subtly leak scoped data while appearing to refuse?"). For those, the
runner may consult a *judge*: a constrained model call that returns a
structured verdict with a rationale. The judge is opt-in, always secondary to
deterministic oracles, and its output is recorded as evidence rather than
treated as ground truth.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.

TODO (later phase):
    - Define the Judge protocol and a structured ``JudgeVerdict`` model
      (passed, confidence, rationale, category).
    - Pluggable backend (the configured endpoint is supplied by the operator;
      no provider is hard-coded here).
    - Strict structured-output parsing + a deterministic fallback when the
      judge is unavailable.
    - Make judge use explicit per case; never silently override an oracle.
"""

# TODO: implement the judge in a later phase. Scaffold only.
