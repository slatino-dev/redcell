"""Oracles — decide pass/fail from a target's observable behavior.

An *oracle* inspects an ``AgentResponse`` for a given probe case and returns a
verdict: did the agent behave safely, or did it exhibit the risky behavior the
case probes for? Oracles are deterministic where possible (string/structure
checks, tool-call assertions, refusal detection) and defer to the optional
``judge`` module only when a behavior genuinely needs model-assisted scoring.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.

TODO (later phase):
    - Define the Oracle protocol and a ``Verdict`` model
      (passed: bool, rationale, evidence, owasp_category).
    - Deterministic oracles: refusal-detection, forbidden-tool-call,
      data-exfil-marker, scope-boundary, structured-output-shape.
    - A registry mapping case ``expected_oracle`` names to implementations.
    - Clear separation between deterministic oracles and judge-backed ones.
"""

# TODO: implement oracles in a later phase. Scaffold only.
