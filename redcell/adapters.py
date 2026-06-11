"""Target adapters — bind a system-under-test to the harness.

An *adapter* is the thin boundary between redcell and the agent being tested.
It accepts a probe case and returns the agent's observable response (final
text, any tool calls it attempted, and metadata) in a normalized shape the
oracles can inspect. Adapters let the same corpus run against very different
targets: a local function, an HTTP endpoint, or the bundled demo target.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test. Only point an adapter at a target you are allowed to assess.

TODO (later phase):
    - Define the Adapter protocol (sync + async) and a normalized
      ``AgentResponse`` model (final_text, tool_calls, transcript, meta).
    - Provide a CallableAdapter (wrap an in-process function/agent).
    - Provide an HttpAdapter (httpx) for networked targets, with the harness's
      SSRF / allowlist guardrails.
    - Provide a DemoAdapter that drives the in-repo ``targets/`` demo.
"""

# TODO: implement adapters in a later phase. Scaffold only.
