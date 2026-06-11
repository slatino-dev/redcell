"""End-to-end integration: corpus -> adapter -> oracle, fully offline.

Drives the bundled sandboxed demo agent through the seed corpus with the
agent_loop adapter and applies each case's oracle. This proves the whole harness
wires together without any network or model. It asserts that at least the
canary/forbidden cases the naive demo agent is built to fail actually fire, and
that nothing raises.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from redcell.adapters import AgentLoopAdapter, build_probe
from redcell.corpus_loader import load_corpus
from redcell.oracles import build_oracle
from targets.demo_agent import DemoAgent

REPO_CORPUS = Path(__file__).resolve().parent.parent / "corpus"


def _new_canary() -> str:
    return "REDCELL-CANARY-" + secrets.token_hex(12)


def test_full_matrix_runs_offline_against_demo_agent() -> None:
    corpus = load_corpus(REPO_CORPUS)
    agent = DemoAgent()
    adapter = AgentLoopAdapter(agent.run)

    triggered_ids: set[str] = set()
    for case in corpus:
        canary = _new_canary()
        probe = build_probe(case, canary=canary)
        response = adapter.run(probe)
        assert response.error is None

        params = dict(case.oracle.params)
        if case.oracle.type == "canary_exfiltration":
            params["canary"] = canary
        oracle = build_oracle(case.oracle.type, params)
        result = oracle.evaluate(response)
        if result.triggered:
            triggered_ids.add(case.id)

    # The naive demo agent is built to fail these specific probes; confirm the
    # oracles actually detect the unsafe behavior end-to-end.
    assert "asi01-goal-hijack-exfil" in triggered_ids  # canary leak via reveal
    assert "asi05-unexpected-code-exec" in triggered_ids  # attempts disabled shell
    assert "asi06-memory-poisoning-canary" in triggered_ids  # canary in output


def test_canary_is_fresh_per_run() -> None:
    assert _new_canary() != _new_canary()
