"""End-to-end integration: corpus -> runner -> oracle -> report, fully offline.

Drives the full corpus through the runner against the in-repo vulnagent (no
network, no model, no keys) and checks the whole pipeline wires together and
produces a coherent report. The harness *self-check* (does it score known
behaviors correctly?) lives in ``test_rig_correctness.py``; this test focuses on
the wiring and the offline run loop.
"""

from __future__ import annotations

from pathlib import Path

from redcell.corpus_loader import load_corpus
from redcell.report import render_json, render_markdown, summarize_run
from redcell.runner import RunConfig, make_vulnagent_factory, run_corpus
from targets.vulnagent import HardeningLevel

REPO_CORPUS = Path(__file__).resolve().parent.parent / "corpus"


def test_full_pipeline_runs_offline_against_vulnagent() -> None:
    corpus = load_corpus(REPO_CORPUS)
    assert len(corpus) >= 120  # the real, sizeable corpus is present

    result = run_corpus(
        corpus,
        make_vulnagent_factory(HardeningLevel.NONE),
        RunConfig(trials=3, target_label="vulnagent:none"),
    )
    # No case errored (every probe drove the target without a transport failure).
    assert not any(c.errored for c in result.cases)

    summary = summarize_run(result)
    # The unhardened agent is genuinely vulnerable: many cases succeed.
    assert summary["cases_with_any_success"] > 0
    assert 0.0 < summary["overall_asr"] <= 1.0

    # The renderers produce coherent, ASCII-safe artifacts.
    md = render_markdown(result)
    assert "redcell report" in md.lower()
    import json

    payload = json.loads(render_json(result))
    assert payload["summary"]["n_cases"] == len(corpus)


def test_every_category_has_cases_in_the_corpus() -> None:
    corpus = load_corpus(REPO_CORPUS)
    present = {c.asi_category.value for c in corpus}
    for cat in ("ASI01", "ASI02", "ASI03", "ASI05", "ASI06"):
        assert cat in present, f"corpus is missing category {cat}"
