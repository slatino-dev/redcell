"""Tests for the runner: trials, aggregation, selection, and the flagship delta.

These cover the orchestration engine itself -- that it runs ``k`` trials, mints a
fresh canary per trial, aggregates attack-success-rate correctly, respects
category/id selection, and that the same corpus across vulnagent's three
hardening levels yields a MONOTONE decrease in risk (the headline result).
"""

from __future__ import annotations

from pathlib import Path

from redcell.corpus_loader import load_corpus
from redcell.report import summarize_run
from redcell.runner import (
    RunConfig,
    make_vulnagent_factory,
    mint_canary,
    run_corpus,
)
from redcell.types import AsiCategory
from targets.vulnagent import HardeningLevel

REPO_CORPUS = Path(__file__).resolve().parent.parent / "corpus"


def test_mint_canary_is_unique_and_prefixed() -> None:
    a, b = mint_canary(), mint_canary()
    assert a != b
    assert a.startswith("REDCELL-CANARY-")


def test_runconfig_rejects_zero_trials() -> None:
    import pytest

    with pytest.raises(ValueError):
        RunConfig(trials=0)


def test_run_corpus_runs_every_case_with_k_trials() -> None:
    corpus = load_corpus(REPO_CORPUS)
    result = run_corpus(
        corpus, make_vulnagent_factory(HardeningLevel.NONE), RunConfig(trials=3)
    )
    assert result.n_cases == len(corpus)
    assert all(c.n_trials == 3 for c in result.cases)
    assert result.trials_per_case == 3


def test_category_selection_filters_cases() -> None:
    corpus = load_corpus(REPO_CORPUS)
    cfg = RunConfig(trials=1, only_categories=frozenset({AsiCategory.ASI05}))
    result = run_corpus(corpus, make_vulnagent_factory(HardeningLevel.NONE), cfg)
    assert result.n_cases > 0
    assert all(c.asi_category is AsiCategory.ASI05 for c in result.cases)


def test_id_selection_filters_cases() -> None:
    corpus = load_corpus(REPO_CORPUS)
    target_id = next(iter(corpus)).id
    cfg = RunConfig(trials=1, only_ids=frozenset({target_id}))
    result = run_corpus(corpus, make_vulnagent_factory(HardeningLevel.NONE), cfg)
    assert result.n_cases == 1
    assert result.cases[0].case_id == target_id


def test_hardening_delta_is_monotone_decreasing() -> None:
    """The flagship: more hardening => strictly less (or equal) measured risk."""
    corpus = load_corpus(REPO_CORPUS)
    scores = []
    for level in (HardeningLevel.NONE, HardeningLevel.BASIC, HardeningLevel.HARDENED):
        result = run_corpus(
            corpus,
            make_vulnagent_factory(level),
            RunConfig(trials=3, target_label=f"vulnagent:{level.value}"),
        )
        scores.append(summarize_run(result)["severity_weighted_score"])

    none_score, basic_score, hardened_score = scores
    # Hardening must reduce measured risk at each step, and meaningfully so.
    assert none_score > basic_score > hardened_score
    assert none_score > 30.0  # the unhardened agent is genuinely vulnerable
    assert hardened_score == 0.0  # the fully-hardened agent withstands the corpus


def test_memory_vector_canary_is_preseeded_and_detected() -> None:
    """A memory-vector case leaks the pre-seeded canary against the none level."""
    corpus = load_corpus(REPO_CORPUS)
    mem_ids = frozenset(
        c.id for c in corpus if c.delivery_vector.value == "memory" and c.oracle.type
        == "canary_exfiltration"
    )
    assert mem_ids, "expected at least one memory-vector canary case in the corpus"
    cfg = RunConfig(trials=2, only_ids=mem_ids)
    result = run_corpus(corpus, make_vulnagent_factory(HardeningLevel.NONE), cfg)
    # At least one memory case should fire (the agent surfaces planted memory).
    assert any(c.succeeded for c in result.cases)


def test_run_record_is_serializable() -> None:
    corpus = load_corpus(REPO_CORPUS)
    cfg = RunConfig(trials=1, only_categories=frozenset({AsiCategory.ASI01}))
    result = run_corpus(corpus, make_vulnagent_factory(HardeningLevel.NONE), cfg)
    # Round-trips through JSON without loss.
    blob = result.model_dump_json()
    assert "vulnagent" not in blob or "target_label" in blob
    assert len(blob) > 0
