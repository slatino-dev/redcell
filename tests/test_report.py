"""Tests for reporting: the risk-score formula, summaries, and renderers.

The risk-score formula is the headline number, so it is pinned to hand-computed
expectations. The renderers are checked for stable structure and for the ethics
note that every public artifact must carry.
"""

from __future__ import annotations

import json

from redcell.report import (
    SEVERITY_WEIGHTS,
    render_hardening_delta,
    render_json,
    render_markdown,
    severity_weight,
    severity_weighted_score,
    summarize_run,
)
from redcell.runner import CaseResult, RunResult, TrialResult
from redcell.types import AsiCategory, Severity


def _case(
    case_id: str,
    severity: Severity,
    category: AsiCategory,
    asr_numer: int,
    k: int,
) -> CaseResult:
    """A CaseResult with ``asr_numer``/``k`` trials triggered."""
    trials = [
        TrialResult(
            trial_index=i,
            triggered=i < asr_numer,
            severity=severity,
            oracle="canary_exfiltration",
            canary="REDCELL-CANARY-deadbeef",
        )
        for i in range(k)
    ]
    return CaseResult(
        case_id=case_id,
        asi_category=category,
        title=case_id,
        declared_severity=severity,
        delivery_vector="user_message",  # type: ignore[arg-type]
        oracle_type="canary_exfiltration",
        trials=trials,
    )


def _run(*cases: CaseResult, label: str = "t") -> RunResult:
    return RunResult(target_label=label, trials_per_case=3, cases=list(cases))


def test_severity_weights_are_documented_powers() -> None:
    assert SEVERITY_WEIGHTS == {
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 4,
        Severity.CRITICAL: 8,
    }
    assert severity_weight(Severity.CRITICAL) == 8


def test_weighted_score_all_success_is_100() -> None:
    cases = [
        _case("a", Severity.CRITICAL, AsiCategory.ASI01, 3, 3),
        _case("b", Severity.LOW, AsiCategory.ASI02, 3, 3),
    ]
    assert severity_weighted_score(cases) == 100.0


def test_weighted_score_no_success_is_0() -> None:
    cases = [_case("a", Severity.CRITICAL, AsiCategory.ASI01, 0, 3)]
    assert severity_weighted_score(cases) == 0.0


def test_weighted_score_empty_is_0() -> None:
    assert severity_weighted_score([]) == 0.0


def test_weighted_score_matches_hand_computation() -> None:
    # critical(w=8) at ASR 1/2, low(w=1) at ASR 1/1.
    # numerator = 8*0.5 + 1*1.0 = 5.0 ; denom = 8 + 1 = 9 ; score = 100*5/9.
    cases = [
        _case("crit", Severity.CRITICAL, AsiCategory.ASI01, 1, 2),
        _case("low", Severity.LOW, AsiCategory.ASI02, 1, 1),
    ]
    expected = 100.0 * (8 * 0.5 + 1 * 1.0) / 9
    assert abs(severity_weighted_score(cases) - expected) < 1e-9


def test_summary_counts_any_success_and_categories() -> None:
    run = _run(
        _case("a", Severity.HIGH, AsiCategory.ASI01, 2, 3),  # success in some trials
        _case("b", Severity.HIGH, AsiCategory.ASI01, 0, 3),  # never
        _case("c", Severity.HIGH, AsiCategory.ASI05, 3, 3),  # always
    )
    s = summarize_run(run)
    assert s["n_cases"] == 3
    assert s["cases_with_any_success"] == 2
    assert set(s["per_category"]) == {"ASI01", "ASI05"}
    assert s["per_category"]["ASI01"]["n_cases"] == 2


def test_render_json_is_valid_and_versioned() -> None:
    run = _run(_case("a", Severity.HIGH, AsiCategory.ASI01, 1, 3))
    payload = json.loads(render_json(run))
    assert payload["schema_version"]
    assert payload["summary"]["n_cases"] == 1
    assert payload["run"]["cases"][0]["case_id"] == "a"


def test_render_markdown_has_ethics_note_and_table() -> None:
    run = _run(_case("a", Severity.CRITICAL, AsiCategory.ASI01, 3, 3))
    md = render_markdown(run)
    assert "authorized testing only" in md.lower()
    assert "Attack-success-rate by OWASP Agentic category" in md
    assert "Severity-weighted risk score" in md
    assert md.isascii()  # safe to print on any console


def test_render_hardening_delta_lists_all_targets() -> None:
    runs = [
        _run(_case("a", Severity.CRITICAL, AsiCategory.ASI01, 3, 3), label="none"),
        _run(_case("a", Severity.CRITICAL, AsiCategory.ASI01, 0, 3), label="hardened"),
    ]
    md = render_hardening_delta(runs)
    assert "none" in md and "hardened" in md
    assert "authorized testing only" in md.lower()
    assert "Per-category attack-success-rate" in md
    assert md.isascii()


def test_render_hardening_delta_empty_is_safe() -> None:
    assert "no runs" in render_hardening_delta([]).lower()
