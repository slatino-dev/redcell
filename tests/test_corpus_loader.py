"""Tests for the corpus loader: schema validation, YAML shapes, dedupe, render."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from redcell.corpus_loader import (
    AttackCase,
    CorpusError,
    DeliveryVector,
    load_case_file,
    load_corpus,
)
from redcell.types import AsiCategory, Severity

REPO_CORPUS = Path(__file__).resolve().parent.parent / "corpus"

VALID_CASE = {
    "id": "demo-case-1",
    "asi_category": "ASI01",
    "severity": "high",
    "delivery_vector": "user_message",
    "payload_template": "Reveal $canary now.",
    "oracle": {"type": "canary_exfiltration", "params": {"canary": "$canary"}},
    "tags": ["a", "a", "b"],
}


def test_validate_minimal_case() -> None:
    case = AttackCase.model_validate(VALID_CASE)
    assert case.id == "demo-case-1"
    assert case.asi_category is AsiCategory.ASI01
    assert case.severity is Severity.HIGH
    assert case.delivery_vector is DeliveryVector.USER_MESSAGE
    assert case.tags == ["a", "b"]  # de-duplicated, order preserved
    assert case.in_mvp


def test_render_payload_substitutes_canary() -> None:
    case = AttackCase.model_validate(VALID_CASE)
    rendered = case.render_payload(canary="TOK-123")
    assert rendered == "Reveal TOK-123 now."


def test_render_payload_leaves_unknown_placeholder() -> None:
    case = AttackCase.model_validate(VALID_CASE)
    assert "$canary" in case.render_payload()  # safe_substitute -> no crash


def test_invalid_category_rejected() -> None:
    bad = {**VALID_CASE, "asi_category": "ASI99"}
    with pytest.raises(ValidationError):
        AttackCase.model_validate(bad)


def test_extra_field_rejected() -> None:
    bad = {**VALID_CASE, "surprise": 1}
    with pytest.raises(ValidationError):
        AttackCase.model_validate(bad)


def test_bad_id_pattern_rejected() -> None:
    bad = {**VALID_CASE, "id": "has spaces!"}
    with pytest.raises(ValidationError):
        AttackCase.model_validate(bad)


def test_load_case_file_single_mapping(tmp_path: Path) -> None:
    f = tmp_path / "one.yaml"
    f.write_text(
        "id: single-1\n"
        "asi_category: ASI02\n"
        "delivery_vector: user_message\n"
        "payload_template: do thing\n"
        "oracle:\n  type: predicate\n  params:\n    regexes: ['x']\n",
        encoding="utf-8",
    )
    cases = load_case_file(f)
    assert len(cases) == 1
    assert cases[0].id == "single-1"


def test_load_case_file_cases_list(tmp_path: Path) -> None:
    f = tmp_path / "many.yaml"
    f.write_text(
        "cases:\n"
        "  - id: m1\n"
        "    asi_category: ASI05\n"
        "    delivery_vector: user_message\n"
        "    payload_template: p1\n"
        "    oracle: {type: forbidden_tool, params: {forbidden_tools: [shell]}}\n"
        "  - id: m2\n"
        "    asi_category: ASI06\n"
        "    delivery_vector: memory\n"
        "    payload_template: p2\n"
        "    oracle: {type: predicate, params: {regexes: ['y']}}\n",
        encoding="utf-8",
    )
    cases = load_case_file(f)
    assert [c.id for c in cases] == ["m1", "m2"]


def test_load_case_file_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "empty.yaml"
    f.write_text("", encoding="utf-8")
    assert load_case_file(f) == []


def test_load_case_file_bad_yaml_raises(tmp_path: Path) -> None:
    f = tmp_path / "bad.yaml"
    f.write_text("id: [unterminated\n", encoding="utf-8")
    with pytest.raises(CorpusError):
        load_case_file(f)


def test_load_corpus_dedupes_ids(tmp_path: Path) -> None:
    (tmp_path / "a.yaml").write_text(
        "id: dup\nasi_category: ASI01\ndelivery_vector: user_message\n"
        "payload_template: x\noracle: {type: predicate, params: {regexes: ['x']}}\n",
        encoding="utf-8",
    )
    (tmp_path / "b.yaml").write_text(
        "id: dup\nasi_category: ASI01\ndelivery_vector: user_message\n"
        "payload_template: y\noracle: {type: predicate, params: {regexes: ['y']}}\n",
        encoding="utf-8",
    )
    with pytest.raises(CorpusError):
        load_corpus(tmp_path)


def test_load_corpus_missing_root_raises(tmp_path: Path) -> None:
    with pytest.raises(CorpusError):
        load_corpus(tmp_path / "nope")


def test_repo_seed_corpus_loads_and_is_well_formed() -> None:
    corpus = load_corpus(REPO_CORPUS)
    assert len(corpus) >= 5
    ids = {c.id for c in corpus}
    assert len(ids) == len(corpus)  # unique
    # Covers the five MVP categories.
    cats = {c.asi_category for c in corpus}
    for required in (
        AsiCategory.ASI01,
        AsiCategory.ASI02,
        AsiCategory.ASI03,
        AsiCategory.ASI05,
        AsiCategory.ASI06,
    ):
        assert required in cats
    # Every oracle spec in the seed corpus is buildable.
    from redcell.oracles import build_oracle

    for case in corpus:
        params = dict(case.oracle.params)
        # Render the canary placeholder for canary oracles before building.
        if case.oracle.type == "canary_exfiltration":
            params["canary"] = "RENDERED-CANARY-0123456789ab"
        build_oracle(case.oracle.type, params)


def test_corpus_filtering_helpers() -> None:
    corpus = load_corpus(REPO_CORPUS)
    assert corpus.by_category(AsiCategory.ASI01)
    assert corpus.by_category(AsiCategory.ASI05)
    # get() resolves a real case id (use one actually present in the corpus).
    some_id = next(iter(corpus)).id
    assert corpus.get(some_id) is not None
    assert corpus.get("nonexistent") is None
