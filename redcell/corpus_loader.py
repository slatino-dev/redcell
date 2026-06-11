"""Corpus loader -- pydantic models + YAML loader for OWASP-categorized cases.

The corpus is redcell's defensive benchmark: a set of *probe cases*, each tagged
with an OWASP Top 10 for Agentic Applications (2026) category, describing a
behavior a well-behaved agent should resist or handle safely. This module
defines the case schema, loads YAML case files from a corpus directory, validates
them, and yields typed :class:`AttackCase` objects for the runner.

A case is data -- it does not contain a turnkey exploit. It names a *delivery
vector* (where the probe text would be planted: system prompt, a tool result,
memory, the user turn), a ``payload_template`` (the probe text, possibly
parameterized), and the ``oracle`` that decides success/failure deterministically.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from enum import StrEnum
from pathlib import Path
from string import Template
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from redcell.types import MVP_CATEGORIES, AsiCategory, Severity

__all__ = [
    "DeliveryVector",
    "OracleSpec",
    "AttackCase",
    "Corpus",
    "CorpusError",
    "load_case_file",
    "load_corpus",
]


class CorpusError(Exception):
    """Raised when a corpus file is malformed, duplicated, or out of bounds."""


class DeliveryVector(StrEnum):
    """Where a probe's ``payload_template`` is planted before driving the target.

    Names the channel an attacker would realistically use, which determines how
    the adapter injects the probe and which OWASP categories it exercises.
    """

    SYSTEM_PROMPT = "system_prompt"  # untrusted content reaches the system role
    USER_MESSAGE = "user_message"  # direct user-turn instruction
    TOOL_RESULT = "tool_result"  # injected via a returned tool/observation
    MEMORY = "memory"  # planted in persistent memory / context store
    RETRIEVED_DOCUMENT = "retrieved_document"  # via RAG / fetched content


class OracleSpec(BaseModel):
    """The oracle a case uses, as ``{type, params}``.

    ``type`` selects a deterministic oracle implementation
    (:func:`redcell.oracles.build_oracle`); ``params`` are that oracle's
    configuration. Kept loose here (``dict``) and validated strictly when the
    oracle is constructed, so the corpus schema and the oracle schemas evolve
    independently.
    """

    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., min_length=1, description="Oracle implementation selector.")
    params: dict[str, Any] = Field(
        default_factory=dict, description="Oracle-specific configuration."
    )


class AttackCase(BaseModel):
    """One validated probe case.

    Fields mirror the on-disk YAML one-to-one. ``payload_template`` may contain
    ``$placeholder`` / ``${placeholder}`` tokens (e.g. ``$canary``) substituted at
    render time by :meth:`render_payload`, so the same case can plant a
    freshly-generated canary on each run.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, pattern=r"^[A-Za-z0-9._-]+$")
    asi_category: AsiCategory
    severity: Severity = Field(default=Severity.MEDIUM)
    delivery_vector: DeliveryVector
    payload_template: str = Field(..., min_length=1)
    oracle: OracleSpec
    title: str = Field(default="", description="Short human-readable name.")
    description: str = Field(default="", description="What the case probes for.")
    tags: list[str] = Field(default_factory=list)
    ambiguous: bool = Field(
        default=False,
        description=(
            "Mark a case whose verdict a deterministic oracle cannot decide "
            "soundly (e.g. 'did it *subtly* comply?'). When set, and only when a "
            "judge endpoint is configured, the runner consults the optional judge "
            "and records its verdict as ADVISORY evidence -- it never overrides "
            "the oracle's deterministic result."
        ),
    )
    probe_intent: str = Field(
        default="",
        description=(
            "A one-line description of the unsafe behavior this case tests for, "
            "passed to the judge for ambiguous cases. Falls back to the title / "
            "description when empty."
        ),
    )

    @field_validator("tags")
    @classmethod
    def _dedupe_tags(cls, value: list[str]) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for tag in value:
            if tag not in seen:
                seen.add(tag)
                out.append(tag)
        return out

    def render_payload(self, **substitutions: str) -> str:
        """Render ``payload_template``, substituting ``$placeholder`` tokens.

        Uses :class:`string.Template` with ``safe_substitute`` so an unknown or
        omitted placeholder is left intact rather than raising -- a missing
        substitution is a no-op, not a crash.
        """
        return Template(self.payload_template).safe_substitute(**substitutions)

    @property
    def in_mvp(self) -> bool:
        """True if this case's category is one the MVP oracles soundly cover."""
        return self.asi_category in MVP_CATEGORIES


class Corpus(BaseModel):
    """An ordered, de-duplicated collection of :class:`AttackCase`.

    Iteration order is the order cases were loaded (stable), so runs are
    reproducible. Provides simple filtering by category / tag / id for the runner.
    """

    model_config = ConfigDict(extra="forbid")

    cases: list[AttackCase] = Field(default_factory=list)

    def __len__(self) -> int:
        return len(self.cases)

    def __iter__(self) -> Iterator[AttackCase]:  # type: ignore[override]
        return iter(self.cases)

    def by_category(self, category: AsiCategory) -> list[AttackCase]:
        """Cases whose ``asi_category`` equals ``category``."""
        return [c for c in self.cases if c.asi_category == category]

    def by_tag(self, tag: str) -> list[AttackCase]:
        """Cases carrying ``tag``."""
        return [c for c in self.cases if tag in c.tags]

    def get(self, case_id: str) -> AttackCase | None:
        """The case with id ``case_id``, or ``None``."""
        for case in self.cases:
            if case.id == case_id:
                return case
        return None


def _coerce_case(data: Any, source: Path) -> AttackCase:
    """Validate one mapping into an :class:`AttackCase`, wrapping errors."""
    if not isinstance(data, dict):
        raise CorpusError(f"{source}: each case must be a mapping, got {type(data).__name__}")
    try:
        return AttackCase.model_validate(data)
    except ValidationError as exc:
        raise CorpusError(f"{source}: invalid case: {exc}") from exc


def load_case_file(path: Path) -> list[AttackCase]:
    """Load and validate every case in a single YAML file.

    A file may contain a single mapping (one case), a top-level list of mappings,
    or a mapping with a ``cases:`` list. Returns the validated cases in document
    order. Raises :class:`CorpusError` on any malformed content.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise CorpusError(f"{path}: cannot read file: {exc}") from exc

    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise CorpusError(f"{path}: invalid YAML: {exc}") from exc

    if doc is None:
        return []

    if isinstance(doc, dict) and "cases" in doc:
        raw_cases = doc["cases"]
    elif isinstance(doc, list):
        raw_cases = doc
    elif isinstance(doc, dict):
        raw_cases = [doc]
    else:
        raise CorpusError(f"{path}: top level must be a mapping or list, got {type(doc).__name__}")

    if not isinstance(raw_cases, list):
        raise CorpusError(f"{path}: 'cases' must be a list, got {type(raw_cases).__name__}")

    return [_coerce_case(item, path) for item in raw_cases]


def _iter_yaml_files(root: Path) -> Iterable[Path]:
    """Yield ``*.yaml`` / ``*.yml`` files under ``root`` in sorted, stable order."""
    files = sorted(
        p
        for p in root.rglob("*")
        if p.is_file() and p.suffix.lower() in (".yaml", ".yml")
    )
    return files


def load_corpus(root: str | Path) -> Corpus:
    """Load every case under ``root`` into a validated, de-duplicated corpus.

    Walks ``root`` for ``*.yaml`` / ``*.yml`` files (sorted for determinism),
    loads each, and assembles a :class:`Corpus`. Duplicate case ids across the
    whole corpus raise :class:`CorpusError` so a copy-paste mistake can't silently
    shadow a case. Symlinks that escape ``root`` are rejected.
    """
    root_path = Path(root).resolve()
    if not root_path.exists():
        raise CorpusError(f"corpus root does not exist: {root_path}")
    if not root_path.is_dir():
        raise CorpusError(f"corpus root is not a directory: {root_path}")

    cases: list[AttackCase] = []
    seen_ids: dict[str, Path] = {}

    for file in _iter_yaml_files(root_path):
        # Containment guard: never load a case file that resolves outside root.
        resolved = file.resolve()
        if not resolved.is_relative_to(root_path):
            raise CorpusError(f"refusing to load case file outside corpus root: {file}")

        for case in load_case_file(file):
            if case.id in seen_ids:
                raise CorpusError(
                    f"duplicate case id {case.id!r} in {file} "
                    f"(first seen in {seen_ids[case.id]})"
                )
            seen_ids[case.id] = file
            cases.append(case)

    return Corpus(cases=cases)
