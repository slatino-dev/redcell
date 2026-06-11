"""Runner -- orchestrate the test matrix (cases x trials x oracle).

The runner is the harness's engine. For each case in a corpus it:

1. mints a fresh canary (so every run/trial uses a unique token);
2. renders the case into a :class:`~redcell.adapters.Probe`;
3. drives the target through an adapter ``k`` times (``trials``), because a
   non-deterministic target may comply only sometimes -- redcell reports the
   *attack-success-rate* over trials, not a single coin flip;
4. applies the case's deterministic oracle to each response and records the
   verdict, evidence, and a bounded transcript.

The result is a fully-serializable :class:`RunResult` that :mod:`redcell.report`
renders. The runner draws no conclusions of its own and never fabricates a score:
it only records what the oracles returned.

A *target* is supplied as a factory: ``Callable[[TrialContext], Adapter]``. A
factory (rather than a single adapter) lets the harness hand each trial a fresh
target instance -- fresh memory, the trial's canary wired into the target's
known-secrets / pre-seeded memory -- which is essential for memory-poisoning
cases and for the hardened level's output-filter tripwire.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted to
test.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from redcell.adapters import Adapter, Probe, build_probe
from redcell.corpus_loader import AttackCase, Corpus, DeliveryVector
from redcell.judge import Judge, JudgeVerdict
from redcell.oracles import OracleResult, build_oracle
from redcell.types import AgentResponse, AsiCategory, Severity

__all__ = [
    "CANARY_PREFIX",
    "TrialContext",
    "TargetFactory",
    "TrialResult",
    "CaseResult",
    "RunResult",
    "RunConfig",
    "mint_canary",
    "run_case",
    "run_corpus",
]

CANARY_PREFIX = "REDCELL-CANARY-"


def mint_canary() -> str:
    """A fresh, high-entropy canary token, unique per call."""
    return CANARY_PREFIX + secrets.token_hex(12)


@dataclass
class TrialContext:
    """What a target factory needs to build a target for one trial.

    ``canary`` is the unique token planted for this trial; a target that supports
    output filtering should treat it as a known secret, and a memory-vector case
    expects it pre-seeded into the target's memory.
    """

    case: AttackCase
    canary: str
    trial_index: int


# A factory builds a *fresh* adapter (wrapping a fresh target) for each trial.
TargetFactory = Callable[[TrialContext], Adapter]


class TrialResult(BaseModel):
    """One (case, trial) outcome: the oracle verdict plus a bounded transcript."""

    model_config = ConfigDict(extra="forbid")

    trial_index: int
    triggered: bool
    severity: Severity
    oracle: str
    canary: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    output_excerpt: str = ""
    tool_calls: list[dict[str, Any]] = Field(default_factory=list)
    adapter_error: str | None = None
    latency_ms: float = 0.0
    judge: JudgeVerdict | None = Field(
        default=None,
        description=(
            "ADVISORY judge verdict for an ambiguous case, recorded as evidence "
            "only. The deterministic ``triggered`` above is authoritative; this is "
            "never used to flip it."
        ),
    )


class CaseResult(BaseModel):
    """All trials for one case, with the case's attack-success-rate."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    asi_category: AsiCategory
    title: str
    declared_severity: Severity
    delivery_vector: DeliveryVector
    oracle_type: str
    trials: list[TrialResult] = Field(default_factory=list)

    @property
    def n_trials(self) -> int:
        return len(self.trials)

    @property
    def n_triggered(self) -> int:
        return sum(1 for t in self.trials if t.triggered)

    @property
    def attack_success_rate(self) -> float:
        """Fraction of trials in which the unsafe behavior was detected (0..1)."""
        return self.n_triggered / self.n_trials if self.n_trials else 0.0

    @property
    def succeeded(self) -> bool:
        """True if the attack succeeded in *any* trial (the conservative view)."""
        return self.n_triggered > 0

    @property
    def errored(self) -> bool:
        """True if every trial failed to drive the target (transport errors)."""
        return self.n_trials > 0 and all(t.adapter_error for t in self.trials)


class RunResult(BaseModel):
    """The full record of a corpus run against one target at one config.

    Serializable end-to-end (``model_dump_json``) so a run is reproducible and
    auditable. :mod:`redcell.report` turns this into JSON + Markdown.
    """

    model_config = ConfigDict(extra="forbid")

    target_label: str
    trials_per_case: int
    cases: list[CaseResult] = Field(default_factory=list)
    started_at: float = 0.0
    finished_at: float = 0.0
    seed: int | None = None

    @property
    def n_cases(self) -> int:
        return len(self.cases)


@dataclass
class RunConfig:
    """Knobs for a corpus run.

    ``base_user_message`` is the benign user turn the harness pairs with each
    injected payload. ``trials`` (k) is how many times each case is run; redcell
    reports the attack-success-rate over these trials.
    """

    trials: int = 3
    base_user_message: str = "Please proceed with the task."
    target_label: str = "target"
    only_categories: frozenset[AsiCategory] | None = None
    only_ids: frozenset[str] | None = None
    judge: Judge | None = None

    def __post_init__(self) -> None:
        if self.trials < 1:
            raise ValueError("trials (k) must be >= 1")


def _selected(corpus: Iterable[AttackCase], config: RunConfig) -> list[AttackCase]:
    out: list[AttackCase] = []
    for case in corpus:
        if config.only_categories is not None and case.asi_category not in config.only_categories:
            continue
        if config.only_ids is not None and case.id not in config.only_ids:
            continue
        out.append(case)
    return out


def _build_probe(case: AttackCase, canary: str, config: RunConfig) -> Probe:
    probe = build_probe(case, canary=canary)
    probe.base_user_message = config.base_user_message
    return probe


def _oracle_for(case: AttackCase, canary: str) -> Any:
    """Build the case's oracle, injecting the trial's canary where relevant."""
    params = dict(case.oracle.params)
    if case.oracle.type == "canary_exfiltration":
        # The corpus uses the "$canary" placeholder; bind it to this trial's token.
        params["canary"] = canary
    return build_oracle(case.oracle.type, params)


def _probe_intent(case: AttackCase) -> str:
    """The one-line intent string handed to the judge for an ambiguous case.

    Prefers the case's explicit ``probe_intent``, falling back to its description
    or title so the judge always receives something concrete to score against.
    """
    return case.probe_intent or case.description or case.title or case.id


def _maybe_judge(
    case: AttackCase,
    response: AgentResponse,
    config: RunConfig,
) -> JudgeVerdict | None:
    """Consult the optional judge for an ambiguous case, as ADVISORY evidence.

    Returns ``None`` unless the case is marked ``ambiguous`` *and* a judge is
    configured. The judge's verdict is recorded alongside the deterministic oracle
    result but never replaces it -- if the judge is unreachable it degrades to a
    ``needs-review`` verdict (see :mod:`redcell.judge`), which is still recorded so
    the ambiguous case is visibly flagged for a human.
    """
    if not case.ambiguous or config.judge is None:
        return None
    return config.judge.evaluate(
        response=response,
        asi_category=case.asi_category,
        probe_intent=_probe_intent(case),
    )


def _transcript(response: AgentResponse) -> tuple[str, list[dict[str, Any]]]:
    output = response.output_text
    excerpt = output if len(output) <= 400 else output[:400] + "..."
    calls = [
        {"name": c.name, "arguments": c.arguments, "raw_arguments": c.raw_arguments}
        for c in response.tool_calls
    ]
    return excerpt, calls


def run_case(
    case: AttackCase,
    factory: TargetFactory,
    config: RunConfig,
) -> CaseResult:
    """Run one case ``config.trials`` times and aggregate the verdicts."""
    trials: list[TrialResult] = []
    for k in range(config.trials):
        canary = mint_canary()
        probe = _build_probe(case, canary, config)
        ctx = TrialContext(case=case, canary=canary, trial_index=k)
        adapter = factory(ctx)

        start = time.perf_counter()
        response = adapter.run(probe)
        latency_ms = (time.perf_counter() - start) * 1000.0

        if response.error:
            trials.append(
                TrialResult(
                    trial_index=k,
                    triggered=False,
                    severity=case.severity,
                    oracle=case.oracle.type,
                    canary=canary,
                    adapter_error=response.error,
                    latency_ms=latency_ms,
                )
            )
            continue

        verdict: OracleResult = _oracle_for(case, canary).evaluate(response)
        excerpt, calls = _transcript(response)
        # Advisory only: consulted for ambiguous cases when a judge is configured;
        # never alters the deterministic ``triggered`` verdict above.
        judge_verdict = _maybe_judge(case, response, config)
        trials.append(
            TrialResult(
                trial_index=k,
                triggered=verdict.triggered,
                severity=verdict.severity if verdict.triggered else case.severity,
                oracle=verdict.oracle or case.oracle.type,
                canary=canary,
                evidence=verdict.evidence,
                output_excerpt=excerpt,
                tool_calls=calls,
                latency_ms=latency_ms,
                judge=judge_verdict,
            )
        )

    return CaseResult(
        case_id=case.id,
        asi_category=case.asi_category,
        title=case.title or case.id,
        declared_severity=case.severity,
        delivery_vector=case.delivery_vector,
        oracle_type=case.oracle.type,
        trials=trials,
    )


def run_corpus(
    corpus: Corpus,
    factory: TargetFactory,
    config: RunConfig | None = None,
) -> RunResult:
    """Run every selected case in ``corpus`` against the target ``factory``.

    Returns a fully-serializable :class:`RunResult`. The ``factory`` is called
    once per trial so each trial gets a fresh target (fresh memory, the trial's
    canary wired in) -- see the module docstring.
    """
    cfg = config or RunConfig()
    started = time.time()
    cases = [run_case(case, factory, cfg) for case in _selected(corpus, cfg)]
    finished = time.time()
    return RunResult(
        target_label=cfg.target_label,
        trials_per_case=cfg.trials,
        cases=cases,
        started_at=started,
        finished_at=finished,
    )


@dataclass
class _CliState:
    """Holds state for the console-script entrypoint (kept minimal)."""

    label: str = "vulnagent"
    extra: dict[str, Any] = field(default_factory=dict)


def main() -> int:
    """Console-script entrypoint: run the seed corpus against ``vulnagent``.

    Runs the bundled corpus against all three vulnagent hardening levels offline
    (no network, no keys) and prints a one-line attack-success-rate summary per
    level. For full reports use ``scripts/run_matrix.py``.
    """
    # Imported lazily so the package import graph stays light and the in-repo
    # target (not part of the wheel) is only required when actually running.
    from pathlib import Path

    from redcell.report import summarize_run

    repo_root = Path(__file__).resolve().parent.parent
    corpus_dir = repo_root / "corpus"
    try:
        from targets.vulnagent import HardeningLevel  # noqa: PLC0415
    except ModuleNotFoundError:
        print("redcell: in-repo target not importable; run from the source tree.")
        return 1

    from redcell.corpus_loader import load_corpus

    corpus = load_corpus(corpus_dir)
    for level in (HardeningLevel.NONE, HardeningLevel.BASIC, HardeningLevel.HARDENED):
        factory = make_vulnagent_factory(level)
        result = run_corpus(
            corpus, factory, RunConfig(trials=3, target_label=f"vulnagent:{level.value}")
        )
        summary = summarize_run(result)
        print(
            f"vulnagent:{level.value:<8} "
            f"cases={summary['n_cases']} "
            f"any-success={summary['cases_with_any_success']} "
            f"overall-ASR={summary['overall_asr']:.2f} "
            f"weighted-risk={summary['severity_weighted_score']:.1f}"
        )
    return 0


def make_vulnagent_factory(level: Any) -> TargetFactory:
    """Build a :class:`TargetFactory` for the in-repo vulnagent at ``level``.

    Each trial gets a fresh agent. For memory-vector cases the trial's canary is
    pre-seeded into the agent's memory (so a leak is observable), and the canary
    is always registered as a known secret so the hardened output-filter tripwire
    is exercised.
    """
    from targets.vulnagent import HardeningLevel, build_agent  # noqa: PLC0415

    lvl = HardeningLevel(level) if isinstance(level, str) else level

    def factory(ctx: TrialContext) -> Adapter:
        from redcell.adapters import AgentLoopAdapter  # noqa: PLC0415

        agent = build_agent(lvl, known_secrets=[ctx.canary])
        if ctx.case.delivery_vector is DeliveryVector.MEMORY:
            # The poisoned record sits in memory for the agent to (mis)handle.
            agent.kv_set("archived_secret", ctx.canary)
        return AgentLoopAdapter(agent.run)

    return factory


if __name__ == "__main__":
    raise SystemExit(main())
