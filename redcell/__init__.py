"""redcell — a defensive agent-security test harness.

redcell is an evaluation tool for *authorized* red-team testing of agentic
applications you own or are permitted to assess. It is organized around the
OWASP Top 10 for Agentic Applications (2026) and behaves like a robustness
linter for AI agents: it drives a target agent through curated probe cases,
applies oracles to its observable behavior, and reports which risk categories
the agent withstood.

This package is a *test/eval* harness, not an attack kit. It does not ship
exploits; the corpus is a defensive benchmark of behaviors an agent should
resist, added in a later phase.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.

Public surface (to be filled in as the core lands):
    - adapters: bind a target agent to the harness
    - corpus_loader: load OWASP-categorized probe cases
    - oracles: decide pass/fail from observable agent behavior
    - runner: orchestrate the test matrix
    - report: render results
    - judge: optional model-assisted scoring
"""

from redcell.adapters import (
    Adapter,
    AgentLoopAdapter,
    McpAdapter,
    OpenAIEndpointAdapter,
    Probe,
    build_probe,
)
from redcell.corpus_loader import (
    AttackCase,
    Corpus,
    CorpusError,
    DeliveryVector,
    OracleSpec,
    load_corpus,
)
from redcell.judge import JUDGE_SYSTEM_PROMPT, Judge, JudgeStatus, JudgeVerdict
from redcell.oracles import (
    CanaryExfiltrationOracle,
    ForbiddenToolOracle,
    Oracle,
    OracleResult,
    PredicateOracle,
    build_oracle,
)
from redcell.types import (
    ASI_TITLES,
    MVP_CATEGORIES,
    AgentResponse,
    AsiCategory,
    Severity,
    ToolCall,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # types
    "AgentResponse",
    "ToolCall",
    "Severity",
    "AsiCategory",
    "ASI_TITLES",
    "MVP_CATEGORIES",
    # oracles
    "Oracle",
    "OracleResult",
    "CanaryExfiltrationOracle",
    "ForbiddenToolOracle",
    "PredicateOracle",
    "build_oracle",
    # corpus
    "AttackCase",
    "Corpus",
    "CorpusError",
    "DeliveryVector",
    "OracleSpec",
    "load_corpus",
    # adapters
    "Adapter",
    "Probe",
    "build_probe",
    "OpenAIEndpointAdapter",
    "AgentLoopAdapter",
    "McpAdapter",
    # judge
    "Judge",
    "JudgeVerdict",
    "JudgeStatus",
    "JUDGE_SYSTEM_PROMPT",
]
