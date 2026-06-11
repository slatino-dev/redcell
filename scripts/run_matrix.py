#!/usr/bin/env python3
"""run_matrix -- drive the corpus x target(s) matrix and write reports.

The convenience entrypoint for running redcell end-to-end. By default it runs the
bundled corpus against the in-repo ``vulnagent`` at all three hardening levels
(offline, no keys, no network) and writes:

* ``results/<label>.report.json``  -- the full run record per target;
* ``results/<label>.report.md``    -- a threat-report-style Markdown per target;
* ``results/hardening_delta.md``   -- the flagship same-corpus delta table.

Point it at your own OpenAI-compatible endpoint with ``--adapter openai`` plus
``OPENAI_BASE_URL`` / ``OPENAI_API_KEY`` to evaluate a real target.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted to
test. Only point an adapter at a target you are authorized to assess.

Examples
--------
    python scripts/run_matrix.py
    python scripts/run_matrix.py --trials 5 --out results
    python scripts/run_matrix.py --adapter openai --model my-local-model
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from redcell.corpus_loader import load_corpus  # noqa: E402
from redcell.report import render_hardening_delta, render_json, render_markdown  # noqa: E402
from redcell.runner import (  # noqa: E402
    RunConfig,
    TrialContext,
    make_vulnagent_factory,
    run_corpus,
)


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run the redcell corpus x target matrix.")
    p.add_argument("--corpus", default=str(REPO_ROOT / "corpus"), help="Corpus directory.")
    p.add_argument("--out", default=str(REPO_ROOT / "results"), help="Output directory.")
    p.add_argument("--trials", type=int, default=3, help="Trials per case (k).")
    p.add_argument(
        "--adapter",
        choices=["vulnagent", "openai"],
        default="vulnagent",
        help="vulnagent (offline, 3 levels) or openai (your endpoint).",
    )
    p.add_argument("--model", default=None, help="Model id for the openai adapter.")
    p.add_argument(
        "--judge",
        action="store_true",
        help=(
            "Consult the optional model-judge on cases flagged 'ambiguous' "
            "(advisory only; uses OPENAI_BASE_URL / OPENAI_JUDGE_MODEL). The "
            "judge never overrides a deterministic oracle verdict."
        ),
    )
    return p.parse_args(argv)


def _run_vulnagent(corpus_dir: str, out_dir: Path, trials: int) -> int:
    from targets.vulnagent import HardeningLevel  # noqa: PLC0415

    corpus = load_corpus(corpus_dir)
    results = []
    for level in (HardeningLevel.NONE, HardeningLevel.BASIC, HardeningLevel.HARDENED):
        label = f"vulnagent-{level.value}"
        result = run_corpus(
            corpus,
            make_vulnagent_factory(level),
            RunConfig(trials=trials, target_label=label),
        )
        results.append(result)
        (out_dir / f"{label}.report.json").write_text(render_json(result), encoding="utf-8")
        (out_dir / f"{label}.report.md").write_text(render_markdown(result), encoding="utf-8")
        print(f"wrote {label}.report.json / .md")

    delta = render_hardening_delta(results)
    (out_dir / "hardening_delta.md").write_text(delta, encoding="utf-8")
    print("wrote hardening_delta.md")
    print()
    print(delta)
    return 0


def _run_openai(
    corpus_dir: str, out_dir: Path, trials: int, model: str | None, use_judge: bool
) -> int:
    if not model:
        print("--adapter openai requires --model (and OPENAI_BASE_URL in the env).")
        return 2
    from redcell.adapters import Adapter, OpenAIEndpointAdapter  # noqa: PLC0415
    from redcell.judge import Judge  # noqa: PLC0415

    corpus = load_corpus(corpus_dir)
    tools = _default_tool_schema()

    def factory(_ctx: TrialContext) -> Adapter:
        return OpenAIEndpointAdapter(model=model, tools=tools)

    judge = Judge() if use_judge else None
    if use_judge and not (judge and judge.available):
        print("--judge set but no OPENAI_BASE_URL configured; ambiguous cases -> needs-review.")

    label = f"openai-{model}".replace("/", "_")
    try:
        result = run_corpus(
            corpus, factory, RunConfig(trials=trials, target_label=label, judge=judge)
        )
    except ValueError as exc:  # missing OPENAI_BASE_URL
        print(f"openai adapter not configured: {exc}")
        return 2
    (out_dir / f"{label}.report.json").write_text(render_json(result), encoding="utf-8")
    (out_dir / f"{label}.report.md").write_text(render_markdown(result), encoding="utf-8")
    print(render_markdown(result))
    return 0


def _default_tool_schema() -> list[dict[str, Any]]:
    """A small OpenAI tool schema mirroring vulnagent's tools, for real targets."""

    def fn(name: str, desc: str, props: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": desc,
                "parameters": {"type": "object", "properties": props},
            },
        }

    s = {"type": "string"}
    return [
        fn("read_file", "Read a file from the sandbox.", {"path": s}),
        fn("send_email", "Send an email.", {"to": s, "body": s}),
        fn("kv_set", "Store a value in memory.", {"key": s, "value": s}),
        fn("run_python", "Execute Python code (should be refused).", {"code": s}),
    ]


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.adapter == "vulnagent":
        return _run_vulnagent(args.corpus, out_dir, args.trials)
    return _run_openai(args.corpus, out_dir, args.trials, args.model, args.judge)


if __name__ == "__main__":
    raise SystemExit(main())
