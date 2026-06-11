#!/usr/bin/env python3
"""gen_tables -- summarize a run-record JSON into per-category tables.

Reads a ``*.report.json`` written by ``scripts/run_matrix.py`` (or
``redcell.report.render_json``) and emits a per-OWASP-category summary as
Markdown and/or CSV. It only formats numbers already present in the run record;
it never recomputes verdicts and never invents a score.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted to
test.

Examples
--------
    python scripts/gen_tables.py results/vulnagent-none.report.json
    python scripts/gen_tables.py results/vulnagent-none.report.json --csv out.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any


def _load(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"cannot read run record {path}: {exc}") from exc
    if not isinstance(payload, dict) or "summary" not in payload:
        raise SystemExit(f"{path}: not a redcell report (no 'summary' key)")
    result: dict[str, Any] = payload
    return result


def _markdown(summary: dict[str, Any]) -> str:
    lines: list[str] = []
    lines.append(f"# Per-category summary -- `{summary['target_label']}`")
    lines.append("")
    lines.append(
        f"Trials/case: {summary['trials_per_case']} - "
        f"cases: {summary['n_cases']} - "
        f"overall ASR: {summary['overall_asr'] * 100:.0f}% - "
        f"weighted risk: {summary['severity_weighted_score']:.1f}"
    )
    lines.append("")
    lines.append("| Category | Title | Cases | >=1 success | Mean ASR | Weighted risk |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: |")
    for cat in summary["per_category"].values():
        lines.append(
            f"| {cat['category']} | {cat['title']} | {cat['n_cases']} | "
            f"{cat['any_success']} | {cat['asr'] * 100:.0f}% | {cat['weighted_score']:.1f} |"
        )
    return "\n".join(lines) + "\n"


def _write_csv(summary: dict[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["category", "title", "n_cases", "any_success", "asr", "weighted_score"])
        for cat in summary["per_category"].values():
            writer.writerow(
                [
                    cat["category"],
                    cat["title"],
                    cat["n_cases"],
                    cat["any_success"],
                    f"{cat['asr']:.4f}",
                    f"{cat['weighted_score']:.2f}",
                ]
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize a redcell run record.")
    parser.add_argument("report", help="Path to a *.report.json run record.")
    parser.add_argument("--csv", default=None, help="Also write a CSV to this path.")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    payload = _load(Path(args.report))
    summary = payload["summary"]
    sys.stdout.write(_markdown(summary))
    if args.csv:
        _write_csv(summary, Path(args.csv))
        print(f"\nwrote CSV: {args.csv}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
