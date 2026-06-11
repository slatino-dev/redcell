# Contributing to redcell

Thanks for your interest. redcell is a **defensive** agent-robustness harness;
all contributions must keep the project squarely on the authorized-testing side
of the line.

> **ETHICS / SCOPE — authorized testing only.** Contributions must not add
> turnkey exploits, working attack payloads against third-party systems, or
> anything whose primary use is offense. Probe cases are *test fixtures* paired
> with deterministic oracles; the value is the methodology and the measured
> deltas, never a ready-to-fire exploit.

## Development setup

```bash
pip install -e ".[dev]"
ruff check .
mypy
pytest -q
python scripts/scrub_check.py
```

All four must pass before a change lands. The same gate runs in CI.

## Conventions

- **Determinism first.** Oracles are deterministic by design; the optional judge
  is advisory and may never override an oracle verdict.
- **No fabricated numbers.** Every figure in the docs is computed from a recorded
  run. If you add a benchmark, commit the command that produces it, not just the
  result.
- **Corpus is generated-but-readable.** Edit the templates in
  `scripts/gen_corpus.py` and regenerate (`python scripts/gen_corpus.py`); the
  YAML under `corpus/` is the committed output.
- **Conventional commits.** `feat(...)`, `fix(...)`, `test(...)`, `docs(...)`,
  `chore(...)`.

## A note on the commit history

The initial public history was **reorganized into a sequence of logical,
conventional commits from a working branch** before release, so the messages
read as a clean layering (types → oracles → loader → adapters → runner → corpus
→ tests → docs) rather than as the raw, out-of-order working timeline. The
commit *messages* describe what each layer contains and are accurate; the
*timestamps* reflect when the history was reorganized, not the original
minute-by-minute development. Ongoing contributions should be committed as the
work actually progresses.
