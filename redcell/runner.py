"""Runner — orchestrate the test matrix (cases x target x oracles).

The runner is the harness's engine. It loads the corpus, sends each probe case
to the target via an adapter, applies the case's oracle to the response, and
collects per-case results into a structured run record. It is responsible for
concurrency limits, timeouts, deterministic ordering, and producing a result
set that ``report`` can render and ``scripts/gen_tables`` can summarize by
OWASP category.

ETHICS / SCOPE: For authorized testing of systems you own or are permitted
to test.

TODO (later phase):
    - Define ``RunConfig`` (target/adapter, corpus filter, concurrency,
      timeout, seed) and a ``RunResult`` aggregate.
    - Drive cases through adapter -> oracle; capture verdicts + timing.
    - Bounded async concurrency with cancellation + back-pressure.
    - Expose a Typer CLI entrypoint (``redcell run``) wired here.
"""

from __future__ import annotations


def main() -> int:
    """CLI entrypoint placeholder for the ``redcell`` console script.

    Replaced by the real Typer app when the run loop lands. Kept here so the
    declared ``[project.scripts]`` entrypoint resolves during scaffolding.
    """
    # TODO: implement the run loop in a later phase. Scaffold only.
    print("redcell: not implemented yet (scaffolding).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
