"""Smoke test: the package imports and exposes a version.

Trivial passing test that proves the skeleton is wired up. Real test suites
(corpus validation, oracle verdicts, runner orchestration) arrive with the
core in a later phase.
"""

from __future__ import annotations

import redcell


def test_package_imports_and_has_version() -> None:
    assert isinstance(redcell.__version__, str)
    assert redcell.__version__
