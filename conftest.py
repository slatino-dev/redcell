"""Pytest configuration: make the repo root importable.

The ``targets/`` demo agent is an in-repo package that is intentionally NOT part
of the installed ``redcell`` wheel (see ``[tool.hatch.build.targets.wheel]`` in
``pyproject.toml``) -- it ships only with the source tree for validating the
harness. Adding the repo root to ``sys.path`` here lets the tests import it
deterministically regardless of how pytest was invoked.
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
