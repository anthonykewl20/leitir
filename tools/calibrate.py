#!/usr/bin/env python3
"""Entry point for the Leitir self-calibration loop (see docs/calibration.md).

    PYTHONPATH=src uv run --no-project --with-requirements requirements.txt \
      --with coverage==7.15.2 --with pytest-cov==7.1.0 --with ruff --with mypy \
      python tools/calibrate.py run
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from calibration.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
