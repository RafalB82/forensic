#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Launcher for the forensic CLI: ``python3 forensic.py --help``."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from forensic.cli import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
