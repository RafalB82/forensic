# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Allow ``python3 -m forensic``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
