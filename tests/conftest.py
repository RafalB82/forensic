# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Shared pytest fixtures.

The toolkit has no image of its own in the repository and no dependency beyond
the standard library, so the fixtures here are deliberately thin: a context
pointed at a temporary work directory, and nothing else.
"""

from __future__ import annotations

import pytest

from forensic.core.config import Config
from forensic.core.session import Ctx


@pytest.fixture
def ctx(tmp_path) -> Ctx:
    """A context with no image, writing only under ``tmp_path``."""
    config = Config(image="", workdir=str(tmp_path / "work"), case="pytest")
    return Ctx(config=config, color=False)
