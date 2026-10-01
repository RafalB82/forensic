# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Shared pytest fixtures.

The toolkit has no image of its own in the repository and no dependency beyond
the standard library, so the fixtures defined here are deliberately thin: a
context pointed at a temporary work directory, and nothing else.

The **domain** fixtures live in :mod:`appdata_fixtures` and are loaded as a
plugin below, which keeps this file small without making every test module import
them.  Importing them by hand does not work: pytest hands a test a fixture as a
parameter of the same name, and ruff then reports the import as a redefinition
(``F811``).  A plugin is the supported way to make fixtures visible everywhere
without that, and it is what ``conftest.py`` is for.
"""

from __future__ import annotations

import pytest

from forensic.core.config import Config
from forensic.core.session import Ctx

#: Domain fixtures — Android application databases, containers and blobs — built
#: as real files rather than described to the readers.  Registered as a plugin
#: rather than imported per module; see the module docstring.
pytest_plugins = ["appdata_fixtures"]


@pytest.fixture
def ctx(tmp_path) -> Ctx:
    """A context with no image, writing only under ``tmp_path``."""
    config = Config(image="", workdir=str(tmp_path / "work"), case="pytest")
    return Ctx(config=config, color=False)