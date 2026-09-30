# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The name an extracted file gets on the host filesystem.

``safe_name`` flattens an in-image path into a filename under
``work/<case>/extracted/``.  Two things have to hold: distinct paths must not
collide into one file (a second extraction would overwrite the first, and the
manifest would name the wrong bytes), and the result must not escape the
directory it is written into.
"""

from __future__ import annotations

import pytest

from forensic.modules.offline.extract_file import safe_name


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/data/system/lock_settings.db", "data_system_lock_settings.db"),
        ("/data/com.example.app/databases/main.db", "data_com.example.app_databases_main.db"),
        ("/", "root"),
        ("", "root"),
        ("///", "root"),
        ("/data/a b/c", "data_a_b_c"),
        # Dots survive the substitution, so these two need the explicit check.
        (".", "root"),
        ("..", "root"),
        ("/..", "root"),
    ],
)
def test_safe_name(path, expected):
    assert safe_name(path) == expected


def test_no_traversal_out_of_the_destination():
    """The result is one component that is not the parent directory.

    ``..`` inside a longer name is only a couple of literal dots and cannot
    climb; the dangerous case is a result that *is* ``..`` or ``.``, which is
    what this pins.
    """
    for path in ("/../../etc/passwd", "/data/../../..", "..", ".", "/a/../b"):
        name = safe_name(path)
        assert "/" not in name, path
        assert name not in (".", ".."), path


def test_distinct_paths_do_not_collide():
    """The names differ for paths that only differ in the separator."""
    a = safe_name("/data/com.example/x")
    b = safe_name("/data/com/example/x")
    assert a != b


def test_same_path_is_stable():
    assert safe_name("/data/system/lock_settings.db") == safe_name(
        "/data/system/lock_settings.db"
    )
