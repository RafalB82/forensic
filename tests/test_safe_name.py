# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The name an extracted file gets on the host filesystem.

Lives in :mod:`forensic.core.naming` because ``Ctx.materialise`` writes files
under the same rules and used to carry its own, colliding, copy of them.

Two contracts, and they are separate on purpose.

``flat_name`` is the readable half: an in-image path becomes **one** filename
component under ``work/<case>/extracted/``, with nothing able to climb out of the
directory.  Flattening alone cannot give distinct paths distinct names — ``/a/b``
and ``/a_b`` both flatten to ``a_b`` — so ``safe_name`` adds a digest of the
original path, and ``unique_names`` makes the one-file-per-source guarantee hold
by construction rather than by probability.

The collision test below is the one that was missing.  The version of this file
that claimed "distinct paths do not collide" tested ``/data/com.example/x``
against ``/data/com/example/x``, which pass only because the ``.`` in
``com.example`` survives flattening while the ``/`` does not.  It looked like
coverage of the exact failure and was not.
"""

from __future__ import annotations

import pytest

from forensic.core.naming import flat_name, safe_name, unique_names


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
def test_flat_name(path, expected):
    assert flat_name(path) == expected


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


def test_paths_that_flatten_the_same_get_different_files():
    """The flattening collision, which is the case that lost bytes.

    ``/a/b`` and ``/a_b`` are two different files that used to be extracted to
    one name, so the second overwrote the first and the manifest went on to list
    two SHA-256 values for one file on disk.
    """
    assert flat_name("/a/b") == flat_name("/a_b") == "a_b"
    assert safe_name("/a/b") != safe_name("/a_b")


def test_separator_and_underscore_do_not_collide():
    for left, right in (
        ("/a/b", "/a_b"),
        ("/data/x", "/data_x"),
        ("/system/build.prop", "/system/build.prop2"),
        ("/a.b/c", "/a/b.c"),
    ):
        assert safe_name(left) != safe_name(right), (left, right)


def test_same_path_is_stable():
    """Re-running a case must not rename artifacts an earlier report referenced."""
    for path in ("/data/system/lock_settings.db", "/", "/data/a b/c"):
        assert safe_name(path) == safe_name(path)


def test_name_stays_readable():
    """The digest is appended, not substituted — the name is still recognisable."""
    name = safe_name("/data/system/lock_settings.db")
    assert name.startswith("data_system_lock_settings.db--")


def test_unique_names_maps_each_source_to_its_own_file():
    paths = ["/a/b", "/a_b", "/data/system/lock_settings.db", "/a/b"]
    names = unique_names(paths)
    assert len(set(names.values())) == len(set(paths))
    # A repeated request for the same source keeps one name, not two files.
    assert len(names) == 3


def test_unique_names_never_hands_two_sources_one_name():
    """Exhaustive over the alphabet the collision lives in.

    The guarantee has to come from :func:`unique_names`, so this checks the
    function's output and not the digest's 48 bits of margin.
    """
    sources = [f"/a{'/' * (i % 4)}{'b' * (i % 3)}" for i in range(60)]
    sources += [f"/x_{i}" for i in range(60)]
    names = unique_names(sources)
    assert len(names) == len(set(sources))
    assert len(set(names.values())) == len(names)