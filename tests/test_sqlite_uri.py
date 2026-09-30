# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""A database whose *name* needs escaping still opens, and stays where it is.

SQLite parses the string handed to ``sqlite3.connect(..., uri=True)`` as a URI,
so a ``#``, ``?`` or ``%`` in the filename is syntax unless it is percent-encoded.
Extracted evidence keeps the name it had inside the image, and nothing in an
Android package path forbids those characters, so the failure is silent: the open
either lands on a different file or on nothing at all.

Both entry points are pinned here, and the directory listing around the database
is checked as well — a read-only open that silently created a ``-wal`` or a
``-journal`` next to the evidence would be a second way to lose the original.
"""

import sqlite3

import pytest

from forensic.core import appdata, sqlite_tools

NAMES = ["case#12", "a?b", "x%20y", "zwykly", "with space", "plus+sign"]


def make_db(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("create table t(x)")
    conn.commit()
    conn.close()
    return path


@pytest.mark.parametrize("name", NAMES)
def test_open_path_with_special_chars(tmp_path, name):
    path = make_db(tmp_path / name / "Login Data")
    before = {p.name for p in tmp_path.iterdir()}

    assert (
        appdata._open(str(path)).execute("select count(*) from sqlite_master").fetchone()
        == (1,)
    )
    assert sqlite_tools.connect(path, immutable=True).execute("select 1").fetchone() == (1,)

    assert {p.name for p in tmp_path.iterdir()} == before


@pytest.mark.parametrize("name", NAMES)
def test_connect_is_read_only(tmp_path, name):
    path = make_db(tmp_path / name / "Login Data")
    conn = sqlite_tools.connect(path)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("insert into t values (1)")
    finally:
        conn.close()


def test_open_missing_file_still_raises(tmp_path):
    with pytest.raises(sqlite3.OperationalError):
        sqlite_tools.connect(tmp_path / "nie_ma_takiej#bazy")


def test_immutable_skips_the_wal(tmp_path):
    """``immutable=1`` is what lets a WAL database be read without its -wal."""
    path = tmp_path / "wal.db"
    conn = sqlite3.connect(path)
    conn.execute("pragma journal_mode=wal")
    conn.execute("create table t(x)")
    conn.commit()
    conn.close()

    assert sqlite_tools.connect(path, immutable=True).execute("select 1").fetchone() == (1,)
