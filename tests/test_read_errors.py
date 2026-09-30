# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""A read that failed must not be reported as a read that found nothing.

The shape this file exists to prevent, in its three usual forms:

* ``except sqlite3.Error: return []`` — the empty list is a *value*, it flows on,
  and it is finally rendered as a count of zero;
* ``get(key, 0)`` — a key the code omitted on purpose reads as a zero;
* a top-level ``except Exception`` that prints a line and returns ``None``, so the
  module leaves no finding, no export and no entry in ``verify.json``.

All three produce the same sentence for a reader: *nothing was there*.  None of
them is that sentence.  A damaged database, a database whose table would not
parse, and a database that is empty are three different facts and each one has to
be able to reach a report in its own words.

The stubs here stand in for connections and modules that fail on demand.  That is
deliberate for ``count_rows``: a SQLite database whose ``count(*)`` genuinely
fails is close to unreachable through a corrupt file, and a test that has to
manufacture one ends up asserting something about SQLite rather than about this
code.  What is reachable — and what went wrong — is the *handling*, so that is
what gets pinned.
"""

from __future__ import annotations

import sqlite3

from forensic import controller as controller_mod
from forensic.core.readlog import ABSENT, PRESENT, TRUNCATED, UNREADABLE, ReadLog, merge_logs
from forensic.core.timeline import Timeline


# --- the vocabulary ----------------------------------------------------------


def test_four_states_are_four_words():
    """Three outcomes plus one, and the fourth is not a refinement of the third.

    ``TRUNCATED`` is about the image; ``UNREADABLE`` is about an artifact.  An
    image can be truncated while everything inside it that was read is intact, so
    collapsing the two would tell a reader that a file they read perfectly was
    damaged.
    """
    words = {PRESENT, ABSENT, UNREADABLE, TRUNCATED}
    assert len(words) == 4
    assert len({len(w) for w in words}) == 4  # no word is a prefix of another


def test_status_prefers_unreadable_over_absent():
    log = ReadLog()
    assert log.status("/x") == PRESENT
    log.absent("/x")
    assert log.status("/x") == ABSENT
    log.unreadable("/x", ValueError("boom"))
    assert log.status("/x") == UNREADABLE


# --- the log itself ----------------------------------------------------------


def test_log_keeps_the_exception_type_in_the_reason():
    """A report line naming only the message does not say what kind of failure."""
    log = ReadLog()
    log.unreadable("/data/db", sqlite3.DatabaseError("malformed"))
    assert log.entries[0]["why"] == "DatabaseError: malformed"


def test_log_is_bounded_but_keeps_the_real_count():
    """A corrupt subtree can fail thousands of times; the report keeps the first few."""
    log = ReadLog()
    for index in range(ReadLog.KEEP + 25):
        log.unreadable(f"/dir/{index}", ValueError("x"))
    assert len(log.entries) == ReadLog.KEEP
    assert log.total == ReadLog.KEEP + 25
    assert log.truncated is True
    assert len(log) == ReadLog.KEEP + 25
    assert bool(log) is True


def test_summary_of_a_clean_log():
    log = ReadLog()
    assert log.summary() == {
        "read_errors": 0,
        "read_error_detail": [],
        "read_errors_truncated": False,
        "complete": True,
    }


def test_summary_names_the_artifact_under_test():
    log = ReadLog()
    log.unreadable("/data/wa.db", ValueError("x"))
    out = log.summary("/data/wa.db")
    assert out["status"] == UNREADABLE
    assert out["unreadable"] is True
    assert out["complete"] is False


def test_merge_keeps_both_kinds():
    a, b = ReadLog(), ReadLog()
    a.unreadable("/one", ValueError("x"))
    b.absent("/two")
    merged = merge_logs(a, b)
    assert merged.failed("/one")
    assert merged.known_absent("/two")
    assert merged.total == 2


# --- count_rows: the sentinel that was truthy --------------------------------


class _StubConn:
    """A connection whose ``count(*)`` fails for named tables only."""

    def __init__(self, good: dict[str, int], bad: set[str]) -> None:
        self.good = good
        self.bad = bad

    def execute(self, sql, params=()):
        if sql.startswith("select count(*) from"):
            name = sql.split('"')[1]
            if name in self.bad:
                raise sqlite3.DatabaseError("database disk image is malformed")
            return _StubCursor([(self.good[name],)])
        if sql.startswith("select name from sqlite_master"):
            return _StubCursor([(name,) for name in list(self.good) + sorted(self.bad)])
        raise AssertionError(sql)


class _StubCursor:
    """What ``sqlite3.Cursor`` gives these helpers that a plain list does not."""

    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)

    def __iter__(self):
        return iter(self._rows)


def test_count_rows_returns_none_and_not_minus_one():
    """``-1`` is truthy, and the caller filters on truthiness.

    ``quicklook`` built ``non_empty_tables`` with ``{k: v for k, v in counts.items()
    if v}``.  A table whose count failed came back as ``-1``, passed that filter,
    and appeared in the report as a table that has something in it — a failure
    rendered as evidence of content.
    """
    from forensic.core.sqlite_tools import count_rows, row_counts

    conn = _StubConn({"accounts": 5}, {"broken"})
    assert count_rows(conn, "accounts") == 5
    assert count_rows(conn, "broken") is None

    counts = row_counts(conn)
    assert counts == {"accounts": 5, "broken": None}
    # The exact expression quicklook used to get wrong.
    assert {k: v for k, v in counts.items() if v} == {"accounts": 5}


def test_unreadable_table_is_not_in_non_empty_tables():
    """The regression in the shape quicklook consumes it."""
    counts = {"accounts": 5, "broken": None, "empty": 0}
    unreadable = [name for name, value in counts.items() if value is None]
    non_empty = {name: value for name, value in counts.items() if value}
    assert unreadable == ["broken"]
    assert non_empty == {"accounts": 5}


# --- preferences_rows: empty list, or an explanation -------------------------


def test_preferences_rows_records_the_failure_when_given_a_log(tmp_path):
    """Both of its callers reported a count, so both needed the distinction.

    ``fb_tokens`` printed "0 documents, 0 tokens" and ``login_timeline`` left an
    empty Messenger timeline; one of them from a database neither had opened.
    """
    from forensic.core import appdata

    db = tmp_path / "prefs.db"
    conn = sqlite3.connect(db)
    conn.execute("create table preferences(key text, type text, value blob)")
    conn.commit()
    conn.close()
    # Not a database at all: the open is what will fail.
    broken = tmp_path / "broken.db"
    broken.write_bytes(b"this is not a sqlite file" * 64)

    # Schema present and no rows: an empty list is the honest answer here.
    assert appdata.preferences_rows(str(db), ReadLog()) == []
    log = ReadLog()
    assert appdata.preferences_rows(str(broken), log) == []
    assert log.total >= 1
    assert log.entries, "nieudane odczytanie bez zapisu"


def test_preferences_rows_without_a_log_still_returns_a_list(tmp_path):
    """The optional log must not change what an existing caller gets."""
    from forensic.core import appdata

    db = tmp_path / "prefs.db"
    conn = sqlite3.connect(db)
    conn.execute("create table preferences(key text, type text, value blob)")
    conn.execute("insert into preferences values('k','s','v')")
    conn.commit()
    conn.close()
    assert appdata.preferences_rows(str(db)) == [("k", "s", "v")]


# --- the whatsapp counts: three states, not two ------------------------------


def test_starred_absent_is_not_zero():
    """``msgstore.get('starred', 0)`` printed "0 oznaczonych gwiazdką" on a
    database whose query had failed.  The key was omitted precisely to avoid
    printing a number it did not have."""
    from forensic.modules.offline.whatsapp import _counts_sentence

    assert _counts_sentence({"forwarded": 12, "starred": 0}) == (
        "12 przekazanych dalej, 0 oznaczonych gwiazdką."
    )
    assert "nieczytelne" in _counts_sentence({"forwarded": 12, "starred": None})
    assert "nieczytelne" in _counts_sentence({"forwarded": None, "starred": None})
    # A column this build never had is not a failure, and is left out entirely.
    assert _counts_sentence({"forwarded": 5}) == "5 przekazanych dalej."
    assert _counts_sentence({}) == ""


# --- timelines carry their own gaps ------------------------------------------


def test_timeline_read_errors_propagate_and_are_never_events():
    """A gap cannot be an event: an event claims a timestamp and a source."""
    one = Timeline(label="messenger")
    one.read_errors.append({"artifact": "/data/prefs.db", "status": UNREADABLE, "why": "x"})
    two = Timeline(label="gmail")
    combined = Timeline(label="auth").extend(one).extend(two)
    assert combined.complete is False
    assert len(combined.read_errors) == 1
    assert combined.events == []


def test_a_timeline_with_no_errors_is_complete():
    assert Timeline(label="auth").complete is True


# --- the top-level classification --------------------------------------------


def test_classify_separates_evidence_failure_from_a_bug():
    """Three destinations, and the third is not a finding about the evidence."""
    from forensic.core.evidence import TruncatedEvidenceError

    assert controller_mod._classify(sqlite3.DatabaseError("malformed")) == (
        UNREADABLE,
        "baza jest, ale nie dało się jej odczytać",
    )
    assert controller_mod._classify(TruncatedEvidenceError("blok 5 poza obrazem"))[0] == TRUNCATED
    status, why = controller_mod._classify(TypeError("None has no len()"))
    assert status == "" and why == "", "błąd w kodzie nie jest twierdzeniem o dowodzie"


def test_escaping_database_error_is_recorded_not_dropped(tmp_path):
    """A module that raised used to return ``None`` and leave no trace at all.

    No finding, no export, nothing in ``verify.json`` — an absence in the report
    that reads exactly like a clean negative.
    """
    from forensic.core.config import Config
    from forensic.modules import registry

    spec = registry.ModuleSpec(
        id="pytest_raises_sqlite", category="pytest", title="t", summary="s"
    )

    def boom(ctx, params):
        raise sqlite3.DatabaseError("database disk image is malformed")

    spec.run = boom  # type: ignore[assignment]
    registry.register(spec)
    try:
        ctrl = controller_mod.Controller(
            config=Config(image="", workdir=str(tmp_path / "w"), case="pytest"),
            color_enabled=False,
        )
        try:
            result = ctrl.run_module("pytest_raises_sqlite", {})
        finally:
            ctrl.close()
    finally:
        registry.REGISTRY[:] = [s for s in registry.REGISTRY if s.id != "pytest_raises_sqlite"]

    assert result is not None, "moduł zniknął bez śladu"
    assert result.worst == "critical"
    assert result.findings[0].values["status"] == UNREADABLE
    assert "malformed" in result.findings[0].detail
    assert result.notes, "brak notatki w session.json"


def test_a_bug_still_prints_and_returns_none(tmp_path, capsys):
    """Classification must not swallow real defects into tidy findings."""
    from forensic.core.config import Config
    from forensic.modules import registry

    spec = registry.ModuleSpec(
        id="pytest_raises_typeerror", category="pytest", title="t", summary="s"
    )

    def boom(ctx, params):
        raise TypeError("None has no len()")

    spec.run = boom  # type: ignore[assignment]
    registry.register(spec)
    try:
        ctrl = controller_mod.Controller(
            config=Config(image="", workdir=str(tmp_path / "w"), case="pytest"),
            color_enabled=False,
        )
        try:
            assert ctrl.run_module("pytest_raises_typeerror", {}) is None
        finally:
            ctrl.close()
    finally:
        registry.REGISTRY[:] = [s for s in registry.REGISTRY if s.id != "pytest_raises_typeerror"]
    assert "TypeError" in capsys.readouterr().out
