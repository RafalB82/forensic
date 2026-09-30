# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Audit our own hand-written parsers against reference implementations.

Most of this tool reads databases with libsqlite3 through :mod:`sqlite3`, which
is the reference implementation, so it inherits that authority for free.  Two
places are *not* like that:

* :func:`forensic.core.sqlite_tools.leaf_rows` is a hand-written decoder for
  SQLite's record format — serial types, varints, the local-payload formula for
  overflowed rows.  It is used to pull records out of a rollback journal when
  the journal's header has been wiped, which is exactly the case where being
  wrong changes a finding rather than raising an error.
* :func:`forensic.core.appdata.classify` decides what a blob is, from four magic
  numbers and a first-character test.

Both were written by the author of the report that cites them, and for a long
time nothing compared either against anybody.  This module does, using
implementations that share no code with ours: ``sqlite3`` for the record format,
libmagic for the container type.

The comparison is deliberately narrow.  For SQLite it checks the row *count* per
table, which is unambiguous, and then the *numeric* columns of rows that did not
overflow — a row whose payload spilled onto another page comes back with its
text truncated, and comparing that against sqlite3 would report a mismatch that
is really just a value we cannot see.  Those rows are counted and named, not
compared.
"""

from __future__ import annotations

import time
from pathlib import Path

from ...core import appdata, sqlite_tools
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, INT, LIST, ModuleSpec, Param, register

#: Databases used when the caller names none.  A contacts database is a good
#: default: 4.8 MB, 44 tables, ~27 000 rows, long text columns that overflow,
#: and a custom collation that stops ``PRAGMA integrity_check`` from running at
#: all — so it exercises the paths a toy database never reaches.
DEFAULT_DATABASES = (
    "/data/com.android.providers.contacts/databases/contacts2.db",
    "/system/users/0/accounts.db",
)

#: How many rows per table are compared value by value.  The counts are checked
#: for every row regardless; only this many have their numbers compared.
VALUE_ROWS = 40


def _alias_column(ref, table: str) -> int:
    """Index of the ``INTEGER PRIMARY KEY`` column, or ``-1``.

    Such a column is an alias for the rowid: SQLite stores ``NULL`` in the record
    and substitutes the rowid at read time.  A decoder that reads the record
    faithfully therefore returns ``None`` where ``sqlite3`` returns an integer —
    and that is the decoder being right.  Without this, every table with a
    surrogate key looks like a total failure: ``accounts`` on the reference image
    reported 1 of 49 values matching, and the cause was three ``None``s that
    should have been the rowids.

    The test is the declared type as well as ``pk``: a ``TEXT PRIMARY KEY`` is a
    real stored value, not an alias, and treating it as one would replace a
    genuine string with a number.
    """
    try:
        for row in ref.execute(f'pragma table_info("{table}")'):
            decl, pk = str(row[2] or "").strip().upper(), row[5]
            if pk and decl == "INTEGER":
                return int(row[0]) if pk == 1 else -1
            if pk:
                return -1
    except Exception:  # noqa: BLE001
        return -1
    return -1


def _compare_row(
    ours: list,
    theirs: tuple,
    rowid: int,
    alias: int,
    overflowed: bool,
) -> tuple[str, dict]:
    """Compare one decoded record against sqlite3's row for the same rowid.

    Returns ``(status, detail)`` where status is ``agree``, ``schema_evolved``
    or ``mismatch``.

    Three outcomes, not two, because on a real Android database all three occur
    and lumping them together buries the one that matters:

    ``agree``
        the record matches.
    ``schema_evolved``
        our record is shorter than the table's column count.  The row predates an
        ``ALTER TABLE ADD COLUMN``, so SQLite fills the missing trailing columns
        from the schema default while the bytes on disk simply do not contain
        them.  ``calls`` in the contacts database has 51 columns and its oldest
        rows carry 50; reporting that as a decoding fault would be wrong, and
        reporting nothing would hide a real schema fact worth knowing.
    ``mismatch``
        the decoder disagrees about a value that is present on both sides.

    Text and blob columns of an overflowed row are skipped rather than compared:
    our decoder only ever sees the local prefix of a spilled payload, so a
    difference there is a value we cannot see, not a value we got wrong.
    """
    detail: dict = {"rowid": rowid, "column": None, "ours": None, "sqlite3": None}
    mine = list(ours)
    if 0 <= alias < len(mine) and mine[alias] is None:
        mine[alias] = rowid
    theirs_list = list(theirs)
    status = "agree"
    if len(mine) != len(theirs_list):
        shorter, longer = (mine, theirs_list) if len(mine) < len(theirs_list) else (theirs_list, mine)
        if shorter == longer[: len(shorter)]:
            status = "schema_evolved"
            detail["schema_columns"] = len(theirs_list)
            detail["record_columns"] = len(mine)
            detail["added_tail"] = [repr(v)[:20] for v in theirs_list[len(mine) :]][:4]
        else:
            detail.update({"column": "-", "ours": len(mine), "sqlite3": len(theirs_list)})
            return "mismatch", detail
    for index, (a, b) in enumerate(zip(mine, theirs_list)):
        if isinstance(b, (bytes, str)) and overflowed:
            continue
        if isinstance(a, bytes) and not isinstance(b, bytes):
            continue
        if a != b:
            detail.update({"column": index, "ours": repr(a)[:60], "sqlite3": repr(b)[:60]})
            return "mismatch", detail
    return status, detail


def _audit_database(ctx: Ctx, res: ModuleResult, local: Path, target: str, limit: int) -> dict:
    out: dict[str, object] = {"target": target, "path": str(local)}
    try:
        head = sqlite_tools.header(local)
    except Exception as exc:  # noqa: BLE001
        out["error"] = str(exc)
        return out
    if not head.get("is_sqlite"):
        out["error"] = "plik nie jest bazą SQLite"
        return out
    out["page_size"] = head["page_size"]
    out["page_count"] = head["page_count"]
    usable = head["page_size"] - head["reserved"]
    verdict = appdata.classify_checked(local.read_bytes())
    out["format"] = verdict["report"]
    out["format_ours"] = verdict["format"]
    out["format_magic"] = verdict["magic"]
    out["format_note"] = verdict["note"]
    try:
        ref = sqlite_tools.connect(local)
        tables = sorted(
            (row[0], row[1])
            for row in ref.execute(
                "select name, rootpage from sqlite_master "
                "where type='table' and name not like 'sqlite_%'"
            )
        )
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"sqlite3: {exc}"
        return out
    agreed = disagreed = skipped = 0
    value_checked = value_agreed = value_evolved = 0
    evolved_examples: list[dict] = []
    total_ours = total_ref = 0
    overflow = 0
    mismatches: list[dict] = []
    order_problems: list[dict] = []
    value_mismatches: list[dict] = []
    problems: list[dict] = []
    for name, root in tables[:limit] if limit else tables:
        walked = sqlite_tools.walk_table(local, root, head["page_size"], usable)
        if walked.get("virtual"):
            skipped += 1
            continue
        overflow += walked.get("overflow_rows", 0)
        for item in walked.get("problems", []):
            problems.append({"table": name, **item})
        try:
            reference = ref.execute(f'select count(*) from "{name}"').fetchone()[0]
        except Exception as exc:  # noqa: BLE001
            skipped += 1
            out.setdefault("skipped_detail", []).append({"table": name, "why": str(exc)})
            continue
        ours = walked["records"]
        total_ours += ours
        total_ref += reference
        if ours == reference:
            agreed += 1
        else:
            disagreed += 1
            mismatches.append({"table": name, "sqlite3": reference, "ours": ours})
        # Value comparison on the rows that did not overflow.  Rows are lined up
        # by rowid, so a traversal-order bug shows up as a value mismatch instead
        # of being hidden by comparing multisets.
        if ours == reference and reference and walked.get("ascending", True):
            alias = _alias_column(ref, name)
            try:
                # ``order by rowid`` is not decoration.  Without it SQLite is
                # free to answer from a covering index, and on accounts.db it
                # does: ``select rowid from extras`` came back 7, 171, 209, 259
                # while the table b-tree holds 1, 2, 3, 4.  The sets are equal,
                # the orders are not, and comparing them positionally would
                # report nine ordering faults in a decoder that is correct.
                sample = ref.execute(
                    f'select * from "{name}" order by rowid limit {VALUE_ROWS}'
                ).fetchall()
                keys = ref.execute(
                    f'select rowid from "{name}" order by rowid limit {VALUE_ROWS}'
                ).fetchall()
            except Exception:  # noqa: BLE001
                sample, keys = [], []
            rowids = walked.get("rowids") or []
            for index, row in enumerate(sample[:VALUE_ROWS]):
                if index >= len(walked["rows"]):
                    break
                key = keys[index][0] if index < len(keys) else (
                    rowids[index] if index < len(rowids) else None
                )
                if key is not None and index < len(rowids) and rowids[index] != key:
                    order_problems.append(
                        {"table": name, "position": index, "our_rowid": rowids[index],
                         "sqlite3_rowid": key}
                    )
                    break
                status, detail = _compare_row(
                    walked["rows"][index],
                    row,
                    key if key is not None else -1,
                    alias,
                    index in (walked.get("overflow_at") or ()),
                )
                value_checked += 1
                if status == "agree":
                    value_agreed += 1
                elif status == "schema_evolved":
                    value_evolved += 1
                    if len(evolved_examples) < 5:
                        evolved_examples.append({"table": name, **detail})
                else:
                    detail["table"] = name
                    value_mismatches.append(detail)
    out.update(
        {
            "tables": len(tables),
            "tables_agreed": agreed,
            "tables_disagreed": disagreed,
            "tables_skipped": skipped,
            "order_problem_count": len(order_problems),
            "records_ours": total_ours,
            "records_sqlite3": total_ref,
            "overflow_rows": overflow,
            "values_compared": value_checked,
            "values_agreed": value_agreed,
            "values_schema_evolved": value_evolved,
            "schema_evolved_examples": evolved_examples,
            "mismatches": mismatches[:10],
            "order_problems": order_problems[:10],
            "value_mismatches": value_mismatches[:10],
            "walk_problems": problems[:10],
        }
    )
    bad = disagreed or value_mismatches or order_problems or problems
    res.add(
        "ok" if not bad else "critical",
        f"{target.split('/')[-1]}: {agreed}/{agreed + disagreed} tabel zgodnych "
        f"({total_ours} rekordów), {value_agreed}/{value_checked} wartości zgodnych"
        if not bad
        else f"{target.split('/')[-1]}: {disagreed} tabel i {len(value_mismatches)} wartości "
        "nie zgadza się z sqlite3",
        detail="; ".join(
            [f"liczba {m['table']}: {m['sqlite3']} vs {m['ours']}" for m in mismatches[:3]]
            + [f"wartość {m.get('table')}#{m.get('rowid')} kol.{m.get('column')}: "
               f"{m.get('ours')} vs {m.get('sqlite3')}" for m in value_mismatches[:3]]
            + [f"kolejność {m['table']}: pozycja {m['position']} to rowid {m['our_rowid']}, "
               f"a sqlite3 ma {m['sqlite3_rowid']}" for m in order_problems[:2]]
            + [f"{p.get('table')} {p.get('issue')}" for p in problems[:2]]
        )[:400] or None,
        values={
            "target": target,
            "format": verdict["report"],
            "format_ours": verdict["format"],
            "format_magic": verdict["magic"],
            "tables": len(tables),
            "tables_agreed": agreed,
            "tables_disagreed": disagreed,
            "tables_skipped": skipped,
            "order_problem_count": len(order_problems),
            "records_ours": total_ours,
            "records_sqlite3": total_ref,
            "overflow_rows": overflow,
            "values_compared": value_checked,
            "values_agreed": value_agreed,
            "values_schema_evolved": value_evolved,
        },
    )
    if value_evolved:
        res.add(
            "info",
            f"{target.split('/')[-1]}: {value_evolved} wierszy starszych niż schemat "
            "(ALTER TABLE ADD COLUMN — sqlite3 dopełnia wartością domyślną, na dysku jej nie ma)",
            detail="; ".join(
                f"{e.get('table')}#{e.get('rowid')}: {e.get('record_columns')} kolumn na dysku, "
                f"{e.get('schema_columns')} w schemacie" for e in evolved_examples[:3]
            )[:400] or None,
            values={"evolved": value_evolved, "tables": sorted({e.get("table") for e in evolved_examples})},
        )
    return out


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("decoder_audit")
    raw = params.get("databases") or DEFAULT_DATABASES
    if isinstance(raw, str):
        targets = [item.strip() for item in raw.split(",") if item.strip()]
    else:
        targets = [str(item) for item in raw]
    limit = max(0, int(params.get("limit") or 0))
    do_magic = bool(params.get("magic", True))
    started = time.time()
    if not do_magic:
        res.note("pomijam libmagic (parametr magic=false)")
    parts: dict[str, object] = {
        "magic_available": appdata.magic_available() if do_magic else False,
        "databases": [],
    }
    resolved = 0
    for target in targets:
        try:
            local = ctx.materialise(target)
        except Exception as exc:  # noqa: BLE001 - a missing file is a finding
            res.add("warn", f"Brak {target} w obrazie", detail=str(exc)[:200])
            parts["databases"].append({"target": target, "error": str(exc)[:200]})
            continue
        resolved += 1
        parts["databases"].append(_audit_database(ctx, res, local, target, limit))
    # Standalone libmagic agreement on whatever blobs the applications hand us.
    if do_magic and parts["magic_available"]:
        samples = 0
        agreed = unrecognised = 0
        for target in ("/data/com.facebook.lite/files/PropertiesStore_v02",):
            try:
                blob = ctx.fs().read(target)
            except Exception:  # noqa: BLE001
                continue
            verdict = appdata.classify_checked(blob)
            samples += 1
            if verdict["format"] == verdict["report"]:
                agreed += 1
            else:
                unrecognised += 1
            res.add(
                "info",
                f"libmagic a własny klasyfikator: {target.split('/')[-1]} → "
                f"{verdict['format']} / {verdict['report'] or '—'}",
                detail=verdict["note"][:300],
                values={
                    "target": target,
                    "ours": verdict["format"],
                    "report": verdict["report"],
                    "magic": verdict["magic"],
                    "magic_raw": verdict["magic_raw"],
                },
            )
        parts["magic_samples"] = samples
        parts["magic_extended"] = unrecognised
        parts["magic_agreed"] = agreed
    parts["seconds"] = round(time.time() - started, 1)
    parts["databases_resolved"] = resolved
    res.data = parts
    from ...core.export import to_json

    path = to_json(ctx.work("exports") / "decoder_audit.json", parts)
    res.export(path)
    bad = [
        db for db in parts["databases"]
        if db.get("tables_disagreed") or db.get("value_mismatches") or db.get("order_problem_count")
    ]
    if not resolved:
        summary = "Brak baz do audytu"
    elif bad:
        summary = f"Audyt własnych parserów: {resolved} baz, {len(bad)} z niezgodnościami"
    else:
        summary = (
            f"Audyt własnych parserów: {resolved} baz, pełna zgodność "
            "z implementacjami referencyjnymi"
        )
    res.add(
        "ok" if resolved and not bad else ("warn" if not resolved else "critical"),
        summary,
        values={
            "databases": resolved,
            "with_mismatches": len(bad),
            "seconds": parts["seconds"],
            "export": str(path),
        },
    )
    res.note(f"{parts['seconds']}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="decoder_audit",
        category="report",
        title="mod.decoder_audit.title",
        summary="mod.decoder_audit.summary",
        params=[
            Param(key="databases", label="Bazy do audytu", default=list(DEFAULT_DATABASES), kind=LIST),
            Param(key="limit", label="Limit tabel", default=0, kind=INT, help="0 = wszystkie"),
            Param(key="magic", label="Sprawdź libmagic", default=True, kind=BOOL),
        ],
        run=run,
    )
)
