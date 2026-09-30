# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Read-only SQLite helpers: header, integrity, tables, companion files."""

from __future__ import annotations

import sqlite3
import struct
from pathlib import Path
from typing import Any, Literal, overload

from .readlog import PRESENT, UNREADABLE

SIDE_CARS = ("-wal", "-shm", "-journal")
BTREE_LEAF_TABLE = 0x0D
BTREE_INTERIOR_TABLE = 0x05
BTREE_LEAF_INDEX = 0x0A
BTREE_INTERIOR_INDEX = 0x02
PAGE_HEADER_OFFSET = 100
HEADER_MAGIC = b"SQLite format 3\0"


def sidecars(path: str | Path) -> dict[str, dict]:
    """Existing companion files next to a database."""
    path = Path(path)
    out: dict[str, dict] = {}
    for suffix in SIDE_CARS:
        candidate = Path(str(path) + suffix)
        if candidate.exists():
            stat = candidate.stat()
            out[suffix] = {"path": str(candidate), "size": stat.st_size, "mtime": stat.st_mtime}
    return out


def header(path: str | Path) -> dict:
    """Parse the first 100 bytes of a SQLite file without opening it."""
    path = Path(path)
    with open(path, "rb") as handle:
        raw = handle.read(100)
    out: dict[str, Any] = {"path": str(path), "size": path.stat().st_size}
    if not raw.startswith(HEADER_MAGIC):
        out["is_sqlite"] = False
        return out
    page_size = struct.unpack_from(">H", raw, 16)[0]
    out.update(
        {
            "is_sqlite": True,
            "page_size": 65536 if page_size == 1 else page_size,
            "write_version": raw[18],
            "read_version": raw[19],
            "reserved": raw[20],
            "text_encoding": {0: "0 (unset)", 1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}.get(raw[56], raw[56]),
            "user_version": struct.unpack_from(">I", raw, 60)[0],
            "application_id": struct.unpack_from(">I", raw, 68)[0],
            "schema_cookie": struct.unpack_from(">I", raw, 40)[0],
            "freelist_pages": struct.unpack_from(">I", raw, 36)[0],
            "freelist_records": struct.unpack_from(">I", raw, 32)[0],
            "page_count": struct.unpack_from(">I", raw, 28)[0],
            "journal_mode_wal": raw[18] == 2 or raw[19] == 2,
            "integrity_header": raw[96:100].hex(),
        }
    )
    out["page_count_real"] = -(-out["size"] // max(out["page_size"], 1))
    return out


def connect(path: str | Path, immutable: bool = False) -> sqlite3.Connection:
    """Open a database read-only.

    The path goes through ``as_uri()`` because a SQLite URI is parsed as a URI:
    a ``#`` in the name would otherwise start a fragment, a ``?`` would start
    the query, and a ``%`` would start an escape — all three silently point the
    open at a different file than the one asked for.  Extracted evidence keeps
    the names it had inside the image, and an Android app package or a database
    file may well contain those characters.
    """
    target = Path(path).resolve()
    uri = target.as_uri() + "?mode=ro"
    if immutable:
        uri += "&immutable=1"
    return sqlite3.connect(uri, uri=True, timeout=10)


def integrity(conn: sqlite3.Connection, limit: int = 20) -> tuple[str, list[str]]:
    """Run PRAGMA integrity_check, returning (status, first N messages)."""
    try:
        rows = conn.execute("PRAGMA integrity_check").fetchmany(limit)
    except Exception as exc:  # pragma: no cover - defensive
        return f"error: {exc}", []
    messages = [str(row[0]) for row in rows]
    status = messages[0] if messages else "empty"
    return status, messages


def tables(conn: sqlite3.Connection) -> list[str]:
    return [
        row[0]
        for row in conn.execute(
            "select name from sqlite_master where type='table' order by name"
        )
    ]


def objects(conn: sqlite3.Connection) -> dict[str, int]:
    out: dict[str, int] = {}
    for kind in ("table", "index", "view", "trigger"):
        out[kind] = conn.execute(
            "select count(*) from sqlite_master where type=?", (kind,)
        ).fetchone()[0]
    return out


def columns(conn: sqlite3.Connection, table: str) -> list[tuple]:
    quoted = '"' + table.replace('"', '""') + '"'
    return [(row[1], row[2]) for row in conn.execute(f"pragma table_info({quoted})")]


def count_rows(conn: sqlite3.Connection, table: str, limit: int = 5_000_000) -> int | None:
    """Rows in ``table``, or ``None`` when the count could not be read.

    ``None`` and not ``-1``, because the caller filters on truthiness:
    ``non_empty_tables = {k: v for k, v in counts.items() if v}`` treats ``-1`` as
    a count and puts a table we could not read into the list of tables that have
    something in them.  A failure would then be reported as evidence of content.
    """
    quoted = '"' + table.replace('"', '""') + '"'
    try:
        return int(conn.execute(f"select count(*) from {quoted}").fetchone()[0])
    except Exception:
        return None


def peek(conn: sqlite3.Connection, table: str, limit: int = 5) -> list[tuple]:
    """Up to ``limit`` rows of ``table``; empty list when it cannot be read.

    The emptiness is ambiguous on its own — it is the same value an empty table
    gives — so callers that care must ask :func:`count_rows` for the same table
    and check for ``None``.  :func:`quicklook` does exactly that, which is why
    this function can stay a plain list without lying to anybody.
    """
    quoted = '"' + table.replace('"', '""') + '"'
    try:
        return conn.execute(f"select * from {quoted} limit ?", (limit,)).fetchall()
    except Exception:
        return []


def row_counts(conn: sqlite3.Connection, limit: int = 200) -> dict[str, int | None]:
    out: dict[str, int | None] = {}
    for table in tables(conn)[:limit]:
        out[table] = count_rows(conn, table)
    return out


def quicklook(path: str | Path, top_tables: int = 12, sample: int = 3) -> dict:
    """Everything a first-pass report needs from one database file.

    Carries a ``status`` of ``PRESENT`` or ``UNREADABLE`` — a caller that wants
    the third state from this vocabulary asks for the path first, because a file
    that is not there is not something this function can open.  The counts that
    came back as ``None`` are named in ``unreadable_tables`` instead of being
    folded into ``non_empty_tables``, which is where a truthy sentinel used to
    put them.
    """
    path = Path(path)
    report: dict[str, Any] = {
        "file": str(path),
        "status": UNREADABLE,
        "header": header(path),
        "companions": sidecars(path),
    }
    if not report["header"].get("is_sqlite"):
        report["error"] = "not a SQLite database"
        return report
    try:
        conn = connect(path)
    except Exception as exc:
        report["error"] = str(exc)
        return report
    try:
        status, messages = integrity(conn)
        report["integrity"] = status
        report["integrity_messages"] = messages
        report["objects"] = objects(conn)
        report["tables"] = tables(conn)
        counts = row_counts(conn)
        unreadable = [name for name, value in counts.items() if value is None]
        report["row_counts"] = counts
        report["unreadable_tables"] = unreadable
        report["non_empty_tables"] = {
            name: value for name, value in counts.items() if value
        }
        readable = [name for name, value in counts.items() if value is not None]
        report["samples"] = {
            table: peek(conn, table, sample) for table in readable[:top_tables]
        }
        report["columns"] = {
            table: columns(conn, table) for table in readable[:top_tables]
        }
        # A database whose every table failed to count has been read as much as
        # this function manages, and what came back is not an account of it.
        report["status"] = UNREADABLE if len(unreadable) == len(counts) and counts else PRESENT
    finally:
        conn.close()
    return report


def is_wal(path: str | Path) -> bool:
    return Path(str(path) + "-wal").exists()


def varint(buf: bytes, index: int) -> tuple[int, int]:
    """Read a SQLite variable-length integer; returns (value, next index)."""
    value = 0
    for step in range(9):
        byte = buf[index + step]
        if step == 8:
            return (value << 8) | byte, index + 9
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            return value, index + step + 1
    return value, index + 9


def decode_record(payload: bytes) -> list:
    """Decode one SQLite record body into a list of Python values."""
    try:
        header_len, cursor = varint(payload, 0)
    except IndexError:
        return []
    types: list[int] = []
    while cursor < header_len and cursor < len(payload):
        serial, cursor = varint(payload, cursor)
        types.append(serial)
    values: list = []
    cursor = header_len
    for serial in types:
        if serial == 0:
            values.append(None)
        elif serial <= 6:
            sizes = (0, 1, 2, 3, 4, 6, 8)
            size = sizes[serial]
            values.append(int.from_bytes(payload[cursor : cursor + size], "big", signed=True))
            cursor += size
        elif serial == 7:
            import struct

            values.append(struct.unpack(">d", payload[cursor : cursor + 8])[0])
            cursor += 8
        elif serial == 8:
            values.append(0)
        elif serial == 9:
            values.append(1)
        elif serial >= 13 and serial % 2 == 1:
            length = (serial - 13) // 2
            values.append(payload[cursor : cursor + length].decode("utf-8", "replace"))
            cursor += length
        else:
            length = (serial - 12) // 2
            values.append(payload[cursor : cursor + length])
            cursor += length
    return values


@overload
def leaf_rows(
    page: bytes, usable: int | None = ..., with_overflow: Literal[False] = ..., with_rowid: bool = ...
) -> list[Any]: ...


@overload
def leaf_rows(
    page: bytes, usable: int | None, with_overflow: Literal[True], with_rowid: bool = ...
) -> tuple[list[Any], int]: ...


@overload
def leaf_rows(
    page: bytes, usable: int | None, with_overflow: bool, with_rowid: bool = ...
) -> list[Any] | tuple[list[Any], int]: ...


def leaf_rows(
    page: bytes,
    usable: int | None = None,
    with_overflow: bool = False,
    with_rowid: bool = False,
) -> list[Any] | tuple[list[Any], int]:
    """Rows stored in one b-tree leaf page (table leaf, type 0x0D).

    Pages 1 and the root of a page have a 100 byte database header first; the
    caller decides by passing a page already stripped of it.

    With ``with_overflow`` the return value is ``(rows, overflow_count)``.  A row
    whose payload does not fit the page keeps only the local prefix, so its text
    and blob columns come back truncated — a caller comparing values against
    another implementation needs to know which rows those are, or it will
    report a mismatch that is really just a value it cannot see.

    With ``with_rowid`` each row becomes a ``(rowid, values)`` pair, in key order
    within the page.  Carrying the rowid is what lets a caller line its output up
    against ``select * from t`` instead of hoping the two traversals agree.
    """
    if not page or page[0] != BTREE_LEAF_TABLE:
        return ([], 0) if with_overflow else []
    count = int.from_bytes(page[3:5], "big")
    rows: list = []
    overflow = 0
    for cell in range(count):
        pointer_at = 8 + cell * 2
        if pointer_at + 2 > len(page):
            break
        offset = int.from_bytes(page[pointer_at : pointer_at + 2], "big")
        if not 0 < offset < len(page):
            continue
        try:
            payload_len, cursor = varint(page, offset)
            rowid, cursor = varint(page, cursor)
            if usable and payload_len > usable - 35:
                local = ((usable - 12) * 32 // 255) - 23
            else:
                local = payload_len
            if local < payload_len:
                overflow += 1
            values = decode_record(page[cursor : cursor + local])
            rows.append((rowid, values) if with_rowid else values)
        except (IndexError, ValueError):
            continue
    return (rows, overflow) if with_overflow else rows


def walk_table(
    path: str | Path,
    root: int,
    page_size: int,
    usable: int,
    page_count: int | None = None,
) -> dict:
    """Walk one table b-tree and decode every record it holds.

    This exists so the decoder above can be *checked* rather than trusted.
    :func:`leaf_rows` is a hand-written reimplementation of SQLite's record
    format, written by the same author as the report that cites it, and nothing
    in the project ever compared its output against the reference
    implementation.  Given a database, it now can be.

    The interior-page cell pointer array holds **byte offsets within the
    page**, not page numbers — the child page number is the first four bytes of
    each cell.  Confusing the two is the classic mistake here and it produces
    child page numbers larger than the file, which then look like corruption
    rather than like a bug in the reader.

    Index pages are counted but their records are not returned: an index row is
    a key, not a table row, and summing the two would double-count every row of
    an indexed table.  Virtual tables (``rootpage == 0``, e.g. FTS5) have no
    b-tree of their own; their rows live in shadow tables and are reported as
    ``virtual`` rather than counted as missing.

    Rows come back in ascending rowid order, which is the order
    ``select * from t`` produces, so a caller can compare them one for one
    instead of comparing multisets and hoping.  A depth-first walk that pops the
    right-most child first produces the same rows in the opposite order — counts
    still match, values do not, and it looks like a decoding bug.
    """
    blob = Path(str(path)).read_bytes()
    pages_total = page_count if page_count is not None else len(blob) // page_size

    def page(number: int) -> bytes:
        if number < 1 or number > pages_total:
            return b""
        return blob[(number - 1) * page_size : number * page_size]

    records: list[tuple] = []
    leaves = interiors = index_pages = 0
    overflow_rows = 0
    overflow_at: set[int] = set()
    problems: list[dict] = []
    if root == 0:
        return {
            "root": 0, "records": 0, "leaves": 0, "interiors": 0, "index_pages": 0,
            "overflow_rows": 0, "overflow_at": set(), "rows": [], "problems": [], "virtual": True,
        }
    stack = [root]
    visited: set[int] = set()
    while stack:
        number = stack.pop()
        if number in visited:
            problems.append({"page": number, "issue": "odwiedzona dwukrotnie"})
            continue
        visited.add(number)
        data = page(number)
        if not data:
            problems.append({"page": number, "issue": "poza końcem pliku"})
            continue
        kind = data[0]
        if kind == BTREE_LEAF_TABLE:
            leaves += 1
            rows, spilled = leaf_rows(
                data, usable, with_overflow=True, with_rowid=True
            )
            overflow_rows += spilled
            overflow_at.update(range(len(records), len(records) + spilled))
            records.extend(rows)
            continue
        if kind in (BTREE_INTERIOR_TABLE, BTREE_INTERIOR_INDEX):
            if kind == BTREE_INTERIOR_INDEX:
                index_pages += 1
            else:
                interiors += 1
            count = int.from_bytes(data[3:5], "big")
            # Stos: right-most wchodzi pierwszy, dzieci w kolejności odwrotnej,
            # żeby pop() dawał lewego syna jako pierwszego — czyli rósł po rowid.
            stack.append(int.from_bytes(data[8:12], "big"))
            for cell in reversed(range(count)):
                at = 12 + cell * 2
                if at + 2 > len(data):
                    break
                offset = int.from_bytes(data[at : at + 2], "big")
                if not 0 < offset < len(data) - 4:
                    problems.append({"page": number, "issue": f"zły wskaźnik komórki {offset}"})
                    continue
                stack.append(int.from_bytes(data[offset : offset + 4], "big"))
            continue
        if kind == BTREE_LEAF_INDEX:
            index_pages += 1
            continue
        problems.append({"page": number, "issue": f"nieznany typ strony 0x{kind:02X}"})
    order = sorted(range(len(records)), key=lambda i: records[i][0])
    records = [records[i] for i in order]
    overflow_at = {order.index(i) for i in overflow_at if i in order}
    ascending = all(
        records[i][0] <= records[i + 1][0] for i in range(len(records) - 1)
    )
    return {
        "root": root,
        "records": len(records),
        "leaves": leaves,
        "interiors": interiors,
        "index_pages": index_pages,
        "overflow_rows": overflow_rows,
        "overflow_at": overflow_at,
        "rows": [values for _rowid, values in records],
        "rowids": [rowid for rowid, _values in records],
        "ascending": ascending,
        "problems": problems[:10],
        "virtual": False,
    }
