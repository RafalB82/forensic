# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""SQLite rollback journal reader, tolerant of a wiped header.

A rollback journal normally starts with a 28 byte header (magic
``d9 d5 05 f9 20 a1 63 d7``) followed by a page-number array and then one frame
per modified page: 4 byte page number, ``page_size`` bytes of data, 4 byte
checksum.  When a process dies or a filesystem goes dirty the header can be zeroed
while the frames survive, which is exactly the case in the reference image, so
this module also reconstructs the frame table heuristically.

Two products come out of a journal:

* every **record** stored in its pages (works even when the page table is gone)
* a **rolled-back copy** of the database, when the frame set is self-consistent
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path

from .sqlite_tools import leaf_rows

JOURNAL_MAGIC = bytes([0xD9, 0xD5, 0x05, 0xF9, 0x20, 0xA1, 0x63, 0xD7])
HEADER_SIZE = 28
DEFAULT_SECTOR = 512
DEFAULT_PAGE = 4096
FRAME_OVERHEAD = 8


@dataclass
class Frame:
    """One journal frame."""

    index: int
    offset: int
    page: int
    data: bytes
    checksum_ok: bool | None = None

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class JournalInfo:
    """Parsed journal header plus the frame table."""

    path: str
    size: int
    header_valid: bool
    header: dict = field(default_factory=dict)
    frames: list[Frame] = field(default_factory=list)
    sector_size: int = DEFAULT_SECTOR
    page_size: int = DEFAULT_PAGE
    checksum_init: int | None = None
    db_pages: int | None = None
    trailing: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def frame_count(self) -> int:
        return len(self.frames)

    @property
    def pages(self) -> list[int]:
        return [frame.page for frame in self.frames]

    def summary(self) -> dict:
        return {
            "path": self.path,
            "size": self.size,
            "header_valid": self.header_valid,
            "frames": self.frame_count,
            "page_size": self.page_size,
            "sector_size": self.sector_size,
            "db_pages_in_header": self.db_pages,
            "checksum_init": self.checksum_init,
            "trailing_bytes": self.trailing,
            "notes": self.notes,
        }


def _checksum(data: bytes, init: int) -> int:
    """SQLite pager checksum, sampled every 200 bytes from the end."""
    value = init
    index = len(data) - 200
    while index > 0:
        value = (value + data[index]) & 0xFFFFFFFF
        index -= 200
    return value


def read_header(path: Path) -> tuple[dict, bool]:
    """Parse the 28 byte journal header; ``valid`` is False when it is zeroed."""
    with open(path, "rb") as handle:
        raw = handle.read(HEADER_SIZE)
    if len(raw) < HEADER_SIZE:
        return {"truncated": True}, False
    if raw[:8] != JOURNAL_MAGIC:
        zeroed = all(byte == 0 for byte in raw)
        return {
            "magic": raw[:8].hex(),
            "zeroed": zeroed,
            "raw": raw.hex(),
        }, False
    records, checksum_init, db_pages, sector_size, page_size = struct.unpack(">IIIII", raw[8:28])
    return (
        {
            "magic": raw[:8].hex(),
            "records": records,
            "checksum_init": checksum_init,
            "db_pages": db_pages,
            "sector_size": sector_size,
            "page_size": page_size or DEFAULT_PAGE,
            "zeroed": False,
        },
        True,
    )


def inspect(path: str | Path) -> JournalInfo:
    """Describe a journal and build its frame table, with or without a header."""
    path = Path(path)
    size = path.stat().st_size
    header, valid = read_header(path)
    info = JournalInfo(path=str(path), size=size, header_valid=valid, header=header)
    if valid:
        info.sector_size = int(header.get("sector_size") or DEFAULT_SECTOR)
        info.page_size = int(header.get("page_size") or DEFAULT_PAGE)
        info.checksum_init = header.get("checksum_init")
        info.db_pages = header.get("db_pages")
        records = int(header.get("records") or 0)
        if records == 0xFFFFFFFF:
            records = _frames_from_size(size, info.sector_size, info.page_size)
        info.frames = _read_frames(path, info, records, info.sector_size)
        if not info.frames:
            info.notes.append("nagłówek poprawny, ale nie znaleziono klatek")
    else:
        if header.get("zeroed"):
            info.notes.append(
                "nagłówek journala wyzerowany — rekonstrukcja ramek heurystyczna"
            )
        else:
            info.notes.append(f"nagłówek nierozpoznany: {header.get('magic')}")
        page_size = _guess_page_size(path, info)
        info.page_size = page_size
        records = _frames_from_size(size, info.sector_size, page_size)
        info.frames = _read_frames(path, info, records, info.sector_size)
        if records:
            info.notes.append(
                f"rozpoznano {records} ramek po {_frames_from_size(size, info.sector_size, page_size)} "
                f"obliczeniach przy page_size={page_size}"
            )
    if info.frames:
        last = info.frames[-1]
        info.trailing = size - (last.offset + FRAME_OVERHEAD + last.size)
    return info


def _frames_from_size(size: int, sector_size: int, page_size: int) -> int:
    frame = page_size + FRAME_OVERHEAD
    if frame <= 0 or size <= sector_size:
        return 0
    return (size - sector_size) // frame


def _guess_page_size(path: Path, info: JournalInfo) -> int:
    """Pick the page size whose frame stride divides the file best."""
    size = path.stat().st_size
    best = DEFAULT_PAGE
    best_score = 0
    for page_size in (1024, 2048, 4096, 8192, 16384, 32768, 65536):
        frames = _frames_from_size(size, info.sector_size, page_size)
        if not frames:
            continue
        remainder = (size - info.sector_size) % (page_size + FRAME_OVERHEAD)
        if remainder == 0:
            return page_size
        if frames > best_score:
            best_score = frames
            best = page_size
    return best


def _read_frames(path: Path, info: JournalInfo, records: int, sector_size: int) -> list[Frame]:
    """Walk the frame table; page numbers come from the array or the frames."""
    page_size = info.page_size
    frame_size = page_size + FRAME_OVERHEAD
    offset = sector_size
    if info.header_valid:
        page_numbers = _read_page_number_array(path, info, records, sector_size, page_size)
    else:
        page_numbers = None
    frames: list[Frame] = []
    with open(path, "rb") as handle:
        for index in range(records):
            handle.seek(offset)
            raw = handle.read(frame_size)
            if len(raw) < frame_size:
                break
            page = struct.unpack(">I", raw[:4])[0]
            if page_numbers is not None and index < len(page_numbers):
                page = page_numbers[index]
            data = raw[4 : 4 + page_size]
            stored = struct.unpack(">I", raw[4 + page_size : 4 + page_size + 4])[0]
            ok: bool | None = None
            if info.checksum_init is not None:
                ok = _checksum(data, info.checksum_init) == stored
            frames.append(Frame(index=index, offset=offset, page=page, data=data, checksum_ok=ok))
            offset += frame_size
    return frames


def _read_page_number_array(
    path: Path, info: JournalInfo, records: int, sector_size: int, page_size: int
) -> list[int]:
    per_sector = max(sector_size // 4, 1)
    out: list[int] = []
    with open(path, "rb") as handle:
        handle.seek(sector_size)
        while len(out) < records:
            chunk = handle.read(sector_size)
            if not chunk:
                break
            values = struct.unpack(f">{len(chunk) // 4}I", chunk[: (len(chunk) // 4) * 4])
            out.extend(values)
            if len(values) < per_sector:
                break
    return out[:records]


def page_payload(frame: Frame, page_number_is_one: bool = True) -> bytes:
    """Strip the 100 byte database header from page 1 when needed."""
    if page_number_is_one and frame.page == 1:
        return bytes(frame.data[:PAGE0]) + frame.data[100:]
    return frame.data


PAGE0 = 100


def records(
    path: str | Path,
    info: JournalInfo | None = None,
    db_pages: int | None = None,
    unique: bool = True,
) -> list[list]:
    """All records found in the journal's leaf pages, in file order.

    A journal may contain the same page twice (the transaction rewrote it), so
    ``unique`` collapses identical rows; the raw count stays available in
    :func:`records_with_counts`.
    """
    rows, _counts = records_with_counts(path, info, db_pages, unique=unique)
    return rows


def records_with_counts(
    path: str | Path,
    info: JournalInfo | None = None,
    db_pages: int | None = None,
    unique: bool = True,
) -> tuple[list[list], dict]:
    """Records plus a small dictionary describing what was seen."""
    info = info or inspect(path)
    out: list[list] = []
    seen: set[tuple] = set()
    pages_used: set[int] = set()
    duplicates = 0
    for frame in info.frames:
        if frame.page == 0:
            continue
        if db_pages and frame.page > db_pages:
            continue
        payload = page_payload(frame)
        if not payload:
            continue
        pages_used.add(frame.page)
        for row in leaf_rows(payload):
            key = tuple(str(value) for value in row)
            if unique:
                if key in seen:
                    duplicates += 1
                    continue
                seen.add(key)
            out.append(row)
    return out, {
        "rows": len(out),
        "duplicates_collapsed": duplicates,
        "pages_with_records": len(pages_used),
        "frames": info.frame_count,
    }


def rows_as_dicts(path: str | Path, info: JournalInfo | None = None) -> list[list]:
    """Alias kept for readability at the call site."""
    return records(path, info)


def rollback(
    database: str | Path,
    journal: str | Path,
    output: str | Path,
    trust_pages: bool = True,
) -> dict:
    """Apply the journal's frames onto a copy of the database.

    ``trust_pages`` keeps frames whose page number exceeds the database size; that
    grows the output, which is what a database looked like *before* the
    transaction is usually needed for.
    """
    database = Path(database)
    journal = Path(journal)
    output = Path(output)
    info = inspect(journal)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(database.read_bytes())
    db_pages = -(-database.stat().st_size // info.page_size)
    written = 0
    skipped = 0
    with open(output, "r+b") as handle:
        for frame in info.frames:
            if frame.page == 0:
                continue
            if frame.page > db_pages and not trust_pages:
                skipped += 1
                continue
            handle.seek((frame.page - 1) * info.page_size)
            if frame.page > db_pages:
                handle.write(b"\0" * ((frame.page - db_pages) * info.page_size))
            handle.write(frame.data)
            written += 1
    result = {
        "output": str(output),
        "frames_total": info.frame_count,
        "frames_written": written,
        "frames_skipped": skipped,
        "database_pages": db_pages,
        "journal": info.summary(),
    }
    try:
        from .sqlite_tools import connect, integrity

        conn = connect(output)
        status, messages = integrity(conn)
        result["integrity"] = status
        result["integrity_messages"] = messages[:10]
        conn.close()
    except Exception as exc:
        result["integrity"] = f"unreadable: {exc}"
    return result
