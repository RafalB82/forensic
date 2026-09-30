# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Search the whole image for a byte pattern and report where it lives.

Literals use the C-level ``bytes.find`` in overlapping windows, so a 27 GB image
scans in about a minute; regular expressions fall back to a slower windowed
``re`` loop.  Each hit is reported with a hexdump context and, when a block
index is cached, with the owning file and the offset inside that file.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from ...core import i18n
from ...core.export import human_bytes, to_csv, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, INT, ModuleSpec, Param, register

WINDOW = 8 * 1024 * 1024
OVERLAP = 1024


def hexdump(data: bytes, base_offset: int, width: int = 16, redact: bytes = b"") -> str:
    """Classic hexdump with absolute image offsets; ``redact`` bytes become '?'."""
    lines = []
    for index in range(0, len(data), width):
        chunk = data[index : index + width]
        shown = chunk
        if redact:
            for start in range(0, max(len(chunk) - len(redact) + 1, 0)):
                window = chunk[start : start + len(redact)]
                if window == redact[: len(window)]:
                    shown = shown[:start] + b"?" * len(window) + shown[start + len(window) :]
        hexpart = " ".join(f"{b:02x}" for b in shown)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in shown)
        lines.append(f"{base_offset + index:012d}  {hexpart:<{width * 3}} |{text}|")
    return "\n".join(lines)


def redact_bytes(data: bytes, needle: bytes) -> bytes:
    if not needle:
        return data
    return data.replace(needle, b"?" * len(needle))


def search_bytes(
    path: Path,
    needle: bytes,
    max_hits: int,
    pattern_re: bool,
    progress=None,
    start: int = 0,
    end: int | None = None,
) -> list[int]:
    """Return sorted image offsets where the pattern occurs, optionally in a range."""
    hits: list[int] = []
    overlap = max(OVERLAP, 4096)
    limit = end if end is not None else path.stat().st_size
    with open(path, "rb") as handle:
        handle.seek(start)
        base = start
        carry = b""
        while base < limit:
            block = handle.read(min(WINDOW, limit - base))
            if not block:
                break
            window = carry + block
            window_base = base - len(carry)
            if pattern_re:
                for match in re.finditer(needle, window):
                    hits.append(window_base + match.start())
                    if len(hits) >= max_hits:
                        return sorted(set(hits))
            else:
                position = window.find(needle)
                while position != -1:
                    hits.append(window_base + position)
                    if len(hits) >= max_hits:
                        return sorted(set(hits))
                    position = window.find(needle, position + 1)
            base += len(block)
            carry = window[-overlap:]
            if progress is not None:
                progress(min(base, limit), limit)
    return sorted(set(hits))


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("find_string")
    image = ctx.image
    raw_pattern = str(params.get("pattern", ""))
    if not raw_pattern:
        res.add("warn", i18n.t("common.warning"), detail="param.pattern")
        return ctx.record(res)
    use_regex = bool(params.get("regex", False)) or (
        raw_pattern.startswith("/") and raw_pattern.endswith("/") and len(raw_pattern) > 2
    )
    if use_regex and raw_pattern.startswith("/") and raw_pattern.endswith("/"):
        raw_pattern = raw_pattern[1:-1]
    context = int(params.get("context", 64) or 0)
    max_hits = int(params.get("max_hits", 50) or 0) or 50
    pattern = raw_pattern.encode("utf-8", "surrogateescape")
    if use_regex:
        try:
            re.compile(pattern)
        except re.error as exc:
            res.add("critical", "Nieprawidłowe wyrażenie regularne", detail=str(exc))
            return ctx.record(res)
    start_offset = int(params.get("start", 0) or 0)
    end_offset = params.get("end")
    end_offset = int(end_offset) if end_offset not in (None, "") else None
    started = time.time()
    state = {"last": 0.0}

    def progress(done: int, total: int) -> None:
        now = time.time()
        if now - state["last"] > 2.0:
            state["last"] = now
            percent = done / max(total, 1) * 100
            ctx.log(f"{human_bytes(done)} / {human_bytes(total)} ({percent:.0f}%)")

    ctx.log(f"Szukam: {raw_pattern}")
    hits = search_bytes(
        image, pattern, max_hits, use_regex, progress=progress, start=start_offset, end=end_offset
    )
    elapsed = time.time() - started
    res.add(
        "ok" if hits else "info",
        f"{i18n.t('msg.hits')}: {len(hits)}",
        values={
            "pattern": raw_pattern,
            "regex": use_regex,
            "image": str(image),
            "image_size": human_bytes(image.stat().st_size),
            "scanned_seconds": round(elapsed, 1),
            "max_hits": max_hits,
            "truncated": len(hits) >= max_hits,
            "start": start_offset,
            "end": end_offset,
        },
    )
    masker = ctx.masker
    index = None
    try:
        from .blockmap import cache_path
        from ...core.blockmap import BlockIndex

        cache = cache_path(ctx)
        if cache.exists():
            index = BlockIndex.load(str(cache))
    except Exception:
        index = None
    rows = []
    with open(image, "rb") as handle:
        for hit in hits:
            handle.seek(max(hit - context, 0))
            window = handle.read(context * 2 + len(pattern))
            shown_window = window if masker.reveal else redact_bytes(window, pattern)
            row = {
                "offset": hit,
                "hex": hex(hit),
                "context_bytes": shown_window.hex(),
                "path": None,
                "file_offset": None,
            }
            if index is not None:
                owner = index.lookup(hit)
                if owner is not None:
                    row["path"] = owner.path
                    row["file_offset"] = owner.file_offset + (hit % index.block_size)
            rows.append(row)
            res.add(
                "finding",
                f"offset {hit} ({human_bytes(hit)})",
                detail=row["path"] or "",
                values={
                    "offset": hit,
                    "path": row["path"],
                    "file_offset": row["file_offset"],
                    "hexdump": hexdump(
                        window, max(hit - context, 0), redact=b"" if masker.reveal else pattern
                    ),
                },
            )
    if elapsed > 1:
        throughput = image.stat().st_size / max(elapsed, 0.001) / 2**20
        res.note(f"prędkość skanowania {throughput:.0f} MiB/s")
    csv_path = to_csv(
        ctx.work("exports") / "find_string.csv",
        ["offset", "offset_hex", "path", "file_offset", "context_bytes"],
        [
            [r["offset"], r["hex"], r["path"] or "", r["file_offset"] or "", r["context_bytes"]]
            for r in rows
        ],
        ctx.masker,
    )
    res.export(csv_path)
    res.export(
        to_json(
            ctx.work("exports") / "find_string.json",
            {
                "pattern": raw_pattern,
                "regex": use_regex,
                "image": str(image),
                "scanned_seconds": round(elapsed, 1),
                "indexed": index is not None,
                "hits": rows,
            },
            ctx.masker,
        )
    )
    return ctx.record(res)


register(
    ModuleSpec(
        id="find_string",
        category="tools",
        title="mod.find_string.title",
        summary="mod.find_string.summary",
        params=[
            Param(key="pattern", label="param.pattern", default="", kind="str"),
            Param(key="regex", label="param.regex", default=False, kind=BOOL),
            Param(key="context", label="param.context", default=64, kind=INT),
            Param(key="max_hits", label="param.max_hits", default=50, kind=INT),
            Param(key="start", label="Początek zakresu (offset)", default=0, kind=INT),
            Param(key="end", label="Koniec zakresu (offset)", default=0, kind=INT),
        ],
        run=run,
    )
)
