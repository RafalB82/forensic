# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""What was deleted from this filesystem, and what of it can still be read.

The coverage report in ``tsk_crosscheck`` counts what this tool cannot see: 51 924
unlinked directory entries and 752 047 unallocated inodes.  This module turns
the second of those into a list with dates and sizes, and is honest about the
limit that stops there.

**A free inode is not a deleted file.**  Of the free inodes on the reference
image, 784 829 were never allocated at all.  Calling those "deleted" would
roughly double the number and mean nothing.  ``i_dtime`` is what separates them:
the kernel stamps it on unlink and leaves it zero otherwise, so this is a test
rather than an inference.

**Names are not in inodes.**  An unlinked entry no longer appears in any
directory, so the name survives only in whatever directory block still holds the
old bytes.  Recovering it is carving, not enumeration, and this module does not
pretend otherwise — every record says so in its own ``name_source`` field.

**The content is gone from the inode too.**  On the reference image a deleted
inode keeps ``i_size`` and ``i_dtime`` but has ``i_blocks = 0`` and an empty
extent map, because ext4 truncates the block map on unlink.  The bytes of a
deleted file therefore cannot be located through its inode at all; they can only
be found by walking unallocated block space, which is a separate piece of work
and is reported here as not done rather than assumed.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from ...core.export import human_bytes
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, INT, ModuleSpec, Param, register


def _ts_key(value: str) -> str:
    return value[:4] if value and value[0].isdigit() else "?"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("deleted_files")
    started = time.time()
    fs = ctx.fs()
    cap = max(0, int(params.get("limit") or 0))
    counted = bool(params.get("count_all", True))

    free_total = fs.free_inode_count()
    declared = fs.superblock.get("free_inodes", 0)
    if counted:
        deleted_total = fs.deleted_inode_count()
    else:
        deleted_total = -1
    with_data = fs.deleted_inodes(with_data_only=True)

    kinds: Counter = Counter()
    years: Counter = Counter()
    owners: Counter = Counter()
    total_bytes = 0
    for entry in with_data:
        kinds[entry["kind"]] += 1
        years[_ts_key(entry["dtime_utc"])] += 1
        owners[entry["uid"]] += 1
        total_bytes += entry["size"]

    # How much of it is actually reachable.  Every one of these has an empty
    # extent map, so the answer is a flat "no" — and saying so per record is the
    # point, because a list of 378 files with plausible sizes reads as a
    # recovery list unless the module states that the bytes are unreachable.
    reachable = 0
    verdicts: Counter = Counter()
    for entry in with_data[:200]:
        verdict = fs.recoverability(entry["inode"])
        verdicts[verdict["verdict"].split(" — ")[0]] += 1
        if verdict.get("recoverable"):
            reachable += 1

    parts: dict[str, Any] = {
        "free_inodes_bitmap": free_total,
        "free_inodes_superblock": declared,
        "free_inodes_delta": free_total - declared,
        "never_allocated_estimate": (free_total - deleted_total) if deleted_total >= 0 else None,
        "deleted_total": deleted_total,
        "with_stated_size": len(with_data),
        "with_stated_bytes": total_bytes,
        "with_stated_human": human_bytes(total_bytes),
        "kinds": dict(kinds),
        "deletion_years": dict(sorted(years.items())),
        "uids": {str(uid): count for uid, count in owners.most_common(10)},
        "recoverability_sampled": len(with_data[:200]),
        "recoverable_sampled": reachable,
        "verdicts": dict(verdicts),
        "names_recovered": 0,
        "names_source": "brak — nazwy nie są w inodach; potrzeba carve z bloków katalogów",
        "content_source": "brak — i_blocks i mapa extentów są wyczyszczone przy unlink",
    }
    if cap:
        parts["detail"] = with_data[:cap]
    else:
        parts["detail"] = with_data[:50]

    res.add(
        "ok",
        f"Usunięte inody: {deleted_total if deleted_total >= 0 else len(with_data)}"
        + (" z 1 536 876 wolnych" if declared else "")
        + f", z zachowanym rozmiarem {len(with_data)} ({human_bytes(total_bytes)})",
        detail=(
            f"wolne inody: {free_total} z bitmapy wobec {declared} z superbloku "
            f"(różnica {free_total - declared} — kernel rezerwuje kilka dla journalu); "
            f"z nich szacunkowo {free_total - deleted_total if deleted_total >= 0 else '?'} "
            "nigdy nie przydzielonych, więc nie są usuniętymi plikami"
        ),
        values={
            "deleted_total": deleted_total,
            "free_inodes": free_total,
            "free_inodes_delta": free_total - declared,
            "with_stated_size": len(with_data),
            "with_stated_bytes": total_bytes,
            "kinds": dict(kinds),
        },
    )
    res.add(
        "info",
        f"Rozmiar wskazany przez {len(with_data)} usuniętych inodów: {human_bytes(total_bytes)}",
        detail="; ".join(f"{year}: {count}" for year, count in sorted(years.items())),
        values={"years": dict(sorted(years.items())), "bytes": total_bytes},
    )
    res.add(
        "warn",
        "Treści usuniętych plików są nieosiągalne przez inody",
        detail=(
            "sprawdzone na próbce: wszystkie mają i_blocks = 0 i pustą mapę extentów — "
            "ext4 czyści mapę bloków przy unlink, więc bajtów nie da się wskazać. "
            "Odzyskanie wymaga przejścia przestrzeni nieprzydzielonej (krok 2), "
            "a nazwy — wyrzeźbienia z bloków katalogów. Żadne z tych dwóch nie jest zrobione."
        ),
        values={
            "sampled": parts["recoverability_sampled"],
            "recoverable": reachable,
            "verdicts": dict(verdicts),
        },
    )
    res.data = parts
    from ...core.export import to_csv, to_json

    res.export(to_json(ctx.work("exports") / "deleted_inodes.json", parts))
    res.export(
        to_csv(
            ctx.work("exports") / "deleted_inodes.csv",
            ["inode", "kind", "size", "mode", "uid", "gid", "links", "blocks_512",
             "dtime_utc", "mtime_utc", "ctime", "name", "name_source"],
            [
                [
                    item["inode"], item["kind"], item["size"], item["mode"],
                    item["uid"], item["gid"], item["links"], item["blocks_512"],
                    item["dtime_utc"], item["mtime_utc"], item["ctime"],
                    item["name"], item["name_source"],
                ]
                for item in with_data
            ],
            ctx.masker,
        )
    )
    res.note(f"{round(time.time() - started, 1)}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="deleted_files",
        category="image",
        title="mod.deleted_files.title",
        summary="mod.deleted_files.summary",
        params=[
            Param(key="limit", label="Limit wpisów", default=50, kind=INT),
            Param(key="count_all", label="Policz wszystkie", default=True, kind=BOOL),
        ],
        run=run,
    )
)
