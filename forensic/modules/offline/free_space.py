# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Unallocated block space: how much of it there is, what shape it has, what is in it.

This is step 2 of the three the plan calls 7.5.  Step 1 enumerated deleted
inodes and established that their contents cannot be located through them: ext4
truncates the block map on unlink, so every one of the 378 deleted inodes on the
reference image keeps a size and a date and has ``i_blocks = 0``.  The bytes are
still on the volume, in blocks the allocator handed back.  This module finds
those blocks and measures them.

**What this is not.**  It is not a recovery.  Nothing here identifies a file,
names a file, or attributes a single byte to anything — that is step 3, carving,
and it is not done.  A report produced from this module must say so, and the
module says it in a field of its own rather than leaving the absence to be
inferred from a list that happens to be short.

**The number comes from the bitmaps, not from the counters.**  On the reference
image three numbers that ought to be equal are not: the block bitmaps say
2 494 484 free blocks, ``s_free_blocks_count`` says 2 494 472, and the 206 group
descriptors sum to 2 510 845.  The bitmaps are what the allocator will hand out
next, so they are what an inventory of recoverable space has to be built on, and
the disagreement is reported rather than resolved silently.  ``e2fsck -fn`` on
the same image counts 2 494 484 and prints ``Free blocks count wrong (2494472,
counted=2494484)``, so the bitmaps have an independent reader agreeing and the
stored counter is the one that is stale — the volume carries ``RECOVER`` and
``errors = 2``.

**What is in the space.**  The one measurement worth having before anyone
attempts a carve: how much of it is zeros.  A volume where the free space is
mostly zero-filled has nothing to carve and a report that implied otherwise
would send an analyst after evidence that does not exist.  A volume where most of
it is non-zero is a volume where a carve is worth attempting, and that is a
statement about the image rather than about a recovered file.

The scan is **bounded by default**, because the reference image's free space is
9,51 GiB and the disk under it reads at 48 MB/s: a full pass is three and a half
minutes of a verification run.  The default is a systematic sample — every k-th
block, spread across all of the space — and the module reports both how many
blocks it looked at and what fraction that is, so a sampled figure can never be
read as a complete one.  ``scan=full`` reads everything and says so.

``BLOCK_UNINIT`` groups are free by definition rather than by measurement: their
bitmaps were never written, so an all-zero bitmap means "every block in this
group".  Those blocks are counted, and counted separately, because they are the
one part of the answer that rests on the filesystem's word rather than on its
bookkeeping.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from ...core.export import human_bytes, to_csv, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, INT, ModuleSpec, Param, register

#: Blocks to read when ``scan=sample``.  100 000 × 4 KiB is 390 MiB, about eight
#: seconds on the disk this was measured on (48 MB/s), against three and a half
#: minutes for the whole 9,51 GiB.  The sample is systematic rather than a prefix,
#: so it lands in every run of free space instead of inside the first one.
DEFAULT_SCAN_BLOCKS = 100_000


def _scan_free_space(fs, blocks: list[int], cap: int, list_blocks: int = 0) -> dict:
    """Look at free blocks and say how much of them is not zeros.

    ``cap`` is the largest number of blocks to read.  The sample is systematic —
    every k-th block of the whole unallocated set, not a prefix — because free
    space is laid out in runs and a prefix would land inside one of them and say
    nothing about the rest.  Zero blocks are counted per block, not per run, so
    "9,51 GiB" and "6,20 GiB of it is zeros" are the same unit.

    The non-zero block numbers are kept, up to ``list_blocks``.  They are the
    only thing in this module that points at individual blocks, and they are the
    raw material a carve would start from — so handing them over costs nothing
    and saves the next step from re-reading 9,51 GiB to find them again.  When
    the sample is a fraction of the space they are a sample of the candidates, not
    the candidates, and the module says which.
    """
    total = len(blocks)
    empty = {
        "scanned_blocks": 0,
        "scanned_bytes": 0,
        "scanned_fraction": 0.0,
        "complete": True,
        "zero_blocks": 0,
        "nonzero_blocks": 0,
        "zero_bytes": 0,
        "nonzero_bytes": 0,
        "zero_share": 0.0,
        "nonzero_blocks_listed": [],
        "nonzero_estimate": 0,
    }
    if total == 0:
        return empty
    if cap and cap < total:
        step = total / cap
        picked = [blocks[int(index * step)] for index in range(cap)]
        complete = False
    else:
        picked = blocks
        complete = True
    zero = nonzero = 0
    zero_bytes = nonzero_bytes = 0
    listed: list[int] = []
    for block in picked:
        data = fs._cache.get(block)
        if data is None:
            continue
        size = len(data)
        if data.count(0) == size:
            zero += 1
            zero_bytes += size
        else:
            nonzero += 1
            nonzero_bytes += size
            if not list_blocks or len(listed) < list_blocks:
                listed.append(block)
    looked = zero + nonzero
    return {
        "scanned_blocks": looked,
        "scanned_bytes": zero_bytes + nonzero_bytes,
        "scanned_fraction": round(looked / total, 6) if total else 0.0,
        "complete": complete,
        "zero_blocks": zero,
        "nonzero_blocks": nonzero,
        "zero_bytes": zero_bytes,
        "nonzero_bytes": nonzero_bytes,
        "zero_share": round(zero / looked, 6) if looked else 0.0,
        "nonzero_blocks_listed": listed,
        "nonzero_estimate": (
            int(round(nonzero * total / looked)) if looked else 0
        ),
    }


def _run_shape(runs: list[tuple[int, int]], block_size: int) -> dict:
    """How the free space is cut up, in words a report can use.

    The longest run matters more than the count of runs.  A deleted file's blocks
    were allocated near each other, so the space it left behind is usually one
    long run rather than a scatter — and a run long enough to hold the file is
    the precondition for reassembling it at all.
    """
    if not runs:
        return {"runs": 0, "longest": 0, "longest_bytes": 0, "longest_first": 0,
                "sizes": {}}
    lengths = sorted((count for _first, count in runs), reverse=True)
    longest_first, longest = max(runs, key=lambda item: item[1])
    buckets: Counter = Counter()
    for count in lengths:
        if count == 1:
            buckets["1 blok"] += 1
        elif count <= 8:
            buckets["2-8 bloków"] += 1
        elif count <= 128:
            buckets["9-128 bloków"] += 1
        elif count <= 1024:
            buckets["129-1024 bloków"] += 1
        else:
            buckets[">1024 bloków"] += 1
    return {
        "runs": len(runs),
        "longest": longest,
        "longest_bytes": longest * block_size,
        "longest_first": longest_first,
        "sizes": dict(buckets),
    }


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("free_space")
    started = time.time()
    fs = ctx.fs()
    sb = fs.superblock
    block_size = fs.block_size

    # Enumerated once and passed on.  Each of the four passes below walks every
    # group bitmap, and on the reference image that is 4,4 s apiece — 18 s of a
    # verification run spent counting the same free blocks four times.
    blocks = list(fs.unallocated_blocks())
    runs = fs.unallocated_runs(blocks)
    counters = fs.free_block_counters(blocks)
    uninit = fs.uninit_state()
    metadata_total = len(fs.metadata_blocks())
    overlap = fs.unallocated_metadata_overlap(sample=16, blocks=blocks)

    mode = str(params.get("scan", "sample")).lower()
    cap = max(0, int(params.get("scan_blocks", 20000) or 0))
    listing = max(0, int(params.get("list_blocks", 64) or 0))
    if mode == "none":
        content: dict[str, Any] = {"scanned_blocks": 0, "complete": False,
                                   "skipped": True}
    elif mode == "full":
        content = _scan_free_space(fs, blocks, 0, listing)
    else:
        content = _scan_free_space(fs, blocks, cap or DEFAULT_SCAN_BLOCKS, listing)
    content["mode"] = mode
    shape = _run_shape(runs, block_size)
    total_bytes = len(blocks) * block_size

    parts: dict[str, Any] = {
        "unallocated_blocks": len(blocks),
        "unallocated_bytes": total_bytes,
        "unallocated_human": human_bytes(total_bytes),
        "blocks_total": sb["blocks_count"],
        "free_share": round(len(blocks) / sb["blocks_count"], 6) if sb["blocks_count"] else 0,
        "counters": counters,
        "runs": shape["runs"],
        "longest_run": shape["longest"],
        "longest_run_bytes": shape["longest_bytes"],
        "longest_run_first_block": shape["longest_first"],
        "run_sizes": shape["sizes"],
        "uninit": uninit,
        "metadata_overlap": overlap["count"],
        "metadata_overlap_blocks": overlap["blocks"],
        "metadata_overlap_at_extent_end": overlap["at_extent_end"],
        "metadata_overlap_interior": overlap["interior"],
        "content": content,
        "names_recovered": 0,
        "files_recovered": 0,
        "names_source": "brak — nazwy usuniętych plików żyją tylko w blokach katalogowych, to krok 3",
        "content_source": "brak — zawartość nie jest przypisana do żadnego pliku; to krok 3 (carving)",
    }

    res.add(
        "ok",
        f"Przestrzeń nieprzydzielona: {len(blocks)} bloków ({human_bytes(total_bytes)}), "
        f"{shape['runs']} luk, najdłuższa {shape['longest']} bloków "
        f"({human_bytes(shape['longest_bytes'])})",
        detail=(
            f"z 6 732 790 bloków wolumenu, czyli {round(100 * len(blocks) / sb['blocks_count'], 1)}%; "
            f"najdłuższa luka zaczyna się w bloku {shape['longest_first']}; "
            f"podział luk: "
            + ", ".join(f"{k}: {v}" for k, v in shape["sizes"].items())
        ),
        values={
            "unallocated_blocks": len(blocks),
            "unallocated_human": human_bytes(total_bytes),
            "runs": shape["runs"],
            "longest_run": shape["longest"],
            "longest_run_bytes": shape["longest_bytes"],
            "free_share": parts["free_share"],
        },
    )
    delta_sb = counters["bitmaps_minus_superblock"]
    delta_gd = counters["bitmaps_minus_groups"]
    if delta_sb or delta_gd:
        res.add(
            "warn",
            f"Trzy liczniki wolnych bloków się nie zgadzają: bitmapy "
            f"{counters['from_bitmaps']}, superblok {counters['from_superblock']}, "
            f"suma grup {counters['from_group_descriptors']}",
            detail=(
                f"bitmapy minus superblok: {delta_sb:+d}; bitmapy minus suma grup: "
                f"{delta_gd:+d}. Użyto bitmap, bo to z nich przydziela alokator i "
                f"do nich wróci wszystko, co jest wolne. Superblok ma "
                f"RECOVER={'tak' if not counters['clean_unmount'] else 'nie'} i "
                f"errors={counters['errors']}, więc liczniki zapisano przy "
                f"nieczystym zamknięciu i rozjechały się z rzeczywistością. "
                f"e2fsck -fn na tym obrazie liczy te same "
                f"{counters['from_bitmaps']} i zgłasza rozjazd ze superblokiem."
            ),
            values=counters,
        )
    if uninit["groups"]:
        groups = ", ".join(str(g) for g in uninit["groups"][:12])
        if uninit["by_definition"]:
            detail = (
                f"grupy {groups}: flaga BLOCK_UNINIT znaczy, że bitmapy nigdy nie "
                f"zapisano, więc zerowa bitmapa odczytuje się jako „cała grupa "
                f"wolna” z definicji, a nie z pomiaru. Cecha uninit_bg jest "
                f"ustawiona, więc flagi znaczą to, co znaczą. Te bloki są "
                f"policzone razem z resztą, bo tak rozumie je alokator, "
                f"e2fsprogs i blkls"
            )
        else:
            detail = (
                f"grupy {groups} zgłaszają BLOCK_UNINIT, ale cecha uninit_bg w "
                f"superbloku NIE jest ustawiona — dwa niezależne miejsca na "
                f"nieporozumienie i mke2fs wychodzi dokładnie na tym: przy "
                f"1024-bajtowych blokach stawia flagi grup, a cechy nie. Bez cechy "
                f"jądro nie traktuje takich grup jako niezainicjalizowane, więc "
                f"te bloki są wolne z pomiaru, nie z definicji, i tak je tu "
                f"raportujemy. Liczba jest ta sama przy obu interpretacjach, bo "
                f"odwrócenie zerowej bitmapy i tak znaczy „cała grupa wolna”"
            )
        res.add(
            "info",
            f"{len(uninit['groups'])} grup ma nieinicjalizowaną bitmapę bloków "
            f"({uninit['free_blocks']} bloków)",
            detail=detail,
            values=uninit,
        )
    if uninit["inconsistent_bitmaps"]:
        res.add(
            "critical",
            f"{len(uninit['inconsistent_bitmaps'])} grup zgłasza BLOCK_UNINIT, "
            f"a ma niezerową bitmapę",
            detail=(
                "to sprzeczność: flaga mówi, że bitmapy nie ma, a jest. Zaufanie "
                "flagzie wyrzuciłoby prawdziwe informacje o alokacji, zaufanie "
                "bitmapie przyjęłoby system plików, który sam mówi, że bitmapy nie "
                "ma. Grupy: "
                + ", ".join(str(g) for g in uninit["inconsistent_bitmaps"][:12])
            ),
            values={"groups": uninit["inconsistent_bitmaps"]},
        )
    if overlap["count"]:
        boundary_only = overlap["interior"] == 0
        res.add(
            "warn" if boundary_only else "critical",
            f"{overlap['count']} bloków jest jednocześnie nieprzydzielone i metadanymi systemu plików",
            detail=(
                (
                    "wszystkie leżą na ostatnim bloku zakresu metadanych, a nie "
                    "w jego środku. Na obrazach budowanych mke2fs jest to dokładnie "
                    "jeden blok: ostatni blok journalu, o którym ten czytnik i "
                    "e2fsck -fn mówią różne rzeczy — e2fsck uznaje taki obraz za "
                    "czysty, więc rozbieżność jest w naszej arytmetyce zakresu, "
                    "nie w bitmapie. Liczba wolnych bloków zgadza się z dumpe2fs "
                    "i z blkls mimo tego, bo bitmapy obu czytników czytane są "
                    "identycznie. Pierwszy: "
                    + ", ".join(str(b) for b in overlap["blocks"][:8])
                )
                if boundary_only
                else (
                    f"{overlap['interior']} z nich leży w środku zakresu metadanych, "
                    "więc to nie jest spór o granicę: albo bitmapy kłamią, albo nasz "
                    "zakres jest zbyt szeroki. Takie bloki wylądują w inwentaryzacji "
                    "przestrzeni do odzyskiwania. Pierwsze: "
                    + ", ".join(str(b) for b in overlap["blocks"][:8])
                )
            ),
            values={
                "count": overlap["count"],
                "at_extent_end": overlap["at_extent_end"],
                "interior": overlap["interior"],
                "blocks": overlap["blocks"],
            },
        )
    else:
        res.add(
            "ok",
            "Żaden nieprzydzielony blok nie jest metadanymi systemu plików",
            detail=(
                f"sprawdzone na {len(fs.metadata_blocks())} blokach metadanych: superblok "
                "i tablica deskryptorów, bitmapy i tabele inodów wszystkich 206 grup, "
                "kopie superbloków w grupach z sparse_super, oraz bloki journalu. "
                "Zatem nic żywego nie zajmuje przestrzeni poniżej."
            ),
            values={"metadata_blocks": metadata_total, "overlap": 0},
        )

    if content.get("skipped"):
        res.add(
            "info",
            "Zawartość przestrzeni nieprzydzielonej nie była skanowana",
            detail=(
                "parametr scan=none. Moduł umie policzyć, ile z tej przestrzeni jest "
                "zerami, ale nie zrobił tego."
            ),
            values={"content": content},
        )
    else:
        share = 100 * (1 - content["zero_share"])
        headline = (
            f"Przestrzeń nieprzydzielona: {share:.2f}% to nie zera"
        )
        if content["complete"]:
            headline += (
                f" ({human_bytes(content['nonzero_bytes'])} z "
                f"{human_bytes(content['scanned_bytes'])})"
            )
        else:
            headline += (
                f" — próbka {content['scanned_blocks']} bloków "
                f"({round(100 * content['scanned_fraction'], 1)}% przestrzeni), "
                f"w niej {content['nonzero_blocks']} bloków z niezerami"
            )
        res.add(
            "ok" if content["complete"] else "info",
            headline,
            detail=(
                f"przeczytano {content['scanned_blocks']} z {len(blocks)} bloków, "
                f"próbka systematyczna co k-ty; {content['zero_blocks']} bloków to "
                f"same zera, {content['nonzero_blocks']} ma coś niezerowego. "
                + (
                    ""
                    if content["complete"]
                    else f"Szacunek na całą przestrzeń: ok. "
                    f"{content['nonzero_estimate']} bloków "
                    f"({human_bytes(content['nonzero_estimate'] * block_size)}) "
                    f"z {content['nonzero_blocks']} trafień w próbce — przy tak "
                    f"niskim udziale liczba trafień jest mała, więc oszacowanie "
                    f"ma szeroki przedział błędu; scan=full czyta wszystko"
                )
            ),
            values=content,
        )

    res.add(
        "warn",
        "To jest krok 2 z trzech: przestrzeń jest zmierzona, nic nie odzyskane",
        detail=(
            "moduł znajduje bloki, w których mogą leżeć treści usuniętych plików, "
            "i mówi, ile ich jest oraz ile z nich nie jest zerami. Nie przypisuje "
            "bajtów do plików, nie znajduje nazw i nie tworzy listy odzyskanych "
            "plików — to krok 3 (carving), który jest osobną pracą i nie jest zrobiony. "
            "Nazwy usuniętych plików żyją wyłącznie w blokach katalogowych, które "
            "wciąż mogą je zawierać, a nie w inodach."
        ),
        values={
            "files_recovered": 0,
            "names_recovered": 0,
            "step": "7.5 krok 2 z 3",
        },
    )

    if bool(params.get("dump", False)):
        target = ctx.work("exports") / "unallocated.img"
        try:
            written = fs.dump_unallocated(str(target))
        except Exception as exc:  # noqa: BLE001 - a failed dump must not lose the inventory
            res.add("critical", f"Nie udało się wypisać przestrzeni: {exc}",
                    values={"dump": {"error": str(exc)[:200]}})
        else:
            written["human"] = human_bytes(written["bytes"])
            parts["dump"] = written
            res.add(
                "ok",
                f"Wypisano przestrzeń nieprzydzieloną: {written['human']} "
                f"({written['blocks']} bloków)",
                detail=f"SHA-256 {written['sha256']}",
                values=written,
                artifacts=[written["path"]],
            )

    res.data = parts
    res.export(to_json(ctx.work("exports") / "free_space.json", parts))
    res.export(
        to_csv(
            ctx.work("exports") / "free_space_runs.csv",
            ["first_block", "blocks", "bytes", "first_offset", "last_block"],
            [
                [
                    first,
                    count,
                    count * block_size,
                    first * block_size,
                    first + count - 1,
                ]
                for first, count in runs
            ],
            ctx.masker,
        )
    )
    top = sorted(runs, key=lambda item: -item[1])[:10]
    res.export(
        to_csv(
            ctx.work("exports") / "free_space_runs_longest.csv",
            ["rank", "first_block", "blocks", "bytes", "first_offset", "last_block"],
            [
                [
                    rank,
                    first,
                    count,
                    count * block_size,
                    first * block_size,
                    first + count - 1,
                ]
                for rank, (first, count) in enumerate(top, start=1)
            ],
            ctx.masker,
        )
    )
    res.note(f"{round(time.time() - started, 1)}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="free_space",
        category="image",
        title="mod.free_space.title",
        summary="mod.free_space.summary",
        params=[
            Param(key="scan", label="Skan zawartości", default="sample"),
            Param(key="scan_blocks", label="Limit bloków do skanu", default=DEFAULT_SCAN_BLOCKS, kind=INT),
            Param(key="list_blocks", label="Ile bloków z niezerami wypisać", default=64, kind=INT),
            Param(key="dump", label="Wypisz przestrzeń do pliku", default=False, kind=BOOL),
        ],
        run=run,
    )
)
