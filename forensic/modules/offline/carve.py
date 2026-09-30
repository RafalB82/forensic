# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Deleted names from directory blocks, and content candidates from free space.

Step 3 of the plan's 7.5, and the step the plan worries about most: *"carving from
a cluster without metadata is inherently weakened as evidence and must be described
as such in the report, otherwise it builds false confidence."*  The step has two
halves because the plan's step 1 established that the bytes cannot be reached
through the inode, and this is what is left.

**Names: 51 903 of them, in two classes that are not equally good.**

The names of deleted files live in directory blocks — but *not* where a walk of
the directory's record chain would find them.  **ext4 merges a live entry with the
entries deleted after it.**  On the reference image,
``/media/0/MIUI/Gallery/cloud/.cache`` has a record for ``micro_thumbnail_blob.1``
that is 3916 bytes long and swallows the rest of the block, and every name deleted
from that directory sits inside its payload.  Following ``rec_len`` from the start
of the block finds **286** unlinked names on the whole volume.  Sliding a window
over each block and testing every offset for a plausible entry header finds
**51 903** more — the same technique a carver uses, and the reason
``fls -d`` reports tens of thousands where a chain walk reports hundreds.

The two are kept apart because the difference between them is the whole point:

* **286 still reachable by walking the chain.**  Their inode number is zero, which
  is what the kernel writes on unlink, so nothing can be attached to these names
  by accident.  That they happen to be reachable is a property of this image, not
  of the format: a record deleted *after* the one that swallowed it is in exactly
  the same position and is equally invisible to a chain walk.  The hand-built
  fixture in the self-test is that case, and it is how the two halves were
  measured rather than argued about.
* **51 903 found only by the window.**  Not reachable from the chain, so ext4 has
  overwritten the space that described them and only the bytes inside the
  swallowing record survived.  The **name** is solid — it was in this directory.
  The **inode number in the record may since have been handed to a different
  file**, so the size, uid and timestamps behind it are not evidence about the
  deleted one.  Every such record carries ``metadata_trust`` saying so, and the
  module's summary counts them separately.

`tsk_crosscheck` has been reporting "51 924 unlinked entries" since the eighth
turn as a single number.  It is not one kind of thing and never was; the split
above is what the number is made of.

**Content: candidates, with the evidence grade attached.**  Three grades —
``validated`` (the structure behind the signature was walked to its terminator or
a checksum recomputed), ``magic`` (the signature is there and nothing behind it
could be checked) and ``weak``.  A candidate cut short by the end of its run is
reported as **truncated**, not as a smaller file.  On the reference image a 12%
sample of the free space yields **3 candidates** and rejects **143** JPEG
signatures that do not validate, and the rejects are reported: a carver that does
not say how often it said no is a carver whose yes cannot be weighed.

**Nothing here is a recovered file.**  No name, path, uid or timestamp is attached
to a content candidate, because there is none to attach: ext4 discarded the inode
and the directory entry at the moment of unlink.  The module says so in a finding
of its own, not only in prose.
"""

from __future__ import annotations

import time
from collections import Counter
from typing import Any

from ...core.carve import carve_run
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, INT, ModuleSpec, Param, register

#: Blocks of unallocated space to carve.  The whole thing is 2.49 million blocks
#: and the disk under it reads at about 48 MB/s, so a full pass is six and a half
#: minutes; 300 000 blocks is 1,2 GiB, twelve per cent of the free space, and
#: costs about eighteen seconds.  Free space is full of zero blocks, so a larger
#: budget buys very little — the first 300 000 blocks hold 62 non-zero ones and
#: every candidate the image has.
DEFAULT_CARVE_BLOCKS = 300_000

#: Names to keep in the export.  The full list is 52 thousand rows; the export is
#: for reading, and the count is reported separately.
DEFAULT_EXPORT_NAMES = 20_000


def _summarise_names(entries: list[dict], total: int) -> dict[str, Any]:
    kinds: Counter = Counter(item["kind_name"] for item in entries)
    # A file type outside 0..8 cannot come from a dentry ext4 wrote, so it is a
    # false positive of the window test.  Counting it separately is what turns
    # "by_kind" from a list of findings into a measure of the filter's cost.
    odd = sum(1 for item in entries if not 0 <= item["kind"] <= 8)
    dirs: Counter = Counter(item["directory"] for item in entries)
    return {
        "total": total,
        "by_kind": dict(kinds.most_common()),
        "distinct_directories": len(dirs),
        "implausible_file_type": odd,
        "top_directories": [
            {"directory": name, "entries": count}
            for name, count in dirs.most_common(10)
        ],
    }


def _fls_deleted_count(ctx: Ctx) -> dict[str, Any]:
    """``fls -d`` as a second reader on the unlinked-entry count.

    Only the count is taken and only as a comparison.  ``fls -d`` reports a deleted
    entry by finding a dentry whose inode no longer matches, which is a different
    rule from either of ours — it accepts a stale record whose inode now resolves
    to an object of a different type, and it prints the inode it found.  So a
    difference against it is a difference in rules, and the numbers are shown
    side by side rather than reconciled.
    """
    from ...core import tsk

    tool = tsk.tool_path("fls")
    if not tool:
        return {"available": False, "why": "brak fls (The Sleuth Kit)"}
    import subprocess

    try:
        proc = subprocess.run(  # noqa: S603 - argv built here, never a shell
            [tool, "-r", "-d", "-p", str(ctx.image)],
            capture_output=True, text=True, errors="surrogateescape",
            timeout=tsk.DEFAULT_TIMEOUT, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"available": False, "why": str(exc)[:200]}
    if proc.returncode != 0:
        return {"available": False, "why": f"fls exit={proc.returncode}"}
    found = [e for e in tsk.parse_fls(proc.stdout) if e.real]
    return {
        "available": True,
        "count": len(found),
        "by_kind": dict(Counter(e.type for e in found).most_common()),
        "reallocated": sum(1 for e in found if e.note == "realloc"),
        "version": tsk.version(),
    }


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("carve")
    started = time.time()
    fs = ctx.fs()

    names = fs.unlinked_entries()
    chain = names["chain_unlinked"]
    window = names["window_only"]
    total_names = names["chain_unlinked_total"] + names["window_only_total"]

    budget = max(0, int(params.get("carve_blocks", 0) or DEFAULT_CARVE_BLOCKS))
    runs = fs.unallocated_runs()
    candidates: list = []
    rejected: Counter = Counter()
    scanned = 0
    zero_blocks = 0
    runs_touched = 0
    used = 0
    unreadable = 0
    for first, count in runs:
        if used >= budget:
            break
        take = min(count, budget - used)
        if not take:
            break
        result = carve_run(
            list(range(first, first + take)), lambda block: fs._cache.get(block),
            fs.block_size,
        )
        runs_touched += 1
        used += take
        scanned += result["scanned_bytes"]
        zero_blocks += result["zero_blocks"]
        unreadable += result["skipped"]
        for kind, number in result["rejected"].items():
            rejected[kind] += number
        candidates.extend(result["candidates"])
    if budget and used < sum(n for _f, n in runs):
        coverage_complete = False
    else:
        coverage_complete = True

    grades: Counter = Counter(c.grade for c in candidates)
    kinds_found: Counter = Counter(c.kind for c in candidates)
    complete_candidates = [c for c in candidates if not c.truncated]

    parts: dict[str, Any] = {
        "names_total": total_names,
        "names_chain_unlinked": names["chain_unlinked_total"],
        "names_window_only": names["window_only_total"],
        "window_positions_rejected": names["rejected"],
        "names_directory_blocks": names["directory_blocks"],
        "names_complete": names["complete"],
        "names_chain_summary": _summarise_names(chain, names["chain_unlinked_total"]),
        "names_window_summary": _summarise_names(window, names["window_only_total"]),
        "carve_runs_total": len(runs),
        "carve_runs_touched": runs_touched,
        "carve_blocks_scanned": used,
        "carve_budget": budget,
        "carve_coverage_complete": coverage_complete,
        "carve_bytes_scanned": scanned,
        "carve_zero_blocks": zero_blocks,
        "carve_blocks_unreadable": unreadable,
        "candidates_total": len(candidates),
        "candidates_complete": len(complete_candidates),
        "candidates_truncated": len(candidates) - len(complete_candidates),
        "candidates_by_grade": dict(grades),
        "candidates_by_kind": dict(kinds_found),
        "candidates_rejected_by_kind": dict(rejected.most_common()),
        "candidates_rejected_total": sum(rejected.values()),
        "files_recovered": 0,
        "names_recovered": 0,
        "candidates_attributed_to_files": 0,
        "candidates_have_names": False,
        "step": "7.5 krok 3 z 3",
    }
    if bool(params.get("crosscheck", True)):
        parts["fls_d"] = _fls_deleted_count(ctx)

    res.add(
        "ok",
        f"Nazwy usuniętych plików: {total_names} "
        f"({names['chain_unlinked_total']} z zerowym numerem inoda, "
        f"{names['window_only_total']} znalezionych przesuniętym oknem)",
        detail=(
            f"przeszukano {names['directory_blocks']} bloków katalogowych; "
            f"okno przeszukano w każdym bajcie, a {names['rejected']} pozycji "
            "odrzucono jako niebędące nazwą (to liczba pozycji, nie liczba nazw). "
            f"Nazwy pochodzą z bloków katalogowych katalogów, które NADAL istnieją — "
            f"usunięty wpis znika z łańcucha rekordów, ale jego bajty zostają"
        ),
        values={
            "names_total": total_names,
            "names_chain_unlinked": names["chain_unlinked_total"],
            "names_window_only": names["window_only_total"],
            "window_positions_rejected": names["rejected"],
        },
    )
    res.add(
        "info",
        f"Nazwy znalezione oknem: {names['window_only_total']} — numer inoda "
        f"w ich rekordzie mógł już należeć do innego pliku",
        detail=(
            f"to nie jest ta sama pewność co przy {names['chain_unlinked_total']} "
            "wpisach z zerowym numerem inoda. Nazwa należała do tego katalogu — to "
            "pewne. Metadane przypisane przez rekord nie należą do usuniętego "
            "pliku, bo inoda mogło dostać co innego. Raport nie łączy tych nazw z "
            "rozmiarem ani czasem pliku. Największe katalogi: "
        )
        + "; ".join(
            f"{item['directory']}: {item['entries']}"
            for item in _summarise_names(window, 0)["top_directories"][:5]
        ),
        values=_summarise_names(window, names["window_only_total"]),
    )
    fls = parts.get("fls_d")
    if fls and fls.get("available"):
        res.add(
            "info",
            f"fls -d (The Sleuth Kit {fls.get('version', '?')}): {fls['count']} "
            f"niepodlinkowanych wpisów wobec naszych {total_names}",
            detail=(
                f"ich typy: {fls['by_kind']}; z nich {fls['reallocated']} ma numer "
                "inoda, który TSK opisuje jako przydzielony ponownie. Różnica w "
                "liczbach to różnica zasad, nie błąd: fls -d uznaje rekord katalogowy "
                "za usunięty, gdy jego numer inoda wskazuje teraz obiekt innego typu, "
                "a my rozróżniamy rekord w łańcuchu (d_ino = 0) od rekordu, który "
                "z łańcucha wypadł. Liczby są obok siebie, nie uśrednione"
            ),
            values=fls,
        )

    res.add(
        "ok" if candidates else "warn",
        f"Kandydaty treści: {len(candidates)} z {used} przeszukanych bloków "
        f"({round(100 * used / max(1, sum(n for _f, n in runs)), 1)}% przestrzeni)",
        detail=(
            f"odrzucono {sum(rejected.values())} sygnatur, które nie przeszły "
            f"walidacji: {dict(rejected.most_common(6)) or 'brak'}. "
            f"stopnie: {dict(grades)}; przerwanych na końcu luki: "
            f"{len(candidates) - len(complete_candidates)}. "
            f"{zero_blocks} z {used} bloków było samymi zerami"
            + (
                f"; {unreadable} bloków nie dało się odczytać wcale, więc nie "
                "przeszukano ich i nie policzono jako puste"
                if unreadable
                else ""
            )
        ),
        values={
            "candidates_total": len(candidates),
            "candidates_by_grade": dict(grades),
            "candidates_by_kind": dict(kinds_found),
            "rejected": dict(rejected.most_common()),
            "blocks": used,
            "zero_blocks": zero_blocks,
            "blocks_unreadable": unreadable,
            "coverage_complete": coverage_complete,
        },
    )
    if unreadable:
        res.add(
            "warn",
            f"Pominięte rekordy: {unreadable} bloków nieczytelnych",
            detail=(
                "blok, którego nie da się odczytać, nie jest pusty — jest dziurą w "
                "dowodzie. Takich bloków nie wyrzeźbiono ani nie policzono jako "
                "zerowych, więc liczba kandydatów poniżej jest dolnym oszacowaniem"
            ),
            values={"blocks_unreadable": unreadable, "blocks_searched": used},
        )
    if not coverage_complete:
        res.add(
            "info",
            f"Przeszukano {used} z {sum(n for _f, n in runs)} bloków przestrzeni",
            detail=(
                f"limit parametru carve_blocks={budget}. Wszystkie bloki tożsame "
                "pominięto przy szukaniu, więc koszt proporcjonalny jest do bloków "
                "nietożsamych, a nie do wielkości luki"
            ),
            values={"scanned": used, "total": sum(n for _f, n in runs)},
        )

    res.add(
        "warn",
        "To jest wyrzeźbienie z klastra bez metadanych — dowód osłabiony",
        detail=(
            "kandydat treści to zakres bajtów, który zaczyna się sygnaturą formatu. "
            "Nie ma do niego nazwy, ścieżki, uid, czasu ani numeru inoda, bo ext4 "
            "usunął inod i wpis katalogowy w momencie unlink, a my nie wiemy, który "
            "inod należał do którego zakresu. Kandydat może być plikiem, może być "
            "fragmentem pliku, który wyrzucił alokator w połowie, a może być "
            "danymi, które wyglądają jak plik. Lista poniżej jest listą zakresów "
            "do obejrzenia przez człowieka, nie listą odzyskanych plików. "
            "Nazwy z pierwszej części dotyczą katalogów, a kandydatów treści nie "
            "łączy z nimi nic poza tym, że oba pochodzą z tej samej przestrzeni "
            "wolnej — żadnej możliwości sparowania nie ma i żadnej nie udajemy"
        ),
        values={
            "files_recovered": 0,
            "candidates_attributed_to_files": 0,
            "candidates_have_names": False,
        },
    )

    res.data = parts
    res.export(to_json(ctx.work("exports") / "carve.json", parts))
    limit = max(0, int(params.get("export_names", 0) or DEFAULT_EXPORT_NAMES))
    rows = [("chain", item) for item in chain] + [("window", item) for item in window]
    rows = rows[:limit]
    res.export(
        to_csv(
            ctx.work("exports") / "unlinked_names.csv",
            ["source", "name", "directory", "kind", "inode", "image_offset",
             "metadata_trust", "name_source"],
            [
                [
                    source,
                    item["name"],
                    item["directory"],
                    item["kind_name"],
                    item["inode"],
                    item["image_offset"],
                    item["metadata_trust"],
                    item["name_source"],
                ]
                for source, item in rows
            ],
            ctx.masker,
        )
    )
    res.export(
        to_csv(
            ctx.work("exports") / "carve_candidates.csv",
            ["offset", "length", "kind", "grade", "truncated", "note", "run_first_block",
             "run_blocks", "name", "name_source"],
            [
                [
                    item.offset, item.length, item.kind, item.grade,
                    int(item.truncated), item.note,
                    item.run[0] if item.run else "", item.run[1] if item.run else "",
                    "", "brak — patrz opis modułu",
                ]
                for item in candidates
            ],
            ctx.masker,
        )
    )
    res.note(f"{round(time.time() - started, 1)}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="carve",
        category="image",
        title="mod.carve.title",
        summary="mod.carve.summary",
        params=[
            Param(key="carve_blocks", label="Limit bloków do wyrzeźbienia",
                  default=DEFAULT_CARVE_BLOCKS, kind=INT),
            Param(key="export_names", label="Limit nazw w eksporcie",
                  default=DEFAULT_EXPORT_NAMES, kind=INT),
            Param(key="crosscheck", label="Porównaj z fls -d", default=True, kind=BOOL),
        ],
        run=run,
    )
)
