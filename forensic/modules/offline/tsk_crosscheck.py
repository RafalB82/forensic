# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Sleuth Kit as a second opinion on everything our own ext4 reader claims.

Our reader is written by the same author as the report that cites it, so when it
is wrong it is wrong in a way that stays internally consistent.  The Sleuth Kit
is a C library written by other people and packaged by Debian, which makes it
the cheapest available check that does not share a single line of code with us —
and the TSK README itself says the results should be recreated with a second
tool.

Five questions are put to it, and they are not the same kind of question:

``superblock``
    Does TSK read the same geometry out of the superblock?  Volume totals, block
    and inode counts, free counts, block size.
``traversal``
    Does TSK walk the same tree?  Entry counts by type, against our own walk.
``inodes``
    Do ``istat`` and our :meth:`Inode` agree on size, owner and link count for a
    deterministic sample?
``content``
    The strongest one: ``icat`` the inode, read it through our extent mapping,
    compare SHA-256.  This is the check that would catch a reader which parses
    the superblock correctly and then maps data blocks wrongly.
``coverage``
    Not a check but a disclosure: how many unlinked directory entries and
    unallocated inodes exist that we do not show.  A cross-check that only
    confirms the comfortable part is worth less than one that states its own
    blind spot.

Two things are reported rather than resolved.  The volume UUID differs between
the tools because TSK prints the raw 16 superblock bytes in Windows GUID order;
both forms are shown so a report cannot be contradicted by ``fsstat``.  And
differences are counted, not asserted: this module produces findings, it never
marks a case as failed, because a disagreement means "go and look", not "the
tool is broken".
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from dataclasses import dataclass, field

from ...core import i18n, tsk
from ...core.ext4 import Ext4
from ...core.export import human_bytes, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, CHOICE, INT, ModuleSpec, Param, register

#: Anchor directories for the deterministic sample.  Android-relevant and spread
#: across the volume so a stride over them cannot systematically miss one region.
SAMPLE_ROOTS = (
    "/data/com.android.providers.contacts",
    "/data/com.google.android.gm",
    "/data/system",
    "/system/app",
    "/system/framework",
    "/data/com.whatsapp",
    "/media/0",
    "/data/misc",
)

#: Files bigger than this are skipped by the byte comparison.  ``icat`` writes to
#: a temporary file, and hashing a 200 MiB video proves no more about extent
#: mapping than hashing a 4 KiB one while making the check unusable in a
#: regression run.
MAX_SAMPLE_BYTES = 4 * 1024 * 1024

#: Zone labels TSK appends to rendered times, and their offsets in hours.
ZONE_OFFSETS = {"UTC": 0, "GMT": 0, "CET": 1, "CEST": 2}

ALL_CHECKS = ("superblock", "traversal", "inodes", "extents", "content", "coverage")


@dataclass
class Command:
    """One tool invocation, kept so the export can be re-read months later."""

    tool: str
    args: list[str]
    returncode: int
    seconds: float
    lines: int = 0
    stderr: str = ""

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "command": " ".join([self.tool, *self.args]),
            "returncode": self.returncode,
            "seconds": round(self.seconds, 2),
            "lines": self.lines,
            "stderr": self.stderr,
        }


@dataclass
class Comparison:
    """One field-level agreement between the two readers."""

    field_name: str
    ours: object
    theirs: object
    agree: bool
    note: str = ""

    def as_dict(self) -> dict:
        return {
            "field": self.field_name,
            "ours": self.ours,
            "theirs": self.theirs,
            "agree": self.agree,
            "note": self.note,
        }


@dataclass
class Report:
    """Accumulator for one cross-check run."""

    commands: list[Command] = field(default_factory=list)
    comparisons: list[Comparison] = field(default_factory=list)

    def add(self, field_name: str, ours: object, theirs: object, note: str = "") -> bool:
        agree = ours == theirs
        self.comparisons.append(Comparison(field_name, ours, theirs, agree, note))
        return agree

    @property
    def agreed(self) -> int:
        return sum(1 for c in self.comparisons if c.agree)

    @property
    def disagreed(self) -> list[Comparison]:
        return [c for c in self.comparisons if not c.agree]


def _run(image: str, tool: str, args: list[str], timeout: int = tsk.DEFAULT_TIMEOUT) -> tuple[int, str, str, float]:
    started = time.time()
    code, out, err = tsk.run_tool(tool, args, timeout=timeout)
    return code, out, err, time.time() - started


def _record(report: Report, tool: str, args: list[str], code: int, secs: float, lines: int = 0, err: str = "") -> None:
    report.commands.append(Command(tool, args, code, secs, lines, err.strip()))


def _tsk_epoch(rendered: str) -> int | None:
    """Turn an istat time string into a Unix epoch, or None when we cannot.

    TSK renders inode times in the image's own zone and names it, so the string
    carries everything needed — but only if the zone is one we know.  An
    unfamiliar label yields ``None`` rather than a guess, which turns the
    comparison into "unavailable" instead of a false mismatch.
    """
    import re

    match = re.match(
        r"^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})", rendered
    )
    if not match:
        return None
    zone = re.search(r"\(([A-Z]+)\)\s*$", rendered)
    if not zone or zone.group(1) not in ZONE_OFFSETS:
        return None
    import datetime as _dt

    try:
        moment = _dt.datetime(
            *(int(part) for part in match.groups()), tzinfo=_dt.timezone.utc
        )
    except ValueError:
        return None
    return int(moment.timestamp()) - ZONE_OFFSETS[zone.group(1)] * 3600


def _sample_inodes(fs: Ext4, limit: int) -> list[tuple[int, int, str]]:
    """Pick a deterministic sample of regular files: ``(inode, size, path)``.

    The sample is a stride over a sorted list, not a random draw, so a
    regression run compares the same inodes every time and a difference in the
    result means the image or the reader changed — not that the dice did.
    """
    found: dict[int, str] = {}
    for root in SAMPLE_ROOTS:
        try:
            entries = list(fs.walk(root))
        except Exception:
            continue
        for path, entry in entries:
            if not entry.is_reg or entry.inode in found:
                continue
            found[entry.inode] = path
    if not found:
        return []
    ordered = sorted(found)
    stride = max(1, len(ordered) // max(1, limit))
    picked = ordered[::stride][:limit]
    out: list[tuple[int, int, str]] = []
    for number in picked:
        try:
            node = fs.inode(number)
        except Exception:
            continue
        if not node.is_reg or node.size <= 0 or node.size > MAX_SAMPLE_BYTES:
            continue
        out.append((number, node.size, found[number]))
    return out


def _group_totals(theirs: dict) -> dict:
    """Total inodes and blocks from TSK's own per-group table.

    ``fsstat`` prints ``Inode Range: 1 - 1687553`` for a volume whose
    ``s_inodes_count`` is 1 687 552, so the printed bound is not the count and
    cannot be compared to ours directly.  Summing the 206 group ranges needs no
    assumption about which end TSK treats as inclusive, and it is derived from
    TSK's own numbers rather than from the label that is in doubt.
    """
    inodes = 0
    blocks = 0
    for group in theirs.get("groups", []):
        if "inode_range_low" in group and "inode_range_high" in group:
            inodes += group["inode_range_high"] - group["inode_range_low"] + 1
        if "block_range_low" in group and "block_range_high" in group:
            blocks += group["block_range_high"] - group["block_range_low"] + 1
    return {"inodes": inodes, "blocks": blocks}


def _check_superblock(ctx: Ctx, res: ModuleResult, report: Report, image: str) -> dict:
    code, out, err, secs = _run(image, "fsstat", [image], timeout=300)
    res.note(f"fsstat {secs:.2f}s exit={code}")
    if code != 0:
        res.add("warn", "fsstat nie odczytał obrazu", detail=(err or out).strip()[:400])
        return {}
    _record(report, "fsstat", [image], code, secs, out.count("\n"), err)
    theirs = tsk.parse_fsstat(out)
    ours = ctx.fs().superblock
    totals = _group_totals(theirs)
    report.add("block_size", ours.get("block_size"), theirs.get("block_size_int"))
    report.add("inode_size", ours.get("inode_size"), theirs.get("inode_size_int"))
    report.add("inode_count", ours.get("inodes_count"), totals["inodes"] or None,
               note="suma zakresów grup z fsstat")
    report.add("block_count", ours.get("blocks_count"), totals["blocks"] or None,
               note="suma zakresów grup z fsstat")
    report.add("free_blocks", ours.get("free_blocks"), theirs.get("free_blocks_int"))
    report.add("free_inodes", ours.get("free_inodes"), theirs.get("free_inodes_int"))
    report.add("last_mounted", ours.get("last_mounted"), theirs.get("last_mounted_on"))
    report.add("group_count", len(ctx.fs()._groups), theirs.get("number_of_block_groups_int"))
    report.add("blocks_per_group", ours.get("blocks_per_group"), theirs.get("blocks_per_group_int"))
    report.add("inodes_per_group", ours.get("inodes_per_group"), theirs.get("inodes_per_group_int"))
    # The UUID is the same 16 superblock bytes in both tools; TSK only prints
    # them in Windows GUID order.  The comparison is made on the converted form
    # and both spellings are kept, so a report cannot be called wrong by fsstat.
    ours_uuid = str(ours.get("uuid", ""))
    theirs_uuid = str(theirs.get("volume_id", ""))
    guid = tsk.guid_display(ours_uuid)
    report.add("volume_uuid", guid or ours_uuid, theirs_uuid, note=f"surowe bajty: {ours_uuid}")
    return {
        "uuid_raw": ours_uuid,
        "uuid_guid": guid,
        "uuid_tsk": theirs_uuid,
        "fs_type": theirs.get("file_system_type"),
        "tsk_version": tsk.version(),
        "groups_total": totals,
    }


def _check_traversal(ctx: Ctx, res: ModuleResult, report: Report, image: str) -> dict:
    code, out, err, secs = _run(image, "fls", ["-r", "-p", image], timeout=tsk.DEFAULT_TIMEOUT)
    res.note(f"fls -r -p {secs:.2f}s exit={code}")
    if code != 0:
        res.add("warn", "fls nie przeszedł obrazu", detail=(err or out).strip()[:400])
        return {}
    _record(report, "fls", ["-r", "-p", image], code, secs, out.count("\n"), err)
    entries = tsk.parse_fls(out)
    real = [e for e in entries if e.real]
    live = [e for e in real if not e.link_deleted]
    unlinked = [e for e in real if e.link_deleted]
    scan = ctx.file_scan()
    report.add("entries_live", scan.get("entries"), len(live))
    report.add("regular_files", scan.get("files_total"), sum(1 for e in live if e.type == "regular"))
    by_type = dict(Counter(e.type for e in live))
    res.add(
        "info",
        "TSK widzi te same wpisy co nasza własna wędrówka",
        detail=f"żywych {len(live)}, niepodlinkowanych {len(unlinked)}",
        values={
            "live": len(live),
            "unlinked": len(unlinked),
            "by_type": by_type,
            "scan_entries": scan.get("entries"),
            "scan_files": scan.get("files_total"),
            "seconds": round(secs, 1),
        },
    )
    return {
        "live": len(live),
        "unlinked": len(unlinked),
        "by_type": by_type,
        "unlinked_by_type": dict(Counter(e.type for e in unlinked)),
        "parsed": len(entries),
        "virtual": len(entries) - len(real),
    }


def _check_inodes(ctx: Ctx, res: ModuleResult, report: Report, image: str, limit: int) -> dict:
    sample = _sample_inodes(ctx.fs(), limit)
    if not sample:
        res.add("warn", "brak plików do porównania metadanych", values={"sample": 0})
        return {"sample": 0}
    mismatched: list[dict] = []
    times_checked = 0
    times_skipped = 0
    for number, _size, path in sample:
        started = time.time()
        code, out, err, _secs = _run(image, "istat", [image, str(number)], timeout=120)
        _record(report, "istat", [image, str(number)], code, time.time() - started, out.count("\n"), err)
        if code != 0:
            continue
        theirs = tsk.parse_istat(out)
        node = ctx.fs().inode(number)
        agree = report.add(f"inode:{number}:size", node.size, theirs.get("size_int"))
        agree &= report.add(f"inode:{number}:uid", node.uid, int(str(theirs.get("uid_gid", "0 / 0")).split("/")[0]))
        agree &= report.add(f"inode:{number}:links", node.links, theirs.get("num_of_links_int"))
        epoch = _tsk_epoch(str(theirs.get("mtime", "")))
        if epoch is None:
            times_skipped += 1
        else:
            times_checked += 1
            agree &= report.add(f"inode:{number}:mtime", node.mtime, epoch)
        if not agree:
            mismatched.append({"inode": number, "path": path, "tsk": {k: v for k, v in theirs.items() if k != "raw"}})
    res.add(
        "ok" if not mismatched else "finding",
        f"istat potwierdził metadane {len(sample)} plików" if not mismatched
        else f"istat nie zgodził się z naszym readerem dla {len(mismatched)} plików",
        detail="; ".join(m["path"] for m in mismatched[:3])[:400] or None,
        values={"sample": len(sample), "mismatched": len(mismatched), "times_checked": times_checked, "times_skipped": times_skipped},
    )
    return {
        "sample": len(sample),
        "mismatched": len(mismatched),
        "mismatched_detail": mismatched[:10],
        "times_checked": times_checked,
        "times_skipped": times_skipped,
    }


def _check_extents(ctx: Ctx, res: ModuleResult, report: Report, image: str, limit: int) -> dict:
    """Ask whether the extent parser dropped anything, using two references.

    The failure this guards against is specific and was real: a subtree of the
    extent tree going unread would leave ``listdir`` empty and ``read``
    returning ``b""`` with no error raised, and a report cannot tell that apart
    from an empty directory.  Two independent numbers catch it.

    ``i_blocks`` is the filesystem's own account of the inode's footprint, in
    512-byte sectors.  It counts the file's data blocks *and* the blocks that
    hold the extent tree itself, so the comparison is
    ``i_blocks / (block_size / 512) == data_blocks + tree_blocks``.  A dropped
    interior node makes the derived count too small and the two disagree.
    Getting this wrong in the reader's favour is easy — the first version of
    this check compared against data blocks alone and reported a false
    discrepancy on 1.4% of files, all of them perfectly correct.

    ``istat`` is a second implementation's view: its ``Direct Blocks`` list is
    the extent's data blocks and its ``Extent Blocks`` list is the tree, so
    both halves are compared independently.

    The root directory is excluded from the ``i_blocks`` half: the kernel
    reserves it an extra block for its self-referential ``..``, so its
    accounting is one higher than its extent tree describes.  It is a known
    exception, not a finding, and a check that cries wolf on inode 2 gets
    ignored.
    """
    sample = _sample_inodes(ctx.fs(), limit)
    if not sample:
        res.add("warn", "brak plików do audytu extentów", values={"sample": 0})
        return {"sample": 0}
    sectors_per_block = ctx.fs().block_size // 512
    volume_blocks = ctx.fs().blocks
    sectors_mismatch: list[dict] = []
    out_of_range: list[dict] = []
    holes: list[dict] = []
    tsk_mismatch: list[dict] = []
    tsk_checked = 0
    total_data_blocks = 0
    total_tree_blocks = 0
    for number, size, path in sample:
        node = ctx.fs().inode(number)
        data_blocks = node.data_block_count
        tree_blocks = len(node.extent_tree_blocks)
        total_data_blocks += data_blocks
        total_tree_blocks += tree_blocks
        expected_sectors = node.blocks // sectors_per_block
        report.add(
            f"extents:{number}:i_blocks",
            expected_sectors,
            data_blocks + tree_blocks,
            note=f"{path} (data {data_blocks} + drzewo {tree_blocks})",
        )
        if data_blocks + tree_blocks != expected_sectors:
            sectors_mismatch.append(
                {
                    "inode": number,
                    "path": path,
                    "data_blocks": data_blocks,
                    "tree_blocks": tree_blocks,
                    "i_blocks_as_blocks": expected_sectors,
                }
            )
        for extent in node.extents:
            if extent.physical + extent.count > volume_blocks:
                out_of_range.append(
                    {"inode": number, "path": path, "physical": extent.physical, "count": extent.count}
                )
        if node.extents:
            reach = 0
            for extent in node.extents:
                if extent.logical > reach:
                    holes.append({"inode": number, "path": path, "hole_at": reach, "next": extent.logical})
                    break
                reach = max(reach, extent.end)
        started = time.time()
        code, out, err, _secs = _run(image, "istat", [image, str(number)], timeout=120)
        _record(report, "istat", [image, str(number)], code, time.time() - started, out.count("\n"), err)
        if code != 0:
            continue
        theirs = tsk.parse_istat(out)
        their_blocks = len(theirs.get("direct_blocks_blocks") or [])
        their_tree = len(theirs.get("extent_blocks_blocks") or [])
        if their_blocks or theirs.get("extent_mapped"):
            tsk_checked += 1
            report.add(
                f"extents:{number}:istat",
                [their_blocks, their_tree],
                [data_blocks, tree_blocks],
                note=path,
            )
            if their_blocks != data_blocks or their_tree != tree_blocks:
                tsk_mismatch.append(
                    {
                        "inode": number,
                        "path": path,
                        "our_data": data_blocks,
                        "tsk_data": their_blocks,
                        "our_tree": tree_blocks,
                        "tsk_tree": their_tree,
                    }
                )
    problems = sectors_mismatch + out_of_range + holes + tsk_mismatch
    res.add(
        "ok" if not problems else "critical",
        f"audyt extentów: {len(sample)} plików, {total_data_blocks} bloków danych + "
        f"{total_tree_blocks} bloków drzewa; i_blocks i istat zgadzają się wszędzie"
        if not problems
        else f"audyt extentów: {len(problems)} niespójności w {len(sample)} plikach",
        detail="; ".join(
            f"{p.get('inode')} {p.get('path')}" for p in (sectors_mismatch + tsk_mismatch + holes)[:4]
        )[:400] or None,
        values={
            "sample": len(sample),
            "data_blocks": total_data_blocks,
            "tree_blocks": total_tree_blocks,
            "i_blocks_mismatch": len(sectors_mismatch),
            "extent_out_of_range": len(out_of_range),
            "logical_holes": len(holes),
            "tsk_checked": tsk_checked,
            "tsk_mismatch": len(tsk_mismatch),
            "sectors_per_block": sectors_per_block,
            "detail": (sectors_mismatch + out_of_range + holes + tsk_mismatch)[:10],
        },
    )
    return {
        "sample": len(sample),
        "data_blocks": total_data_blocks,
        "tree_blocks": total_tree_blocks,
        "i_blocks_mismatch": len(sectors_mismatch),
        "extent_out_of_range": len(out_of_range),
        "logical_holes": len(holes),
        "tsk_checked": tsk_checked,
        "tsk_mismatch": len(tsk_mismatch),
        "sectors_per_block": sectors_per_block,
        "detail": (sectors_mismatch + out_of_range + holes + tsk_mismatch)[:10],
    }


def _check_content(ctx: Ctx, res: ModuleResult, report: Report, image: str, limit: int) -> dict:
    sample = _sample_inodes(ctx.fs(), limit)
    if not sample:
        res.add("warn", "brak plików do porównania treści", values={"sample": 0})
        return {"sample": 0}
    identical = 0
    differing: list[dict] = []
    unread = 0
    total_bytes = 0
    for number, size, path in sample:
        try:
            ours = ctx.fs().read(number)
        except Exception as exc:  # noqa: BLE001
            unread += 1
            res.add("warn", f"nasz reader nie odczytał inoda {number}", detail=str(exc)[:200])
            continue
        started = time.time()
        theirs, error = tsk.icat(image, number, timeout=300)
        _record(
            report,
            "icat",
            [image, str(number)],
            0 if not error else 1,
            time.time() - started,
            len(theirs),
            error,
        )
        if error:
            unread += 1
            res.add("info", f"icat pominął inoda {number}", detail=error[:200])
            continue
        total_bytes += len(ours)
        our_hash = hashlib.sha256(ours).hexdigest()
        their_hash = hashlib.sha256(theirs).hexdigest()
        if our_hash == their_hash:
            identical += 1
            report.add(f"content:{number}", our_hash, their_hash, note=path)
        else:
            differing.append(
                {
                    "inode": number,
                    "path": path,
                    "expected_size": size,
                    "our_bytes": len(ours),
                    "tsk_bytes": len(theirs),
                    "our_sha256": our_hash,
                    "tsk_sha256": their_hash,
                }
            )
            report.add(f"content:{number}", our_hash, their_hash, note=path)
    ok = not differing and identical > 0
    res.add(
        "ok" if ok else ("finding" if differing else "warn"),
        f"icat potwierdził treść {identical}/{len(sample)} plików ({human_bytes(total_bytes)})"
        if not differing
        else f"treść {len(differing)}/{len(sample)} plików różni się od icat",
        detail="; ".join(d["path"] for d in differing[:3])[:400] or None,
        values={
            "sample": len(sample),
            "identical": identical,
            "differing": len(differing),
            "unread": unread,
            "bytes_compared": total_bytes,
            "differing_detail": differing[:10],
        },
    )
    return {
        "sample": len(sample),
        "identical": identical,
        "differing": len(differing),
        "unread": unread,
        "bytes_compared": total_bytes,
        "differing_detail": differing[:10],
    }


def _check_coverage(ctx: Ctx, res: ModuleResult, report: Report, image: str) -> dict:
    out: dict = {}
    code, text, err, secs = _run(image, "fls", ["-r", "-d", "-p", image], timeout=tsk.DEFAULT_TIMEOUT)
    res.note(f"fls -r -d -p {secs:.2f}s exit={code}")
    if code == 0:
        _record(report, "fls", ["-r", "-d", "-p", image], code, secs, text.count("\n"), err)
        unlinked = [e for e in tsk.parse_fls(text) if e.real]
        out["unlinked_entries"] = len(unlinked)
        out["unlinked_by_type"] = dict(Counter(e.type for e in unlinked))
        out["unlinked_reallocated"] = sum(1 for e in unlinked if e.note == "realloc")
    code, text, err, secs = _run(image, "ils", [image], timeout=tsk.DEFAULT_TIMEOUT)
    res.note(f"ils {secs:.2f}s exit={code}")
    if code == 0:
        _record(report, "ils", [image], code, secs, text.count("\n"), err)
        out.update(tsk.parse_ils(text))
    live = out.get("unlinked_entries", 0)
    free_inodes = ctx.fs().superblock.get("free_inodes", 0)
    out["free_inodes_superblock"] = free_inodes
    res.add(
        "warn" if live else "info",
        f"TSK pokazuje {live} niepodlinkowanych wpisów, których nasz reader nie wymienia",
        detail=(
            f"wolnych inodów w superblocku: {free_inodes}; "
            f"nieużytych, ale dawniej zajętych: {out.get('unallocated_inodes', '?')}"
        ),
        values={
            "unlinked_entries": out.get("unlinked_entries"),
            "unlinked_by_type": out.get("unlinked_by_type"),
            "unlinked_reallocated": out.get("unlinked_reallocated"),
            "unallocated_inodes": out.get("unallocated_inodes"),
            "unallocated_with_data": out.get("with_data"),
            "unallocated_total_size": out.get("total_size"),
            "free_inodes_superblock": free_inodes,
        },
    )
    return out


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("tsk_crosscheck")
    image = str(ctx.image)
    if not ctx.image.exists():
        res.add("critical", i18n.t("msg.image_missing"), image)
        return ctx.record(res)
    found = tsk.present()
    missing = [name for name in tsk.required_tools() if name not in found]
    if missing:
        res.add(
            "warn",
            "Sleuth Kit nie jest zainstalowany — brak drugiego czytnika",
            detail=f"brakuje: {', '.join(missing)}; sudo apt install sleuthkit",
            values={"present": found, "missing": missing},
        )
        return ctx.record(res)
    wanted = str(params.get("check") or "all")
    checks = ALL_CHECKS if wanted in ("all", "") else (wanted,)
    unknown = [name for name in checks if name not in ALL_CHECKS]
    if unknown:
        res.add("critical", f"nieznany check: {', '.join(unknown)}", values={"valid": list(ALL_CHECKS)})
        return ctx.record(res)
    limit = max(1, int(params.get("sample") or 15))
    report = Report()
    started = time.time()
    parts: dict = {"tsk_version": tsk.version(), "tools": found, "checks": list(checks), "sample": limit}
    if "superblock" in checks:
        parts["superblock"] = _check_superblock(ctx, res, report, image)
    if "traversal" in checks:
        parts["traversal"] = _check_traversal(ctx, res, report, image)
    if "inodes" in checks:
        parts["inodes"] = _check_inodes(ctx, res, report, image, limit)
    if "extents" in checks:
        parts["extents"] = _check_extents(ctx, res, report, image, limit)
    if "content" in checks:
        parts["content"] = _check_content(ctx, res, report, image, limit)
    if "coverage" in checks and params.get("deleted", True):
        parts["coverage"] = _check_coverage(ctx, res, report, image)
    elapsed = round(time.time() - started, 1)
    bad = report.disagreed
    parts["agreed"] = report.agreed
    parts["compared_count"] = len(report.comparisons)
    parts["disagreed_count"] = len(bad)
    parts["disagreed"] = [c.as_dict() for c in bad]
    parts["fields"] = [c.as_dict() for c in report.comparisons]
    parts["commands"] = [c.as_dict() for c in report.commands]
    parts["seconds"] = elapsed
    res.data = parts
    path = to_json(ctx.work("exports") / "tsk_crosscheck.json", parts)
    res.export(path)
    log = ["# Sleuth Kit — independent second reader", f"# {tsk.version()}", f"# {image}", ""]
    log += [f"$ {c['command']}   -> exit {c['returncode']}, {c['lines']} lines, {c['seconds']}s" for c in parts["commands"]]
    log += ["", "## field comparisons", ""]
    log += [
        f"{'OK ' if c['agree'] else 'DIFF'}  {c['field']}: ours={c['ours']!r} tsk={c['theirs']!r} {c['note']}"
        for c in (x.as_dict() for x in report.comparisons)
    ]
    log_path = ctx.work("exports") / "tsk_crosscheck.log"
    log_path.write_text("\n".join(log) + "\n", encoding="utf-8")
    res.export(log_path)
    res.add(
        "ok" if not bad else "critical",
        f"Zgodność z Sleuth Kit: {report.agreed}/{len(report.comparisons)} pól"
        if not bad
        else f"Sleuth Kit nie zgodził się w {len(bad)}/{len(report.comparisons)} pól",
        detail="; ".join(f"{c.field_name}: {c.ours!r} vs {c.theirs!r}" for c in bad[:5])[:400] or None,
        values={
            "agreed": report.agreed,
            "compared": len(report.comparisons),
            "disagreed": len(bad),
            "tsk_version": tsk.version(),
            "seconds": elapsed,
        },
    )
    res.note(f"{elapsed}s, {len(report.commands)} wywołań narzędzi")
    return ctx.record(res)


register(
    ModuleSpec(
        id="tsk_crosscheck",
        category="image",
        title="mod.tsk_crosscheck.title",
        summary="mod.tsk_crosscheck.summary",
        params=[
            Param(
                key="check",
                label="Zakres",
                default="all",
                kind=CHOICE,
                choices=("all",) + ALL_CHECKS,
                help="all = superblock + traversal + inodes + content + coverage",
            ),
            Param(key="sample", label="Próbka plików", default=15, kind=INT, help="ile plików porównać bajt po bajcie"),
            Param(
                key="deleted",
                label="Policz usunięte",
                default=True,
                kind=BOOL,
                help="fls -d i ils: ile wpisów nasz reader nie widzi",
            ),
        ],
        run=run,
    )
)
