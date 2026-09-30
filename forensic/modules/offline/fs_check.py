# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""File system consistency check with ``e2fsck -fn`` (never repairs).

The output is classified: cosmetic optimisations, real inconsistencies and
unreadable metadata are counted separately, because ``e2fsck`` exit code 4 covers
all of them together.
"""

from __future__ import annotations

import re
import subprocess
import time

from ...core import fsformat, i18n, imagemount
from ...core.export import human_bytes
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import ModuleSpec, register

EXIT_MEANING = {
    0: "no errors",
    1: "errors corrected",
    2: "errors corrected, reboot needed",
    4: "errors left uncorrected",
    8: "operational error",
    16: "usage error",
    32: "cancelled by user",
    128: "shared library error",
}
CONTINUATION = re.compile(r"^(Fix|Optimize|Connect)\?\s*(no|yes)?$")

BUCKETS = (
    ("timestamp_pre1970", re.compile(r"Timestamp\(s\).*pre-1970"), "info"),
    ("extent_tree_short", re.compile(r"extent tree .*could be shorter"), "info"),
    ("free_blocks_count", re.compile(r"Free blocks count wrong"), "finding"),
    ("free_inodes_count", re.compile(r"Free inodes count wrong"), "finding"),
    ("directories_count", re.compile(r"Directories count wrong"), "finding"),
    ("unattached_inode", re.compile(r"Unattached inode"), "finding"),
    ("i_size_mismatch", re.compile(r"i_size is .* should be"), "finding"),
    ("bitmap_diff", re.compile(r"bitmap differences"), "finding"),
    ("unreadable", re.compile(r"could not|unable to read|Error|corrupt", re.I), "critical"),
)


def messages(lines: list[str]) -> list[str]:
    """Join e2fsck message lines with their 'Fix? no' continuation."""
    out: list[str] = []
    for raw in lines:
        text = raw.strip()
        if not text or text.startswith("$") or text.startswith("Warning:"):
            continue
        if text.startswith("Pass ") or text.startswith("exit="):
            continue
        if CONTINUATION.match(text) and out:
            out[-1] = f"{out[-1]}  [{text}]"
            continue
        out.append(text)
    return out


def classify(lines: list[str]) -> dict:
    """Bucket e2fsck messages by kind, keeping one sample per bucket."""
    buckets: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    severity: dict[str, str] = {}
    for text in messages(lines):
        for name, pattern, level in BUCKETS:
            if pattern.search(text):
                counts[name] = counts.get(name, 0) + 1
                buckets.setdefault(name, []).append(text)
                severity[name] = level
                break
        else:
            counts["other"] = counts.get("other", 0) + 1
            buckets.setdefault("other", []).append(text)
            severity.setdefault("other", "warn")
    buckets["_counts"] = counts  # type: ignore[assignment]
    buckets["_severity"] = severity  # type: ignore[assignment]
    return buckets


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("fs_check")
    image = ctx.image
    if not image.exists():
        res.add("critical", i18n.t("msg.image_missing"), str(image))
        return ctx.record(res)
    kind = fsformat.detect(image)
    if not kind["readable"]:
        # e2fsprogs does not know EROFS or F2FS and says so in its own dialect:
        # "other" and "unreadable" lines, a clean exit, and no indication that the
        # program it ran was for a different filesystem.  A report would carry
        # those counts as findings about this image, which is the same
        # confident-wrong-answer failure the format table was written to stop.
        # The notes in the format table are written as sentence fragments, because
        # that is how they are spliced into a longer message.  Here they start a
        # sentence, so the first letter is raised.
        note = kind["note"]
        detail = f"Rozpoznany jako {kind['name']}. {note[:1].upper()}{note[1:]}."
        extra = ""
        if kind["reader"] == "f2fs":
            from ...core.f2fs import F2fs, F2fsError

            try:
                fs = F2fs(str(image))
            except F2fsError as exc:
                extra = f" Czytnik F2FS też odmówił: {exc}"
            else:
                cp = fs.checkpoint
                extra = (
                    " e2fsck nie ma tu czego sprawdzać. Co jest zamiast tego: "
                    f"{fs.blocks} bloków po {fs.block_size} B, "
                    f"{fs.superblock['segment_count']} segmentów, "
                    f"checkpoint 0x{cp['checkpoint_ver']:x} z flagami "
                    f"{', '.join(cp['flag_names'])}; "
                    f"{cp['valid_block_count']} bloków poprawnych, "
                    f"{cp['free_segment_count']} segmentów wolnych."
                )
                fs.close()
        elif kind["reader"] == "erofs":
            extra = (
                " e2fsck nie ma tu czego sprawdzać — geometrię i drzewo EROFS "
                "czyta czytnik erofs, a zasięg treści zależy od kompresji."
            )
        res.add(
            "warn",
            f"Format systemu plików: {kind['name']} — e2fsck tego nie sprawdzi",
            detail=detail + extra,
            values={
                "kind": kind["kind"],
                "name": kind["name"],
                "reader": kind.get("reader", ""),
                "refused": True,
            },
        )
        return ctx.record(res)
    if not imagemount.sudo_ok():
        res.add(
            "warn",
            "e2fsck wymaga sudo",
            detail="Uruchom ręcznie: sudo e2fsck -fn <obraz>",
            values={"image": str(image)},
        )
        return ctx.record(res)
    e2fsck = imagemount.tool_path("e2fsck")
    if not e2fsck:
        res.add("warn", "e2fsck nie jest zainstalowany (e2fsprogs)", values={})
        return ctx.record(res)
    started = time.time()
    args = [e2fsck, "-fn", str(image)]
    proc = subprocess.run(args, capture_output=True, text=True, timeout=7200, check=False)
    output = (proc.stdout or "") + (proc.stderr or "")
    lines = output.splitlines()
    kinds = classify(lines)
    counts = dict(kinds.pop("_counts"))  # type: ignore[arg-type]
    levels = dict(kinds.pop("_severity"))  # type: ignore[arg-type]
    elapsed = round(time.time() - started, 1)
    log = "\n".join([f"$ {' '.join(args)}", f"exit={proc.returncode} ({EXIT_MEANING.get(proc.returncode, '?')})", output.strip()])
    path = ctx.work("exports") / "e2fsck.log"
    path.write_text(log + "\n", encoding="utf-8")
    res.export(path)
    res.data = {
        "counts": {
            "command": " ".join(args),
            "exit_code": proc.returncode,
            "exit_meaning": EXIT_MEANING.get(proc.returncode, "?"),
            "by_kind": counts,
            "seconds": elapsed,
            "image": str(image),
            "log": str(path),
        }
    }
    res.add(
        "info",
        "Podsumowanie e2fsck",
        values={
            "command": " ".join(args),
            "exit_code": proc.returncode,
            "exit_meaning": EXIT_MEANING.get(proc.returncode, "?"),
            "counts": counts,
            "image_size": human_bytes(image.stat().st_size),
            "seconds": elapsed,
            "log": str(path),
        },
    )
    substantive = {
        key: value
        for key, value in counts.items()
        if key not in ("timestamp_pre1970", "extent_tree_short")
    }
    if not substantive and proc.returncode in (0, 4):
        res.add("ok", "Tylko znane kosmetyczne komunikaty, brak błędów", values={"counts": counts})
    elif not substantive:
        res.add("warn", "e2fsck zakończył się kodem operacyjnym", values={"counts": counts})
    else:
        res.add(
            "finding",
            "e2fsck znalazł niesprawności (nic nie naprawiono, -n)",
            values={"exit_code": proc.returncode, "counts": counts},
        )
    for key, items in kinds.items():
        level = levels.get(key, "warn")
        label = f"{key} ×{counts.get(key, len(items))}"
        res.add(
            level,
            label,
            detail="; ".join(items[:3])[:400],
            values={"count": counts.get(key, len(items)), "samples": items[:3]},
        )
    res.note(f"exit {proc.returncode} w {elapsed}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="fs_check",
        category="image",
        title="mod.fs_check.title",
        summary="mod.fs_check.summary",
        params=[],
        run=run,
        needs_sudo=True,
    )
)
