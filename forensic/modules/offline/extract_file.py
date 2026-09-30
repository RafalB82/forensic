# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Extract files (and SQLite sidecars) out of the image into the work directory."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from ...core.evidence import TruncatedEvidenceError
from ...core.export import human_bytes, to_json
from ...core.naming import flat_name, safe_name, unique_names
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, ModuleSpec, Param, register

__all__ = [
    "STATUS_ABSENT",
    "STATUS_PRESENT",
    "STATUS_TRUNCATED",
    "flat_name",
    "run",
    "safe_name",
    "unique_names",
]

SIDE_CARS = ("-wal", "-shm", "-journal")
DEFAULT_TARGETS = [
    "/system/users/0/accounts.db",
    "/system/users/0/accounts.db-journal",
    "/data/com.android.browser/app_miui_webview/Login Data",
    "/data/com.chrome.dev/app_chrome/Default/History",
]

#: What happened to one requested path.  Three words, not two, because the third
#: case used to be silently folded into the first: a path whose data blocks lie
#: past the end of a truncated image raised the same "no such path" as a path the
#: device never had, and the difference between *absent* and *we could not read
#: what is there* is the difference between a clean negative and a gap in the
#: evidence.
STATUS_PRESENT = "PRESENT"
STATUS_ABSENT = "ABSENT"
STATUS_TRUNCATED = "TRUNCATED"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("extract_file")
    raw_targets = params.get("path") or params.get("paths") or DEFAULT_TARGETS
    if isinstance(raw_targets, str):
        raw_targets = [p.strip() for p in raw_targets.split(",") if p.strip()]
    sidecars = bool(params.get("sidecars", True))
    dest_root = Path(params.get("dest") or (ctx.work("extracted")))
    dest_root.mkdir(parents=True, exist_ok=True)
    fs = ctx.fs()
    manifest: list[dict] = []

    # Every requested path, sidecars included, gets its name decided before the
    # first byte is written — so uniqueness is a property of the whole batch and
    # not of the order the loop happened to reach things in.
    wanted: list[str] = []
    for raw in raw_targets:
        target = str(raw).strip()
        wanted.append(target)
        if sidecars:
            wanted += [target + suffix for suffix in SIDE_CARS]
    names = unique_names(wanted)

    for target in raw_targets:
        target = str(target).strip()
        started = time.time()
        try:
            inode = fs.resolve(target)
        except KeyError as exc:
            res.add(
                "info",
                f"Brak ścieżki: {target}",
                detail=f"{STATUS_ABSENT} — ścieżki nie ma w obrazie",
                values={"path": target, "status": STATUS_ABSENT},
            )
            manifest.append({"source_path": target, "status": STATUS_ABSENT, "detail": str(exc)})
            continue
        if not inode.is_reg:
            res.add(
                "info",
                f"To nie jest plik: {target}",
                detail=f"{STATUS_ABSENT} — inode {inode.number} nie jest plikiem regularnym",
                values={"path": target, "status": STATUS_ABSENT, "inode": inode.number},
            )
            manifest.append(
                {"source_path": target, "status": STATUS_ABSENT, "detail": "not a regular file", "inode": inode.number}
            )
            continue
        try:
            blob = fs.read(inode)
        except TruncatedEvidenceError as exc:
            # The one case that must never be recorded as a successful
            # extraction.  Nothing is written and nothing is hashed: the old
            # reader returned a zero-filled buffer of the declared length here,
            # which this manifest would then have certified with a SHA-256.
            res.add(
                "warn",
                f"Obraz ucięty, nie da się odczytać: {target}",
                detail=f"{STATUS_TRUNCATED} — {exc}",
                values={"path": target, "status": STATUS_TRUNCATED, "inode": inode.number},
            )
            manifest.append(
                {"source_path": target, "status": STATUS_TRUNCATED, "detail": str(exc), "inode": inode.number}
            )
            continue
        digest = hashlib.sha256(blob).hexdigest()
        out = dest_root / names[target]
        out.write_bytes(blob)
        entry: dict = {
            "source_path": target,
            "status": STATUS_PRESENT,
            "output": str(out),
            "size": len(blob),
            "size_human": human_bytes(len(blob)),
            "sha256": digest,
            "inode": inode.number,
            "mtime_utc": fs.stat(target)["mtime"],
            "seconds": round(time.time() - started, 2),
        }
        manifest.append(entry)
        companions: list[dict] = []
        if sidecars:
            for suffix in SIDE_CARS:
                sibling = target + suffix
                try:
                    sibling_inode = fs.resolve(sibling)
                except KeyError:
                    continue
                if not sibling_inode.is_reg:
                    continue
                try:
                    sibling_blob = fs.read(sibling_inode)
                except TruncatedEvidenceError as exc:
                    res.add(
                        "warn",
                        f"Obraz ucięty, nie da się odczytać: {sibling}",
                        detail=f"{STATUS_TRUNCATED} — {exc}",
                        values={"path": sibling, "status": STATUS_TRUNCATED},
                    )
                    manifest.append(
                        {"source_path": sibling, "status": STATUS_TRUNCATED, "detail": str(exc)}
                    )
                    continue
                sibling_out = dest_root / names[sibling]
                sibling_out.write_bytes(sibling_blob)
                companion: dict = {
                    "source_path": sibling,
                    "status": STATUS_PRESENT,
                    "output": str(sibling_out),
                    "size": len(sibling_blob),
                    "sha256": hashlib.sha256(sibling_blob).hexdigest(),
                }
                companions.append(companion)
                manifest.append(companion)
        res.add(
            "ok",
            f"Wyekstrahowano: {target}",
            detail=f"{entry['size_human']} → {out}",
            values={**entry, "companions": [c["source_path"] for c in companions]},
            artifacts=[str(out)] + [c["output"] for c in companions],
        )
    res.data = {
        "count": len(manifest),
        "present": sum(1 for m in manifest if m["status"] == STATUS_PRESENT),
        "absent": sum(1 for m in manifest if m["status"] == STATUS_ABSENT),
        "truncated": sum(1 for m in manifest if m["status"] == STATUS_TRUNCATED),
        "image_truncated_bytes": getattr(fs, "truncated_bytes", 0),
        "items": manifest,
    }
    path = to_json(
        ctx.work("exports") / "extract_manifest.json", res.data, ctx.masker
    )
    res.export(path)
    read = res.data["present"]
    if read:
        res.note(f"wyekstrahowano {read} plik(ów)")
    missing = res.data["truncated"]
    if missing:
        res.note(
            f"{missing} plik(ów) nie odczytano — obraz jest ucięty, to brak dowodu, "
            f"nie brak pliku; patrz extract_manifest.json"
        )
    return ctx.record(res)


register(
    ModuleSpec(
        id="extract_file",
        category="image",
        title="mod.extract_file.title",
        summary="mod.extract_file.summary",
        params=[
            Param(
                key="path",
                label="param.path",
                default=",".join(DEFAULT_TARGETS),
                kind="str",
                help="Lista ścieżek oddzielona przecinkiem",
            ),
            Param(key="dest", label="param.dest", default="", kind="path"),
            Param(key="sidecars", label="param.sidecars", default=True, kind=BOOL),
        ],
        run=run,
    )
)
