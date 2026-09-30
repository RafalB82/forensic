# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Extract files (and SQLite sidecars) out of the image into the work directory."""

from __future__ import annotations

import time
from pathlib import Path

from ...core.evidence import DEFAULT_STREAM_LIMIT, TruncatedEvidenceError, copy_stream
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
    stream_limit = int(params.get("max_bytes") or DEFAULT_STREAM_LIMIT)
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
        out = dest_root / names[target]
        try:
            written = copy_stream(
                lambda offset, length: fs.read_at(inode, offset, length),
                out,
                size=inode.size,
                limit=stream_limit,
            )
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
        digest = written["sha256"]
        entry: dict = {
            "source_path": target,
            "status": STATUS_PRESENT,
            "output": str(out),
            "size": written["bytes"],
            "size_human": human_bytes(written["bytes"]),
            "sha256": digest,
            "inode": inode.number,
            "declared_size": written["declared_size"],
            "mtime_utc": fs.stat(target)["mtime"],
            "seconds": round(time.time() - started, 2),
        }
        if not written["complete"]:
            # ``i_size`` is a field in the image.  Believing a corrupted one means
            # writing its value in zeros, and reporting a prefix as if it were the
            # file is the same defect as padding a short read — so this is its own
            # status, not a successful extraction of something smaller.
            entry["status"] = STATUS_TRUNCATED
            entry["detail"] = (
                f"i_size deklaruje {written['declared_size']} B, wyciągnięto "
                f"{written['bytes']} B (limit {stream_limit} B)"
            )
            manifest.append(entry)
            res.add(
                "warn",
                f"Przycięty do limitu: {target}",
                detail=f"{STATUS_TRUNCATED} — {entry['detail']}",
                values=entry,
            )
            continue
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
                sibling_out = dest_root / names[sibling]
                node_for_sidecar = sibling_inode
                try:
                    side = copy_stream(
                        lambda offset, length: fs.read_at(node_for_sidecar, offset, length),
                        sibling_out,
                        size=sibling_inode.size,
                        limit=stream_limit,
                    )
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
                companion: dict = {
                    "source_path": sibling,
                    "status": STATUS_PRESENT if side["complete"] else STATUS_TRUNCATED,
                    "output": str(sibling_out),
                    "size": side["bytes"],
                    "declared_size": side["declared_size"],
                    "sha256": side["sha256"],
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
            Param(
                key="max_bytes",
                label="Limit bajtów na plik (0 = bez limitu)",
                default=0,
                kind="str",
                help=(
                    "i_size pochodzi z obrazu, więc uszkodzone pole potrafi kazać "
                    "zapisać terabajty zer. Limit przerywa to i raportuje plik jako "
                    "nie w pełni wyekskstrahowany."
                ),
            ),
        ],
        run=run,
    )
)
