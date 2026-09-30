# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Extract files (and SQLite sidecars) out of the image into the work directory."""

from __future__ import annotations

import hashlib
import re
import time
from pathlib import Path

from ...core.export import human_bytes, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, ModuleSpec, Param, register

SIDE_CARS = ("-wal", "-shm", "-journal")
DEFAULT_TARGETS = [
    "/system/users/0/accounts.db",
    "/system/users/0/accounts.db-journal",
    "/data/com.android.browser/app_miui_webview/Login Data",
    "/data/com.chrome.dev/app_chrome/Default/History",
]


def safe_name(path: str) -> str:
    """A single filename component for an in-image path.

    Every character outside ``[A-Za-z0-9._-]`` becomes an underscore, which
    keeps the result to one component: a ``/`` in an extracted name would put
    the file somewhere else in the work directory than the manifest says.  A
    name of ``.`` or ``..`` is the one case the substitution cannot catch,
    because dots are allowed — and as a path component ``..`` *is* the parent
    directory, so those two go to ``root`` like an empty path does.
    """
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/")) or "root"
    return "root" if name in (".", "..") else name


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("extract_file")
    raw_targets = params.get("path") or params.get("paths") or DEFAULT_TARGETS
    if isinstance(raw_targets, str):
        raw_targets = [p.strip() for p in raw_targets.split(",") if p.strip()]
    sidecars = bool(params.get("sidecars", True))
    dest_root = Path(params.get("dest") or (ctx.work("extracted")))
    dest_root.mkdir(parents=True, exist_ok=True)
    fs = ctx.fs()
    manifest = []
    for target in raw_targets:
        target = str(target).strip()
        started = time.time()
        try:
            inode = fs.resolve(target)
        except KeyError as exc:
            res.add("warn", f"Brak ścieżki: {target}", detail=str(exc))
            continue
        if not inode.is_reg:
            res.add("warn", f"To nie jest plik: {target}")
            continue
        blob = fs.read(inode)
        digest = hashlib.sha256(blob).hexdigest()
        out = dest_root / safe_name(target)
        out.write_bytes(blob)
        entry = {
            "source_path": target,
            "output": str(out),
            "size": len(blob),
            "size_human": human_bytes(len(blob)),
            "sha256": digest,
            "inode": inode.number,
            "mtime_utc": fs.stat(target)["mtime"],
            "seconds": round(time.time() - started, 2),
        }
        manifest.append(entry)
        companions = []
        if sidecars:
            for suffix in SIDE_CARS:
                sibling = target + suffix
                try:
                    sibling_inode = fs.resolve(sibling)
                except KeyError:
                    continue
                if not sibling_inode.is_reg:
                    continue
                sibling_blob = fs.read(sibling_inode)
                sibling_out = dest_root / safe_name(sibling)
                sibling_out.write_bytes(sibling_blob)
                companion = {
                    "source_path": sibling,
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
    res.data = {"count": len(manifest), "items": manifest}
    path = to_json(
        ctx.work("exports") / "extract_manifest.json", res.data, ctx.masker
    )
    res.export(path)
    if manifest:
        res.note(f"wyekstrahowano {len(manifest)} plik(ów)")
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
