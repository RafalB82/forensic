# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Create a case file for an image nobody has looked at yet.

A case is the record of what a device actually contained, so writing one
before the analysis would freeze a guess into a regression test.  This module
therefore only writes the parts that cannot be wrong — identity, geometry,
hash — and leaves every check marked ``todo`` with the value still empty, so
the first run of ``verify`` reports what is missing instead of pretending the
case is complete.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from ...core.export import human_bytes, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ._cases import CASES_DIR
from ..registry import BOOL, ModuleSpec, Param, register

TEMPLATE_CHECKS = [
    {
        "id": "image.superblock",
        "module": "image_info",
        "scopes": ["image", "all"],
        "note": "TODO: uzupelnić po uruchomieniu image_info",
        "params": {"hash": False},
        "expect": [
            {"path": "data.geometry.block_size", "equals": "TODO"},
            {"path": "data.geometry.blocks_count", "equals": "TODO"},
            {"path": "data.state.uuid", "equals": "TODO"},
        ],
    },
    {
        "id": "accounts.accounts_db",
        "module": "accounts_db",
        "scopes": ["accounts", "all"],
        "note": "TODO: liczba kont i terminy tokenow (bez wartosci sekretow)",
        "params": {},
        "expect": [{"path": "data.account_count", "equals": "TODO"}],
    },
    {
        "id": "timeline.fs",
        "module": "fs_timeline",
        "scopes": ["timeline", "all"],
        "note": "TODO: okno sesji zapisow w obrazie (próg since do dobrac)",
        "params": {"since": "2024-01-01"},
        "expect": [
            {"path": "data.count", "equals": "TODO"},
            {"path": "data.first_utc", "equals": "TODO"},
            {"path": "data.last_utc", "equals": "TODO"},
            {"path": "data.usage.packages", "equals": "TODO"},
        ],
    },
]


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("newcase")
    name = str(params.get("name") or ctx.config.case).strip()
    dest_dir = Path(str(params.get("dest") or CASES_DIR))
    overwrite = bool(params.get("overwrite", False))
    with_checks = bool(params.get("checks", True))
    hash_image = bool(params.get("hash", True))
    started = time.time()
    if not name or "/" in name:
        res.add("critical", f"Nieprawidłowa nazwa case'a: {name!r}")
        return ctx.record(res)
    try:
        fs = ctx.fs()
    except FileNotFoundError as exc:
        res.add("critical", "Brak obrazu", detail=str(exc))
        return ctx.record(res)
    target = dest_dir / f"{name}.public.json"
    exists = target.exists()
    if exists and not overwrite:
        res.add(
            "critical",
            f"{target.name} już istnieje",
            detail="ustaw overwrite=true, aby nadpisać, albo podaj inną nazwę",
            values={"path": str(target)},
        )
        return ctx.record(res)
    superblock = fs.superblock
    geometry = {
        "block_size": superblock.get("block_size"),
        "blocks_count": superblock.get("blocks_count"),
        "size_bytes": (superblock.get("block_size") or 0) * (superblock.get("blocks_count") or 0),
        "inodes_count": superblock.get("inodes_count"),
        "groups": len(getattr(fs, "_groups", []) or []),
    }
    image_path = ctx.image
    stat = image_path.stat()
    case = {
        "name": name,
        "description": str(params.get("description") or f"{image_path.name} — case wygenerowany {time.strftime('%Y-%m-%d')}",),
        "image": str(image_path),
        "image_size": stat.st_size,
        "root": str(params.get("root") or "/data"),
        "notes": "Wartosci TODO w checkach trzeba uzupelnic po analizie; verify zglosi je jako niezgodne.",
        "generated_by": "forensic newcase",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "geometry": geometry,
        "uuid": superblock.get("uuid"),
        "state": superblock.get("state_name") or superblock.get("state"),
        "checks": TEMPLATE_CHECKS if with_checks else [],
    }
    if hash_image:
        from .image_info import sha256_file

        case["image_sha256"] = sha256_file(image_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(case, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    res.add(
        "ok" if not exists else "warn",
        f"Case zapisany: {target.name}",
        detail=(
            f"geometria i {'SHA-256' if hash_image else 'bez SHA-256'} zapisane; "
            f"{len(case['checks'])} checków z wartościami TODO do uzupełnienia"
        ),
        values={
            "path": str(target),
            "name": name,
            "overwritten": exists,
            "geometry": geometry,
            "uuid": case.get("uuid"),
            "image_size": stat.st_size,
            "size_human": human_bytes(stat.st_size),
            "sha256": case.get("image_sha256", ""),
            "sha256_computed": hash_image,
            "checks": len(case["checks"]),
            "seconds": round(time.time() - started, 2),
            "next_step": f"./forensic.py --cli verify --case {target}",
        },
        artifacts=[str(target)],
    )
    res.data = {"path": str(target), "case": case, "overwritten": exists}
    res.export(to_json(ctx.work("exports") / "newcase.json", res.data, ctx.masker))
    return ctx.record(res)


register(
    ModuleSpec(
        id="newcase",
        category="report",
        title="mod.newcase.title",
        summary="mod.newcase.summary",
        params=[
            Param(key="name", label="param.case_name", default="", kind="str"),
            Param(key="dest", label="param.dest", default="", kind="path"),
            Param(key="description", label="param.description", default="", kind="str"),
            Param(key="root", label="param.root", default="/data", kind="str"),
            Param(key="hash", label="param.hash", default=True, kind=BOOL),
            Param(key="checks", label="param.template_checks", default=True, kind=BOOL),
            Param(key="overwrite", label="param.overwrite", default=False, kind=BOOL),
        ],
        run=run,
        needs_image=True,
    )
)
