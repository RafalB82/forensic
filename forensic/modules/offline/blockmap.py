# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Block map: which file owns a given image offset, and where that offset lives
inside the file.  The index is cached as JSON in the work directory."""

from __future__ import annotations

from pathlib import Path

from ...core import i18n
from ...core.blockmap import DEFAULT_SCOPE, BlockIndex
from ...core.export import human_bytes, to_json
from ...core.ext4 import Ext4Error
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, INT, LIST, ModuleSpec, Param, register

CACHE_NAME = "blockmap.json"


def cache_path(ctx: Ctx) -> Path:
    return ctx.work("cache") / CACHE_NAME


def _clean(value: object) -> str:
    text = str(value).strip().strip("[]").strip()
    return text.strip("'\"").strip()


def scope_from(ctx: Ctx, params: dict) -> list[str]:
    raw = params.get("scope") or ctx.config.blockmap_scope or DEFAULT_SCOPE
    if isinstance(raw, (list, tuple)):
        items = [_clean(x) for x in raw]
    else:
        items = [_clean(part) for part in str(raw).split(",")]
    return [item for item in items if item]


def get_index(ctx: Ctx, params: dict, res: ModuleResult) -> BlockIndex | None:
    """Load the cached index or build it, depending on parameters.

    A cache built for a **different image** is not used, and saying so is part of
    the result.  The cache sits beside the case rather than beside the image, so
    it outlives any switch of image — and answering "which file owns this offset"
    out of another filesystem's index produces a path, a byte offset and a file
    size, none of which are wrong-looking and all of which are about the wrong
    device.
    """
    cache = cache_path(ctx)
    use_cache = bool(params.get("use_cache", True))
    force = bool(params.get("force", False))
    try:
        image_size = ctx.image.stat().st_size
    except OSError:
        image_size = 0
    if use_cache and cache.exists() and not force:
        try:
            index = BlockIndex.load(str(cache))
        except Exception:
            index = None
        if index is not None:
            if index.matches(str(ctx.image), image_size):
                res.add(
                    "ok", i18n.t("msg.index_cached"), values=index.summary(),
                    artifacts=[str(cache)],
                )
                return index
            res.add(
                "warn",
                "Indeks bloków w cache pochodzi z innego obrazu — pominięty",
                detail=(
                    f"cache: {index.image} "
                    f"({human_bytes(index.image_size)}); "
                    f"teraz: {ctx.image} ({human_bytes(image_size)})"
                ),
                values={"cached_image": index.image, "image": str(ctx.image)},
                artifacts=[str(cache)],
            )
    scope = scope_from(ctx, params)

    def progress(files: int, path: str) -> None:
        ctx.log(f"{files} plików … {path}")

    ctx.log("Budowanie indeksu bloków …")
    try:
        index = BlockIndex.build(ctx.fs(), scope=scope, progress=progress)
    except Ext4Error as exc:
        from ...core import fsformat

        kind = fsformat.detect(ctx.image)
        res.add(
            "warn",
            f"Format {kind['name']} — ten indeks jest tylko dla ext4",
            detail=(
                f"{exc} Pytanie „do którego pliku należą te bajty” wymaga czytnika "
                f"ext4; dla {kind['name']} ten moduł nie ma odpowiedzi."
                if kind["kind"] == fsformat.UNKNOWN
                else f"{exc}"
            ),
            values={"kind": kind["kind"], "name": kind["name"], "refused": True},
        )
        return None
    index.save(str(cache))
    res.add(
        "ok",
        i18n.t("msg.index_built"),
        values={**index.summary(), "scope": scope},
        artifacts=[str(cache)],
    )
    gaps = len(index.skipped) + len(index.walk_errors)
    if gaps:
        res.add(
            "warn",
            f"Pominięte rekordy: {gaps}",
            detail=(
                f"{len(index.walk_errors)} katalogów nie dało się wypisać, "
                f"{len(index.skipped)} plików nie dało się przypisać do bloków. "
                "Bloki, których nikt nie przypisał do pliku, wyglądają w mapie jak "
                "wolne — pytanie „do którego pliku należą te bajty” ma wtedy "
                "odpowiedź „do żadnego”, która jest prawdziwa tylko połowicznie"
            ),
            values={
                "skipped": len(index.skipped),
                "walk_errors": len(index.walk_errors),
                "detail": index.skipped[:5] or index.walk_errors[:5],
            },
        )
    res.note(f"build {index.build_seconds:.1f}s")
    return index


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("blockmap")
    mode = str(params.get("mode", "lookup"))
    if mode == "summary":
        try:
            fs = ctx.fs()
        except Exception as exc:
            res.add("critical", i18n.t("msg.no_image"), detail=str(exc))
            return ctx.record(res)
        cache = cache_path(ctx)
        values = {
            "block_size": fs.block_size,
            "image": str(ctx.image),
            "cache": str(cache),
            "cache_exists": cache.exists(),
        }
        if cache.exists():
            try:
                values["index"] = BlockIndex.load(str(cache)).summary()
            except Exception as exc:
                values["error"] = str(exc)
        res.data = values
        res.add("info", "Stan indeksu bloków", values=values)
        return ctx.record(res)
    if mode == "file":
        path = str(params.get("path", "")).strip()
        if not path:
            res.add("warn", "Brak ścieżki", detail="param.path")
            return ctx.record(res)
        fs = ctx.fs()
        stat = fs.stat(path)
        extents = []
        inode = fs.resolve(path)
        for extent in inode.extents:
            extents.append(
                {
                    "logical": extent.logical,
                    "physical": extent.physical,
                    "count": extent.count,
                    "image_offset_start": extent.physical * fs.block_size,
                    "image_offset_end": (extent.physical + extent.count) * fs.block_size,
                }
            )
        res.data = {"stat": stat, "extents": extents}
        res.add("info", f"Bloki pliku: {path}", values=res.data)
        return ctx.record(res)
    offset = params.get("offset")
    index = get_index(ctx, params, res)
    if index is None:
        return ctx.record(res)
    if offset in (None, ""):
        values: list = []
    elif isinstance(offset, (list, tuple)):
        values = list(offset)
    else:
        values = [offset]
    rows = []
    for item in values:
        found = index.owner_at(int(item))
        if found is None:
            rows.append({"offset": int(item), "path": None, "note": i18n.t("msg.owner_unknown")})
        else:
            found["human"] = human_bytes(found["image_offset"])
            rows.append(found)
    if not values:
        res.add("warn", "Brak offsetu do sprawdzenia", detail="param.block")
        return ctx.record(res)
    severity = "ok" if any(row.get("path") for row in rows) else "warn"
    res.add(
        severity,
        "Offset → plik",
        values={"lookups": rows, "index": index.summary()},
    )
    res.data = {"lookups": rows, "index": index.summary()}
    path_out = to_json(
        ctx.work("exports") / "blockmap_lookup.json", res.data, ctx.masker
    )
    res.export(path_out)
    return ctx.record(res)


register(
    ModuleSpec(
        id="blockmap",
        category="image",
        title="mod.blockmap.title",
        summary="mod.blockmap.summary",
        params=[
            Param(
                key="mode",
                label="Tryb (lookup|file|summary)",
                default="lookup",
                kind="choice",
                choices=("lookup", "file", "summary"),
            ),
            Param(key="offset", label="param.block", default="", kind=INT),
            Param(key="path", label="param.path", default="", kind="path"),
            Param(key="scope", label="param.scope", default=[], kind=LIST),
            Param(key="use_cache", label="Użyj cache", default=True, kind=BOOL),
            Param(key="force", label="Przebuduj indeks", default=False, kind=BOOL),
        ],
        run=run,
    )
)
