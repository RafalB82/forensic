# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Mount the image read-only (optional; the ext4 reader works without it)."""

from __future__ import annotations

import time

from ...core import i18n
from ...core import imagemount
from ...core.export import to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, ModuleSpec, Param, register


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("mount_ro")
    image = ctx.image
    mountpoint = params.get("mountpoint") or ctx.config.mountpoint
    norecovery = bool(params.get("norecovery", True))
    options = ctx.config.default_mount_options
    if not norecovery and "norecovery" in options:
        options = options.replace(",norecovery", "")
    existing = imagemount.find_mount_for(str(image))
    if existing is not None:
        health = imagemount.health(existing.mountpoint)
        res.add(
            "ok",
            i18n.t("msg.already_mounted"),
            detail=existing.mountpoint,
            values={**existing.as_dict(), "health": health},
        )
        return ctx.record(res)
    if not imagemount.have("mount"):
        res.add("warn", i18n.t("msg.mount_needs_sudo"), values={"tool": "mount"})
        return ctx.record(res)
    if not imagemount.sudo_ok():
        res.add(
            "warn",
            i18n.t("msg.mount_needs_sudo"),
            detail="Analiza działa bez montowania (parser ext4 w Pythonie).",
        )
        return ctx.record(res)
    started = time.time()
    keep = bool(params.get("keep_mounted", False))
    info, message = imagemount.mount(str(image), str(mountpoint), options, keep=keep)
    if info is None:
        res.add("warn", "Montowanie nie powiodło się", detail=message, values={"options": options})
        return ctx.record(res)
    health = imagemount.health(info.mountpoint)
    res.add(
        "ok" if health["ok"] else "warn",
        i18n.t("msg.mounted"),
        detail=f"{info.mountpoint} ({info.options})",
        values={**info.as_dict(), "health": health, "seconds": round(time.time() - started, 1)},
    )
    path = to_json(ctx.work("exports") / "mount.json", info.as_dict(), ctx.masker)
    res.export(path)
    return ctx.record(res)


register(
    ModuleSpec(
        id="mount_ro",
        category="image",
        title="mod.mount_ro.title",
        summary="mod.mount_ro.summary",
        params=[
            Param(key="mountpoint", label="param.mountpoint", default="", kind="path"),
            Param(key="norecovery", label="param.norecovery", default=True, kind=BOOL),
            Param(
                key="keep_mounted",
                label="Zostaw zamontowane po wyjściu",
                default=False,
                kind=BOOL,
            ),
        ],
        run=run,
        needs_sudo=True,
    )
)
