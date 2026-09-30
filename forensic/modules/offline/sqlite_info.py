# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""First-pass information about a SQLite database, from the image or a copy."""

from __future__ import annotations

import time

from ...core import i18n, sqlite_tools
from ...core.export import human_bytes, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import INT, ModuleSpec, Param, register

DEFAULT_TARGETS = [
    "/system/users/0/accounts.db",
    "/data/com.chrome.dev/app_chrome/Default/History",
]


def re_safe(path: str) -> str:
    import re

    return re.sub(r"[^A-Za-z0-9._-]+", "_", path.strip("/")) or "root"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("sqlite_info")
    raw = params.get("path") or DEFAULT_TARGETS
    targets = [t.strip() for t in str(raw).split(",") if t.strip()] if isinstance(raw, str) else list(raw)
    sample = int(params.get("sample", 3) or 3)
    for target in targets:
        started = time.time()
        try:
            local = ctx.materialise(target)
        except KeyError:
            res.add("warn", f"Brak ścieżki w obrazie: {target}")
            continue
        except FileNotFoundError as exc:
            res.add("critical", i18n.t("msg.no_image"), detail=str(exc))
            continue
        report = sqlite_tools.quicklook(local, sample=sample)
        report["target"] = target
        header = report.get("header", {})
        if not header.get("is_sqlite"):
            res.add("warn", f"To nie jest baza SQLite: {target}", values={"path": str(local)})
            continue
        values = {
            "path": str(local),
            "size": human_bytes(header.get("size", 0)),
            "page_size": header.get("page_size"),
            "page_count": header.get("page_count_real"),
            "text_encoding": header.get("text_encoding"),
            "journal_mode_wal": header.get("journal_mode_wal"),
            "freelist_records": header.get("freelist_records"),
            "integrity": report.get("integrity"),
            "tables": len(report.get("tables", [])),
            "non_empty_tables": report.get("non_empty_tables"),
            "companions": list(report.get("companions", {}).keys()),
            "seconds": round(time.time() - started, 2),
        }
        severity = "ok" if report.get("integrity") == "ok" else "warn"
        res.add(
            severity,
            f"SQLite: {target}",
            detail=f"integrity: {report.get('integrity')}",
            values=values,
            artifacts=[str(local)],
        )
        if report.get("integrity_messages") and report.get("integrity") != "ok":
            res.add("finding", "Komunikaty integralności", values={"messages": report["integrity_messages"]})
        res.data = {"target": target, "report": report}
        out = to_json(
            ctx.work("exports") / f"sqlite_{re_safe(target)}.json", report, ctx.masker
        )
        res.export(out)
    return ctx.record(res)


register(
    ModuleSpec(
        id="sqlite_info",
        category="image",
        title="mod.sqlite_info.title",
        summary="mod.sqlite_info.summary",
        params=[
            Param(key="path", label="param.path", default=",".join(DEFAULT_TARGETS), kind="str"),
            Param(key="sample", label="Próbki na tabelę", default=3, kind=INT),
        ],
        run=run,
    )
)
