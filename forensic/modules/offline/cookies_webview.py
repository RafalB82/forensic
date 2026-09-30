# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Chromium cookie stores: which session cookies exist and are they protected."""

from __future__ import annotations

import time
from pathlib import Path

from ...core import i18n
from ...core.chromium import SECRET_VERDICT_BASIS, cookies, decode_facebook_xs
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.masking import token_of
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

DEFAULT_TARGETS = [
    "/data/com.android.browser/app_miui_webview/Cookies",
    "/data/com.chrome.dev/app_chrome/Default/Cookies",
]
SESSION_COOKIES = ("xs", "c_user", "datr", "sb", "ss", "fr", "wd")


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("cookies_webview")
    raw = params.get("path") or DEFAULT_TARGETS
    targets = [t.strip() for t in str(raw).split(",") if t.strip()] if isinstance(raw, str) else list(raw)
    started = time.time()
    found: list[dict] = []
    databases: list[dict] = []
    for target in targets:
        try:
            local = Path(target)
            if not local.exists():
                local = ctx.materialise(target)
        except KeyError:
            res.add("warn", f"Brak ścieżki w obrazie: {target}")
            continue
        except FileNotFoundError as exc:
            res.add("critical", i18n.t("msg.no_image"), detail=str(exc))
            continue
        report = cookies(local)
        report["target"] = target
        rows_all = report.pop("rows", [])
        databases.append(report)
        res.add(
            "ok" if report.get("count") else "warn",
            f"{Path(target).name}: {report.get('count', 0)} ciasteczek",
            detail=f"hosty: {len(report.get('hosts', []))}",
            values={
                "path": str(local),
                "target": target,
                "cookies": report.get("count", 0),
                "hosts": report.get("hosts", [])[:20],
                "error": report.get("error"),
            },
            artifacts=[str(local)],
        )
        for row in rows_all:
            item = dict(row)
            item["target"] = target
            if row["name"] in SESSION_COOKIES and row["value"]:
                found.append(item)
                res.add(
                    "info",
                    f"{row['host_key']} → {row['name']}",
                    detail=(
                        f"wartość jawna ({row['verdict']}), ważne do "
                        f"{row['expires_utc'] or 'sesji'} — {SECRET_VERDICT_BASIS}"
                    ),
                    values={
                        "host": row["host_key"],
                        "name": row["name"],
                        "value": token_of(row["value"]),
                        "verdict": row["verdict"],
                        "expires_utc": row["expires_utc"],
                        "last_access_utc": row["last_access_utc"],
                        "target": target,
                    },
                )
            if row["name"] == "xs" and row["value"]:
                decoded = decode_facebook_xs(row["value"])
                res.add(
                    "finding",
                    "Ciasteczko sesyjne Facebooka (xs)",
                    detail="; ".join(f"{k}={v}" for k, v in decoded.items() if k not in ("raw", "note")),
                    values={**decoded, "host": row["host_key"], "target": target},
                )
    if found:
        res.add(
            "critical",
            f"Ciasteczka sesyjne w jawnej postaci: {len(found)}",
            detail=(
                "kolumna encrypted_value jest pusta, a wartość leży w value — sesja facebook.com "
                "jest zapisana bez szyfrowania"
            ),
            values={
                "count": len(found),
                "hosts": sorted({item["host_key"] for item in found}),
                "names": sorted({item["name"] for item in found}),
            },
        )
    res.data = {"databases": databases, "session_cookies": found, "targets": targets}
    res.export(
        to_csv(
            ctx.work("exports") / "cookies.csv",
            ["target", "host_key", "name", "value", "verdict", "expires_utc", "last_access_utc"],
            [
                [
                    d["target"],
                    row["host_key"],
                    row["name"],
                    row["value"],
                    row["verdict"],
                    row["expires_utc"],
                    row["last_access_utc"],
                ]
                for d in databases
                for row in (d.get("rows") or [])
            ],
            ctx.masker,
        )
    )
    res.export(to_json(ctx.work("exports") / "cookies.json", res.data, ctx.masker))
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="cookies_webview",
        category="accounts",
        title="mod.cookies_webview.title",
        summary="mod.cookies_webview.summary",
        params=[Param(key="path", label="param.path", default=",".join(DEFAULT_TARGETS), kind="str")],
        run=run,
    )
)
