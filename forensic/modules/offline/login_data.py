# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Chromium ``Login Data`` databases: saved logins and how they are protected."""

from __future__ import annotations

import time
from pathlib import Path

from ...core import i18n
from ...core.chromium import SECRET_VERDICT_BASIS, login_data
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.masking import password_of
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

DEFAULT_TARGETS = [
    "/data/com.android.browser/app_miui_webview/Login Data",
    "/data/com.chrome.dev/app_chrome/Default/Login Data",
]


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("login_data")
    raw = params.get("path") or DEFAULT_TARGETS
    targets = [t.strip() for t in str(raw).split(",") if t.strip()] if isinstance(raw, str) else list(raw)
    started = time.time()
    rows: list[dict] = []
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
        report = login_data(local)
        report["target"] = target
        entries = report.pop("entries", [])
        databases.append(report)
        res.add(
            "ok",
            f"{Path(target).name}: {report.get('count', 0)} zapisanych logowań",
            detail=(
                f"jawnych {report.get('plaintext', 0)}, zaszyfrowanych {report.get('encrypted', 0)}, "
                f"pustych {report.get('empty', 0)}"
            ),
            values={
                "path": str(local),
                "target": target,
                "entries": report.get("count", 0),
                "plaintext": report.get("plaintext", 0),
                "encrypted": report.get("encrypted", 0),
                "empty": report.get("empty", 0),
                "error": report.get("error"),
            },
            artifacts=[str(local)],
        )
        for entry in entries:
            item = entry.as_dict(reveal=ctx.masker.reveal, keep_tail=4)
            item["target"] = target
            item["password"] = entry.password_text
            rows.append(item)
            severity = "critical" if entry.verdict.startswith("jawny") and entry.password_text else "info"
            res.add(
                severity,
                f"Zapisane logowanie: {entry.origin_url}",
                detail=(
                    f"użytkownik: {entry.username or '(pusty)'} · "
                    f"pole: {entry.password_field or '?'} · {entry.verdict} — {SECRET_VERDICT_BASIS}"
                ),
                values={
                    "origin_url": entry.origin_url,
                    "action_url": entry.action_url,
                    "username": entry.username,
                    "password": password_of(entry.password_text) if entry.password_text else None,
                    "verdict": entry.verdict,
                    "verdict_basis": SECRET_VERDICT_BASIS,
                    "date_created": entry.date_created,
                    "times_used": entry.times_used,
                    "target": target,
                },
            )
    plaintext = [r for r in rows if r["password_verdict"].startswith("jawny") and r["password"]]
    if plaintext:
        res.add(
            "critical",
            f"Bez szyfrowania: {len(plaintext)} haseł w postaci jawnej",
            detail=(
                "kolumna password_value nie ma prefiksu v10/v20, a wartość jest czytelnym tekstem — "
                "to nie jest Android keystore obfuscation, hasła leżą w pliku jak są"
            ),
            values={
                "count": len(plaintext),
                "sites": sorted({r["origin_url"] for r in plaintext}),
                "usernames": sorted({r["username"] for r in plaintext if r["username"]}),
            },
        )
    exported = [
        {**r, "password": password_of(r["password"]) if r.get("password") else r.get("password")}
        for r in rows
    ]
    res.data = {
        "databases": databases,
        "entries": exported,
        "plaintext_passwords": len(plaintext),
        "targets": targets,
    }
    res.export(
        to_csv(
            ctx.work("exports") / "login_data.csv",
            ["target", "origin_url", "username", "password", "verdict", "date_created"],
            [
                [
                    r["target"],
                    r["origin_url"],
                    r["username"],
                    r["password"],
                    r["password_verdict"],
                    r["date_created"],
                ]
                for r in exported
            ],
            ctx.masker,
        )
    )
    res.export(to_json(ctx.work("exports") / "login_data.json", res.data, ctx.masker))
    res.note(f"{len(rows)} wpisów, {len(plaintext)} jawnych, {time.time() - started:.1f}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="login_data",
        category="accounts",
        title="mod.login_data.title",
        summary="mod.login_data.summary",
        params=[Param(key="path", label="param.path", default=",".join(DEFAULT_TARGETS), kind="str")],
        run=run,
    )
)
