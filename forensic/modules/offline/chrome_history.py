# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Chromium ``History``: browsing timeline, search terms and account hints."""

from __future__ import annotations

import time
from pathlib import Path

from ...core import i18n
from ...core.chromium import HEURISTIC, history
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

DEFAULT_TARGET = "/data/com.chrome.dev/app_chrome/Default/History"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("chrome_history")
    raw = params.get("path") or DEFAULT_TARGET
    targets = [t.strip() for t in str(raw).split(",") if t.strip()] if isinstance(raw, str) else list(raw)
    started = time.time()
    reports: list[dict] = []
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
        report = history(local)
        report["target"] = target
        report.pop("search_terms", None)
        report.pop("sessions", None)
        report.pop("identity_hints", None)
        report.pop("visits_per_day", None)
        reports.append(report)
        counts = report.get("counts", {})
        res.add(
            "ok",
            f"Historia: {Path(target).name}",
            detail=(
                f"URL-i {report.get('url_count', 0)}, wizyty {counts.get('visits', 0)}, "
                f"wyszukiwania {counts.get('keyword_search_terms', 0)}, sesje {len(history(local).get('sessions', []))}"
            ),
            values={
                "path": str(local),
                "target": target,
                "urls": report.get("url_count"),
                "visits": counts.get("visits"),
                "search_terms": counts.get("keyword_search_terms"),
                "downloads": counts.get("downloads"),
                "first_visit": report.get("first_visit_time"),
                "last_visit": report.get("last_visit_time"),
            },
            artifacts=[str(local)],
        )
        full = history(local)
        terms = full.get("search_terms", [])
        unique = {item["term"] for item in terms}
        if terms:
            res.add(
                "info",
                f"Zapytania w wyszukiwarkach: {len(terms)} wpisów, {len(unique)} unikalnych",
                detail=f"zakres {terms[-1]['last_visit']} … {terms[0]['last_visit']}",
                values={
                    "entries": len(terms),
                    "unique": len(unique),
                    "newest": terms[0],
                    "oldest": terms[-1],
                },
            )
        sessions = full.get("sessions", [])
        if sessions:
            longest = max(sessions, key=lambda item: item["visits"])
            res.add(
                "info",
                f"Sesje przeglądania: {len(sessions)}",
                detail=f"najdłuższa: {longest['start']} → {longest['end']} ({longest['visits']} wizyt)",
                values={
                    "sessions": len(sessions),
                    "longest": {
                        "start": longest["start"],
                        "end": longest["end"],
                        "visits": longest["visits"],
                        "domains": longest["domains"][:8],
                        "viewers": longest["viewers"],
                    },
                },
            )
        viewers = sorted(
            {
                viewer
                for entry in full.get("identity_hints", [])
                for key, viewer in entry.items()
                if key in ("viewer_uid", "viewer_av")
            }
        )
        if viewers:
            res.add(
                "finding",
                f"Konta widoczne w adresach URL: {viewers}",
                detail=(
                    "parametr av=/lst= w adresach m.facebook.com wskazuje zalogowane konto — "
                    f"{HEURISTIC}"
                ),
                values={"uids": viewers, "heuristic": True, "basis": HEURISTIC},
            )
        for hint in full.get("identity_hints", [])[:12]:
            interesting = {
                k: v
                for k, v in hint.items()
                if k not in ("url", "heuristic", "basis")
            }
            if not interesting:
                continue
            res.add(
                "info",
                f"Adres z identyfikatorami (heurystyka): "
                f"{', '.join(f'{k}={v}' for k, v in list(interesting.items())[:4])}",
                detail=f"{hint.get('url', '')[:160]} — {HEURISTIC}",
                values={**interesting, "heuristic": True},
            )
        hints_csv = to_csv(
            ctx.work("exports") / "history_identity_hints.csv",
            ["key", "value", "url"],
            [
                [key, value, hint.get("url", "")]
                for hint in full.get("identity_hints", [])
                for key, value in hint.items()
                if key not in ("url", "heuristic", "basis")
            ],
            ctx.masker,
        )
        res.export(hints_csv)
        res.export(
            to_csv(
                ctx.work("exports") / "history_search_terms.csv",
                ["last_visit_utc", "term", "url", "visit_count"],
                [
                    [t["last_visit"], t["term"], t["url"], t["visit_count"]]
                    for t in full.get("search_terms", [])
                ],
                ctx.masker,
            )
        )
        res.export(
            to_csv(
                ctx.work("exports") / "history_sessions.csv",
                ["start", "end", "visits", "viewers", "domains"],
                [
                    [
                        s["start"],
                        s["end"],
                        s["visits"],
                        ",".join(s["viewers"]),
                        ";".join(s["domains"]),
                    ]
                    for s in sessions
                ],
                ctx.masker,
            )
        )
    res.data = {"databases": reports, "targets": targets}
    res.export(to_json(ctx.work("exports") / "chrome_history.json", res.data, ctx.masker))
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="chrome_history",
        category="accounts",
        title="mod.chrome_history.title",
        summary="mod.chrome_history.summary",
        params=[Param(key="path", label="param.path", default=DEFAULT_TARGET, kind="str")],
        run=run,
    )
)
