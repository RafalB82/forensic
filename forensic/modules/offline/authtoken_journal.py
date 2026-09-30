# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Recover OAuth2 tokens from a rolled-back ``accounts.db-journal``.

The framework wipes its cached tokens on logout, expiry or an unclean unmount,
but the rollback journal keeps the *previous* pages.  Its header is usually zeroed
after a crash, so the frame table is reconstructed from the file size and the
records are read straight out of the leaf pages — which works even when a full
rollback would not produce a consistent database.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.masking import token_of
from ...core.session import Ctx
from ...core.sqlite_journal import inspect, records_with_counts, rollback
from ..registry import BOOL, ModuleSpec, Param, register

DEFAULT_DB = "/system/users/0/accounts.db"
OAUTH2 = re.compile(r":oauth2:")
SNOWBALL = re.compile(r":(\^\^[^:]+)")


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("authtoken_journal")
    target = str(params.get("path") or DEFAULT_DB)
    journal_path = params.get("journal") or (target + "-journal")
    started = time.time()
    if Path(journal_path).exists():
        journal_local = Path(journal_path)
    else:
        journal_local = ctx.materialise(journal_path)
    if not journal_local.exists():
        res.add("warn", f"Brak journala: {journal_path}")
        return ctx.record(res)
    info = inspect(journal_local)
    rows, stats = records_with_counts(journal_local, info)
    tokens: list[dict] = []
    orphans: list[dict] = []
    for row in rows:
        text = [value for value in row if isinstance(value, str)]
        token = next((v for v in text if v.startswith("ya29.") or v.startswith("1//")), None)
        kind = next((v for v in text if OAUTH2.search(v) or SNOWBALL.search(v)), None)
        if token and not kind:
            orphans.append(
                {
                    "token": token,
                    "row": [str(value)[:120] for value in row],
                }
            )
            continue
        if token and kind:
            parts = kind.split(":")
            tokens.append(
                {
                    "authenticator": parts[0],
                    "kind": kind,
                    "scope": kind.split(":oauth2:", 1)[1] if ":oauth2:" in kind else "",
                    "token": token,
                    "token_length": len(token),
                }
            )
    unique: dict[str, dict] = {}
    for item in tokens:
        unique.setdefault(item["token"], item)
    tokens = list(unique.values())
    google = [t for t in tokens if OAUTH2.search(t["kind"])]
    whatsapp = [t for t in tokens if SNOWBALL.search(t["kind"])]
    res.add(
        "ok" if info.frame_count else "warn",
        f"Journal: {info.frame_count} klatek, strona {info.page_size} B",
        detail="; ".join(info.notes),
        values={**info.summary(), "records": stats},
        artifacts=[str(journal_local)],
    )
    res.add(
        "ok" if tokens else "warn",
        f"Odzyskane tokeny: {len(tokens)} (Google {len(google)}, inne {len(whatsapp)})",
        detail="unikalne wartości tokenów; duplikaty stron usunięte",
        values={
            "unique_tokens": len(tokens),
            "google_oauth2": len(google),
            "other_providers": len(whatsapp),
            "seconds": round(time.time() - started, 2),
        },
    )
    if orphans:
        res.add(
            "info",
            f"Tokeny bez kompletnej pary typ/wartość: {len(orphans)}",
            detail=(
                "rekord z liści zawiera sam token, ale komórka z typem autentykatora jest pusta "
                "lub rozdzielona stroną przepełnienia — dlatego token nie jest przypisany do zakresu"
            ),
            values={"orphans": orphans},
        )
    by_auth: dict[str, int] = {}
    for item in tokens:
        by_auth[item["authenticator"]] = by_auth.get(item["authenticator"], 0) + 1
    res.add("info", "Tokeny wg autentykatora", values=by_auth)
    gmail = [t for t in tokens if t["authenticator"] == "com.google.android.gm"]
    gmail_scope = [
        t
        for t in tokens
        if "gmail" in t["scope"] or "mail.google.com" in t["scope"]
    ]
    if gmail or gmail_scope:
        res.add(
            "finding",
            f"Zakres Gmail: {len(gmail_scope)} tokenów (wystawione przez com.google.android.gm: {len(gmail)})",
            detail="tokeny z dostępem do skrzynki (mail.google.com / gmail.full_access)",
            values={
                "gmail_scope_tokens": len(gmail_scope),
                "gmail_authenticator_tokens": len(gmail),
                "scopes": sorted({t["scope"][:120] for t in gmail_scope})[:6],
            },
        )
    for item in tokens[:6]:
        res.add(
            "info",
            f"{item['authenticator']}: {item['token'][:16]}…",
            values={
                "authenticator": item["authenticator"],
                "token": token_of(item["token"]),
                "scope": item["scope"][:200],
            },
        )
    rollback_result = None
    if params.get("rollback", False):
        database_local = ctx.materialise(target)
        output = ctx.work("exports") / "accounts_rolledback.db"
        rollback_result = rollback(database_local, journal_local, output)
        severity = "ok" if rollback_result.get("integrity") == "ok" else "warn"
        res.add(
            severity,
            f"Rekonstrukcja bazy: integrity = {rollback_result.get('integrity')}",
            detail=(
                "Dziennik nie opisuje kompletnego stanu (brak tablicy stron / sumy kontrolnych), "
                "więc do odzyskiwania danych używaj ekstrakcji rekordów z klatek"
            ),
            values={k: v for k, v in rollback_result.items() if k != "journal"},
            artifacts=[rollback_result["output"]],
        )
    masked_tokens = [
        {**item, "token": token_of(item["token"])} if item.get("token") else item
        for item in tokens
    ]
    res.data = {
        "journal": info.summary(),
        "records": stats,
        "tokens": masked_tokens,
        "unique_tokens": len(tokens),
        "google_oauth2": len(google),
        "other_providers": len(whatsapp),
        "by_authenticator": by_auth,
        "orphan_tokens": [
            {
                **item,
                "token": token_of(item["token"]) if item.get("token") else "",
                "row": [
                    token_of(cell) if isinstance(cell, str) and cell.startswith("ya29.") else cell
                    for cell in item.get("row", [])
                ],
            }
            for item in orphans
        ],
        "gmail_scope_tokens": len(gmail_scope),
        "gmail_authenticator_tokens": len(gmail),
        "rollback": rollback_result,
    }
    res.export(
        to_csv(
            ctx.work("exports") / "authtokens_from_journal.csv",
            ["authenticator", "scope", "token"],
            [[t["authenticator"], t["scope"], token_of(t["token"])] for t in tokens if t.get("token")],
            ctx.masker,
        )
    )
    res.export(to_json(ctx.work("exports") / "authtokens_from_journal.json", res.data, ctx.masker))
    return ctx.record(res)


register(
    ModuleSpec(
        id="authtoken_journal",
        category="accounts",
        title="mod.authtoken_journal.title",
        summary="mod.authtoken_journal.summary",
        params=[
            Param(key="path", label="param.path", default=DEFAULT_DB, kind="path"),
            Param(key="journal", label="Plik journala", default="", kind="path"),
            Param(
                key="rollback",
                label="Zbuduj skopiowaną bazę po rollbacku",
                default=False,
                kind=BOOL,
            ),
        ],
        run=run,
    )
)
