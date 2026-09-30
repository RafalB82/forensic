# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Android AccountManager database: accounts, stored passwords, token metadata.

``/data/system/users/0/accounts.db`` is where the framework records every account
and, for some authenticator types, the account password itself.  The
``extras`` table additionally holds the expiry timestamps of cached OAuth2
tokens, which is what makes it possible to date the last successful
authentication without touching the tokens.
"""

from __future__ import annotations

import datetime as _dt
import time

from ...core import i18n
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.masking import password_of
from ...core.session import Ctx
from ...core.sqlite_tools import connect
from ..registry import ModuleSpec, Param, register

DEFAULT_DB = "/system/users/0/accounts.db"
GOOGLE_TYPES = ("com.google", "com.google.android.gm")


def _utc(value: int | None) -> str:
    if not value:
        return ""
    try:
        return (
            _dt.datetime.fromtimestamp(int(value), _dt.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    except (TypeError, ValueError, OverflowError, OSError):
        return str(value)


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("accounts_db")
    target = str(params.get("path") or DEFAULT_DB)
    try:
        local = ctx.materialise(target)
    except KeyError:
        res.add("warn", f"Brak ścieżki w obrazie: {target}")
        return ctx.record(res)
    except FileNotFoundError as exc:
        res.add("critical", i18n.t("msg.no_image"), detail=str(exc))
        return ctx.record(res)
    started = time.time()
    conn = connect(local)
    try:
        tables = {row[0] for row in conn.execute("select name from sqlite_master where type='table'")}
        if "accounts" not in tables:
            res.add("critical", "Brak tabeli accounts", values={"tables": sorted(tables)})
            return ctx.record(res)
        rows = list(
            conn.execute(
                "select _id, name, type, password, previous_name from accounts order by _id"
            )
        )
        accounts = [
            {
                "_id": row[0],
                "name": row[1],
                "type": row[2],
                "password": row[3],
                "previous_name": row[4],
            }
            for row in rows
        ]
        authtokens = conn.execute("select count(*) from authtokens").fetchone()[0]
        extras = list(conn.execute("select key, value from extras"))
    finally:
        conn.close()
    google = [a for a in accounts if a["type"] in GOOGLE_TYPES]
    res.add(
        "ok",
        f"Konta w {target.split('/')[-1]}: {len(accounts)}",
        values={
            "database": str(local),
            "accounts": len(accounts),
            "by_type": _by_type(accounts),
            "authtokens_rows": authtokens,
            "extras_rows": len(extras),
            "seconds": round(time.time() - started, 2),
        },
        artifacts=[str(local)],
    )
    for account in accounts:
        secret = password_of(account["password"]) if account["password"] else None
        verdict = "brak kolumny password (hasło zapisuje tylko autentykator)"
        if account["password"]:
            verdict = "hasło zapisane JAWNIE"
        res.add(
            "finding" if account["password"] else "info",
            f"{account['type']}: {account['name']}",
            detail=verdict,
            values={
                "_id": account["_id"],
                "name": account["name"],
                "type": account["type"],
                "password": secret if secret else None,
                "password_verdict": verdict,
                "previous_name": account["previous_name"],
            },
        )
    if google:
        res.add(
            "ok",
            "Konta Google: hasła NIE są przechowywane lokalnie",
            detail=(
                "AccountManagerService zapisuje kolumnę password tylko dla kont legacy/third-party; "
                "konto com.google trzyma wyłącznie tokeny OAuth2, więc hasło da się odzyskać tylko "
                "z innego nośnika (np. bazy haseł przeglądarki)"
            ),
            values={"accounts": [a["name"] for a in google]},
        )
    expiry = _token_expiries(extras)
    if expiry:
        newest = expiry[-1]
        res.add(
            "info",
            f"Najnowszy zapisany termin ważności tokenu: {newest['expires_utc']}",
            detail=f"klucz: {newest['key'][:120]}",
            values={
                "tokens_with_expiry": len(expiry),
                "newest": newest,
                "oldest": expiry[0],
                "note": "EXP to termin ważności zapisanego tokenu, nie czas logowania",
            },
        )
        csv_path = to_csv(
            ctx.work("exports") / "accounts_token_expiries.csv",
            ["expires_utc", "expires_unix", "authenticator", "scope"],
            [
                [
                    item["expires_utc"],
                    item["expires_unix"],
                    item["authenticator"],
                    item["scope"],
                ]
                for item in expiry
            ],
            ctx.masker,
        )
        res.export(csv_path)
    interesting = _interesting_extras(extras)
    if interesting:
        res.add("info", "Kluczowe wpisy w tabeli extras", values=interesting)
    res.data = {
        "database": str(local),
        "accounts": [
            {**a, "password": password_of(a["password"]) if a["password"] else None}
            for a in accounts
        ],
        "account_count": len(accounts),
        "by_type": _by_type(accounts),
        "authtokens_rows": authtokens,
        "extras_rows": len(extras),
        "token_expiries": {
            "count": len(expiry),
            "first": expiry[0] if expiry else None,
            "last": expiry[-1] if expiry else None,
            "all": expiry,
        },
        "interesting_extras": interesting,
    }
    res.export(
        to_json(
            ctx.work("exports") / "accounts_db.json",
            res.data,
            ctx.masker,
        )
    )
    res.export(
        to_csv(
            ctx.work("exports") / "accounts.csv",
            ["_id", "name", "type", "password_verdict", "password", "previous_name"],
            [
                [
                    a["_id"],
                    a["name"],
                    a["type"],
                    "jawny" if a["password"] else "brak",
                    password_of(a["password"]) if a["password"] else "",
                    a["previous_name"] or "",
                ]
                for a in accounts
            ],
            ctx.masker,
        )
    )
    return ctx.record(res)


def _by_type(accounts: list[dict]) -> dict:
    out: dict[str, int] = {}
    for account in accounts:
        out[account["type"]] = out.get(account["type"], 0) + 1
    return out


def _token_expiries(extras: list[tuple]) -> list[dict]:
    """Rows whose key is ``EXP:<authenticator>:<sig>:oauth2:<scopes>``."""
    out: list[dict] = []
    for key, value in extras:
        if not key.startswith("EXP:"):
            continue
        try:
            unix = int(value)
        except (TypeError, ValueError):
            continue
        parts = key.split(":")
        out.append(
            {
                "key": key,
                "authenticator": parts[1] if len(parts) > 1 else "",
                "scope": key.split(":oauth2:", 1)[1] if ":oauth2:" in key else "",
                "expires_unix": unix,
                "expires_utc": _utc(unix),
            }
        )
    out.sort(key=lambda item: item["expires_unix"])
    return out


def _interesting_extras(extras: list[tuple], limit: int = 12) -> dict:
    """Extras rows worth an analyst's attention, without dumping all 400."""
    needles = (
        "GoogleUserId",
        "firstName",
        "lastName",
        "CredentialsState",
        "services",
        "last_unseen",
        "authenticator",
        "account_type",
        "recovery",
    )
    out: dict[str, str] = {}
    for key, value in extras:
        if any(needle.lower() in key.lower() for needle in needles) and len(out) < limit:
            text = str(value)
            out[key[:140]] = text[:400]
    return out


register(
    ModuleSpec(
        id="accounts_db",
        category="accounts",
        title="mod.accounts_db.title",
        summary="mod.accounts_db.summary",
        params=[Param(key="path", label="param.path", default=DEFAULT_DB, kind="path")],
        run=run,
    )
)
