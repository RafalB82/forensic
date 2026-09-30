# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""When each account was last actually authenticated, and when it was not.

"Last login" is not one field on Android.  A Google account refreshes long-lived
OAuth2 grants, Messenger keeps its own login markers, Gmail registers itself with
a push service, and the Play Store keeps per-account log directories.  This
module reads all of those and puts them on one axis, so the answer to "when was
this account last in use" is a date with a source attached rather than a guess.
"""

from __future__ import annotations

import time

from ...core import appdata, timeline as tl
from ...core.export import to_csv, to_json
from ...core.readlog import ABSENT, ReadLog
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ...core.sqlite_tools import connect
from ..registry import ModuleSpec, Param, register

ACCOUNTS_DB = "/system/users/0/accounts.db"
MESSENGER_PREFS = "/data/com.facebook.orca/databases/prefs_db"
GMAIL_NOTIFICATIONS = "/data/com.google.android.gm/databases/accounts.notifications.db"
GMAIL_PREFS = "/data/com.google.android.gm/shared_prefs"
GMS_FILES = "/data/com.google.android.gms/files"
GSF_DB = "/data/com.google.android.gsf/databases/gservices.db"
PLAY_LOGS = "/data/com.android.vending/cache/logs"
WHATSAPP_LOG = "/data/com.whatsapp/files/Logs/whatsapp.log"
GMS_CHECKIN_FILES = (
    "gaClientId",
    "copresence_gaia_id",
    "device_key",
    "checkin_id_token",
    "gcm_connection_infos",
)
MESSENGER_KEYS = (
    "/unified_account_login/login_last_success_ts",
    "/unified_account_login/login_screen_last_seen_ts",
    "/auth/last_account_switch_timestamp",
    "/auth/auth_machine_id",
)
MESSENGER_PREFIXES = (
    "/unified_account_login/save_account_dialog_last_seen_ts/",
    "/orca_accounts/saved_account/",
    "/orca_accounts/saved_page_account/",
)


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("login_timeline")
    services = str(params.get("services") or "google,messenger,gmail,play,whatsapp")
    wanted = {item.strip() for item in services.split(",") if item.strip()}
    started = time.time()
    events = tl.Timeline(label="auth")
    sources: list[dict] = []
    accounts_events = tl.Timeline()
    if "google" in wanted:
        accounts_events = _accounts_db(ctx)
        events.extend(accounts_events)
        events.extend(_gsf(ctx))
    if "messenger" in wanted:
        events.extend(_messenger(ctx))
    if "gmail" in wanted:
        events.extend(_gmail(ctx))
    if "play" in wanted:
        sources.extend(_play(ctx, events))
    if "whatsapp" in wanted:
        sources.extend(_whatsapp(ctx, events))
    window = events.window()
    res.add(
        "ok" if events.count else "warn",
        f"Zdarzenia uwierzytelnienia: {window['count']}",
        detail=(
            f"od {window['first_utc']} do {window['last_utc']} ({window['span_human']}); "
            f"rodzaje: {events.by_kind()}"
        ),
        values={
            **window,
            "by_kind": events.by_kind(),
            "by_source": events.by_source(),
            "by_day": events.by_day(),
            "last_per_source": tl.last_per_source(events)[:20],
            # A count with holes in it is not a count.  ``complete`` is the one
            # word that tells a reader of the exported JSON that the timeline
            # may be missing events rather than that there were none.
            "complete": events.complete,
            "read_errors": len(events.read_errors),
        },
    )
    if events.read_errors:
        res.add(
            "warn",
            f"Osz z {len(events.read_errors)} źródłami nieczytelnymi",
            detail=(
                "te źródła nie zostały odczytane, więc zdarzeń z nich brakuje; "
                "ich brak w osi czasu nie oznacza, że nic się nie wydarzyło — "
                + "; ".join(
                    f"{entry['artifact']}: {entry['status']}"
                    + (f" ({entry['why'][:60]})" if entry.get("why") else "")
                    for entry in events.read_errors[:5]
                )
            ),
            values={"read_errors": events.read_errors[:20]},
        )
    mail_grant = _mail_grant(accounts_events)
    if mail_grant:
        res.add(
            "ok",
            f"Gmail: ostatni grant z prawem czytania poczty {mail_grant['last_grant_utc']}",
            detail=(
                "to graniczny «ostatni login» konta Google — nowsze granty dotyczą zakresów "
                "księgowych (cclog, notifications) i nie oznaczają użycia poczty"
            ),
            values=mail_grant,
        )
    for service, entry in _per_service(events).items():
        if entry["last_auth_utc"]:
            title = f"{service}: ostatnie uwierzytelnienie {entry['last_auth_utc']}"
            detail = (
                f"{entry['last_auth_evidence']}; ostatni zapis danych tej usługi "
                f"{entry['last_utc']} ({entry['last_source']})"
            )
        else:
            title = f"{service}: brak definicji uwierzytelnienia"
            detail = (
                f"ostatni zapis {entry['last_utc']} ({entry['last_source']}) — "
                + (
                    "WhatsApp loguje numerem telefonu, nie hasłem"
                    if not entry["has_password_concept"]
                    else "żaden z zebranych znaczników nie jest zapisem logowania"
                )
            )
        res.add(
            "ok" if entry["last_auth_utc"] else "info",
            title,
            detail=detail,
            values={"service": service, **entry},
        )
    ordered = events.sorted()
    res.data = {
        "window": window,
        "count": events.count,
        "by_kind": events.by_kind(),
        "by_source": events.by_source(),
        "by_day": events.by_day(),
        "per_service": _per_service(events),
        "grants": _grant_table(accounts_events),
        "gmail_mail_grant": _mail_grant(accounts_events),
        "last_per_source": tl.last_per_source(events),
        "extra_sources": sources,
        "events": [event.as_dict() for event in ordered],
    }
    res.export(
        to_json(ctx.work("exports") / "login_timeline.json", res.data, ctx.masker, indent=1)
    )
    res.export(
        to_csv(
            ctx.work("exports") / "login_timeline.csv",
            ["utc", "local_warsaw", "kind", "source", "package", "detail"],
            [event.row() for event in ordered],
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


AUTH_KINDS = (tl.KIND_LOGIN, tl.KIND_TOKEN)


def _grant_table(events: tl.Timeline) -> list[dict]:
    """Newest token grant per authenticator — the per-service "last login".

    The scope is carried along because a Google account holds several grants at
    once: the newest one overall is often a bookkeeping scope such as
    ``cclog``, while the newest grant that can actually read mail is the
    meaningful date for "when was this account last used".
    """
    newest: dict[str, tl.Event] = {}
    for event in events.events:
        if event.kind != tl.KIND_TOKEN:
            continue
        current = newest.get(event.detail)
        if current is None or event.unix > current.unix:
            newest[event.detail] = event
    out: list[dict] = []
    for detail, event in sorted(newest.items(), key=lambda item: -item[1].unix):
        out.append(
            {
                "authenticator": detail.replace("grant tokenu dla ", ""),
                "last_grant_utc": event.utc,
                "last_grant_local": event.local,
                "scope_head": event.extra.get("scope_head", ""),
            }
        )
    return out


def _mail_grant(events: tl.Timeline) -> dict:
    """Newest grant whose scope can read mail — the Gmail "last login"."""
    candidates = [
        event
        for event in events.events
        if event.kind == tl.KIND_TOKEN
        and "grant tokenu dla com.google.android.gm" in event.detail
        and "mail.google.com" in event.extra.get("scope", "")
    ]
    if not candidates:
        return {}
    best = max(candidates, key=lambda item: item.unix)
    return {
        "authenticator": "com.google.android.gm",
        "last_grant_utc": best.utc,
        "last_grant_local": best.local,
        "scope_head": best.extra.get("scope_head", ""),
        "mail_scope_grants": len(candidates),
        "note": (
            "najnowszy zapis terminu ważności grantu z zakresem czytającym pocztę; "
            "nowsze granty Google dotyczą zakresów księgowych (cclog, notifications)"
        ),
    }


def _per_service(events: tl.Timeline) -> dict[str, dict]:
    """Per service: last authentication and last touch, kept apart.

    "Last login" and "last activity" are different questions, and on this image
    they are four years apart for the Google account, so one number cannot
    answer both.
    """
    groups: dict[str, list[tl.Event]] = {}
    for event in events.events:
        groups.setdefault(event.package or "other", []).append(event)
    out: dict[str, dict] = {}
    for name, items in groups.items():
        last = max(items, key=lambda item: item.unix)
        auth = [item for item in items if item.kind in AUTH_KINDS]
        newest_auth = max(auth, key=lambda item: item.unix) if auth else None
        out[name] = {
            "events": len(items),
            "first_utc": min(item.utc for item in items),
            "last_utc": last.utc,
            "last_local": last.local,
            "last_source": last.source,
            "last_detail": last.detail,
            "last_kind": last.kind,
            "evidence": f"{last.source}: {last.detail}" if last.detail else last.source,
            "auth_events": len(auth),
            "last_auth_utc": newest_auth.utc if newest_auth else "",
            "last_auth_kind": newest_auth.kind if newest_auth else "",
            "last_auth_evidence": (
                f"{newest_auth.source}: {newest_auth.detail}" if newest_auth else ""
            ),
            "has_password_concept": name not in ("whatsapp",),
            "kinds": sorted({item.kind for item in items}),
        }
    return dict(sorted(out.items(), key=lambda item: item[1]["last_utc"], reverse=True))


def _local(ctx: Ctx, target: str) -> str | None:
    try:
        return str(ctx.materialise(target))
    except KeyError:
        return None


def _accounts_db(ctx: Ctx) -> tl.Timeline:
    out = tl.Timeline(label="accounts.db")
    grants: dict[str, tuple] = {}
    local = _local(ctx, ACCOUNTS_DB)
    if not local:
        return out
    conn = connect(local)
    try:
        extras = list(conn.execute("select key, value from extras"))
    finally:
        conn.close()
    for key, value in extras:
        if not str(key).startswith("EXP:"):
            continue
        parts = str(key).split(":")
        stamp = tl.epoch_seconds(value)
        if not stamp["unix"]:
            continue
        authenticator = parts[1] if len(parts) > 1 else "?"
        scope = str(key).split(":oauth2:", 1)[1] if ":oauth2:" in str(key) else ""
        grants[authenticator] = (stamp["unix"], scope)
        out.add(
            tl.make_event(
                value,
                "accounts.db extras EXP",
                tl.KIND_TOKEN,
                detail=f"grant tokenu dla {authenticator}",
                package="google",
                extra={"scope": scope, "scope_head": scope.split(" ")[0]},
            )
        )
    out.grants = grants
    try:
        stat = ctx.fs().stat(ACCOUNTS_DB)
    except Exception:
        return out
    out.add(
        tl.make_event(
            stat["mtime_utc"],
            ACCOUNTS_DB,
            tl.KIND_LOGOUT,
            detail="transakcja na bazie kont (usuwa zapisane tokeny)",
            package="google",
        )
    )
    return out


def _gsf(ctx: Ctx) -> tl.Timeline:
    """State files of the Google services layer.

    They are tagged ``gms`` and not ``google`` on purpose: a file rewritten at
    boot proves the layer ran, not that an account was authenticated, and
    mixing the two would move the "last login" date by four years.
    """
    out = tl.Timeline(label="gsf")
    for name in GMS_CHECKIN_FILES:
        target = f"{GMS_FILES}/{name}"
        try:
            stat = ctx.fs().stat(target)
        except Exception:
            continue
        out.add(
            tl.make_event(
                stat["mtime_utc"],
                target,
                tl.KIND_CHECKIN,
                detail=f"zapis {name} ({stat['size']} B)",
                package="gms",
            )
        )
    for target, label in (
        (GSF_DB, "baza usług Google (check-in)"),
        (f"{GMS_FILES}/google_app_measurement.db", "pomiar aktywności GMS"),
    ):
        try:
            stat = ctx.fs().stat(target)
        except Exception:
            continue
        out.add(
            tl.make_event(
                stat["mtime_utc"],
                target,
                tl.KIND_CHECKIN,
                detail=label,
                package="gms",
            )
        )
    return out


def _messenger(ctx: Ctx) -> tl.Timeline:
    out = tl.Timeline(label="messenger")
    local = _local(ctx, MESSENGER_PREFS)
    if not local:
        out.read_errors.append(
            {"artifact": MESSENGER_PREFS, "status": ABSENT, "why": "brak pliku w obrazie"}
        )
        return out
    report = appdata.messenger_prefs_db(local)
    # A read that failed must not leave an empty timeline looking like a device
    # that never logged in to Messenger.  The events are still added from
    # whatever was readable; what changes is that the gap is named.
    log = ReadLog()
    for key, _type, value in appdata.preferences_rows(local, log):
        text = str(key)
        if text in MESSENGER_KEYS or any(text.startswith(p) for p in MESSENGER_PREFIXES):
            if text == "/auth/auth_machine_id":
                continue
            out.add(
                tl.make_event(
                    value,
                    f"prefs_db {text}",
                    tl.KIND_LOGIN,
                    detail=_messenger_detail(text),
                    package="messenger",
                )
            )
    out.read_errors.extend(log.entries)
    for account in report.get("accounts", []):
        out.add(
            tl.make_event(
                account.get("last_logout_utc"),
                f"prefs_db /orca_accounts/saved_*/{account['uid']}",
                tl.KIND_LOGIN,
                detail=(
                    f"wylogowanie konta {account['name'] or account['uid']} "
                    f"({account['kind']})"
                ),
                package="messenger",
            )
        )
        out.add(
            tl.make_event(
                account.get("last_unseen_utc"),
                f"prefs_db last_unseen_timestamp/{account['uid']}",
                tl.KIND_OTHER,
                detail=(
                    f"licznik nieprzeczytanych {account['name'] or account['uid']} "
                    f"zapisany jako {account['last_unseen'].get('value')} "
                    f"({account['last_unseen'].get('unit')})"
                ),
                package="messenger",
            )
        )
    return out


def _messenger_detail(key: str) -> str:
    if key.endswith("login_last_success_ts"):
        return "ostatnie udane logowanie Messengera"
    if key.endswith("login_screen_last_seen_ts"):
        return "ekran logowania Messengera ostatnio widziany"
    if key.endswith("last_account_switch_timestamp"):
        return "przełączenie konta w Messengerze"
    if "save_account_dialog_last_seen_ts" in key:
        return "okno dodawania konta widziane"
    if "saved_page_account" in key:
        return "zapisane konto strony"
    if "saved_account" in key:
        return "zapisane konto użytkownika"
    return key


def _gmail(ctx: Ctx) -> tl.Timeline:
    out = tl.Timeline(label="gmail")
    local = _local(ctx, GMAIL_NOTIFICATIONS)
    if local:
        conn = connect(local)
        try:
            tables = {row[0] for row in conn.execute("select name from sqlite_master where type='table'")}
            if "accounts" in tables:
                columns = {row[1] for row in conn.execute('pragma table_info("accounts")')}
                if "last_registration_time_ms" in columns:
                    for name, millis in conn.execute(
                        "select account_name, last_registration_time_ms from accounts"
                    ):
                        out.add(
                            tl.make_event(
                                millis,
                                "accounts.notifications.db",
                                tl.KIND_CHECKIN,
                                detail=f"Gmail zarejestrowany do synchronizacji: {name}",
                                package="gmail",
                            )
                        )
        finally:
            conn.close()
    try:
        entries = ctx.fs().listdir(GMAIL_PREFS)
    except Exception:
        entries = []
    for entry in entries:
        name = entry.name
        if not name.startswith("Account-"):
            continue
        stat = ctx.fs().stat(f"{GMAIL_PREFS}/{name}")
        out.add(
            tl.make_event(
                stat["mtime_utc"],
                f"{GMAIL_PREFS}/{name}",
                tl.KIND_LOGIN,
                detail=(
                    f"stan konta / ostatnia synchronizacja: {name[len('Account-'):-len('.xml')]}"
                ),
                package="gmail",
            )
        )
    return out


def _play(ctx: Ctx, events: tl.Timeline) -> list[dict]:
    out: list[dict] = []
    try:
        entries = ctx.fs().listdir(PLAY_LOGS)
    except Exception:
        return out
    for entry in entries:
        if not entry.is_dir or entry.name.startswith("."):
            continue
        account = entry.name
        newest = None
        count = 0
        newest_bytes = 0
        try:
            logs = ctx.fs().listdir(entry.inode)
        except Exception:
            continue
        for log in logs:
            if not log.is_reg or not log.name.endswith(".log"):
                continue
            stat = ctx.fs().stat(f"{PLAY_LOGS}/{account}/{log.name}")
            count += 1
            newest_bytes += stat["size"]
            if newest is None or stat["mtime_unix"] > newest[0]:
                newest = (stat["mtime_unix"], log.name, stat["size"])
        if not newest:
            continue
        out.append(
            {
                "account": account,
                "logs": count,
                "bytes": newest_bytes,
                "newest_log": newest[1],
                "newest_utc": tl.utc(newest[0]),
                "newest_local": tl.local_warsaw(newest[0]),
                "is_null_account": account == "null_account",
            }
        )
        events.add(
            tl.make_event(
                newest[0],
                f"Play Store logs/{account}/{newest[1]}",
                tl.KIND_OTHER,
                detail=(
                    f"najnowszy log Sklepu Play dla konta {account} "
                    f"({count} plików, {newest_bytes} B)"
                ),
                package="play",
            )
        )
    return out


def _whatsapp(ctx: Ctx, events: tl.Timeline) -> list[dict]:
    try:
        stat = ctx.fs().stat(WHATSAPP_LOG)
    except Exception:
        return []
    events.add(
        tl.make_event(
            stat["mtime_utc"],
            WHATSAPP_LOG,
            tl.KIND_OTHER,
            detail="ostatni zapis logu WhatsAppa (WhatsApp nie ma pojęcia logowania hasłem)",
            package="whatsapp",
        )
    )
    return [
        {
            "log": WHATSAPP_LOG,
            "size": stat["size"],
            "utc": stat["mtime_utc"],
            "verdict": "WhatsApp nie ma hasła — log to najbliższy znacznik aktywności",
        }
    ]


register(
    ModuleSpec(
        id="login_timeline",
        category="timeline",
        title="mod.login_timeline.title",
        summary="mod.login_timeline.summary",
        params=[
            Param(
                key="services",
                label="param.services",
                default="google,messenger,gmail,play,whatsapp",
                kind="str",
            )
        ],
        run=run,
    )
)
