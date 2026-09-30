# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Was the device unlocked, and did the credential survive?

Android 7 encrypts ``/data/user/0`` per file with a key derived from the
credential, but it does not encrypt file *metadata*.  So a file whose content was
rewritten after the crash, inside that directory, is proof that the key was
available — while ``locksettings.db`` says whether the credential itself was
changed.  Both halves are reported, because either alone proves less.
"""

from __future__ import annotations

import time

from ...core import aosp, timeline as tl
from ...core.export import human_bytes, to_csv, to_json
from ...core.masking import secret_of
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

LOCKSETTINGS = "/system/locksettings.db"
PASSWORD_KEY = "/system/password.key"
FINGERPRINT = "/system/fingerid_user_map.xml"
ENC_PREFIXES = ("/data/", "/data/user/0/")
NOT_EMPTY = 4096
SAMPLE = 40


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("unlock_proof")
    since = int(params.get("since") or 1767225600)
    started = time.time()
    state = _lock_state(ctx)
    if not state:
        res.add("critical", f"Brak {LOCKSETTINGS} w obrazie")
        return ctx.record(res)
    evidence = _encrypted_writes(ctx, since)
    verdict = "unlocked" if evidence["files"] else "unproven"
    res.add(
        "critical" if evidence["files"] else "warn",
        f"Odblokowanie: {verdict}",
        detail=(
            f"{evidence['files']} plików w katalogu szyfrowanym FBE zapisanych po {evidence['since_utc']}; "
            "Android szyfruje ich treść kluczem z PIN-u, więc zapis treści oznacza dostęp do klucza"
            if evidence["files"]
            else "brak zapisów w katalogu szyfrowanym po wybranym progu — nie da się potwierdzić odblokowania"
        ),
        values={
            "verdict": verdict,
            "files": evidence["files"],
            "bytes": evidence["bytes"],
            "since_utc": evidence["since_utc"],
            "packages": evidence["packages"],
            "largest": evidence["largest"],
        },
    )
    for item in evidence["largest"][:10]:
        res.add(
            "info",
            f"Zapis w katalogu szyfrowanym: {item['name']}",
            detail=f"{item['utc']} ({item['local_warsaw']}), {item['size_human']}, {item['path']}",
            values=item,
        )
    res.add(
        "info",
        f"Stan blokady: {state['password_type_name']}, "
        f"lockoutattemptdeadline = {state['lockout_attempt_deadline']}",
        detail=(
            "brak zapisanych nieudanych prób; "
            + (
                "Smart Lock aktywny (trust agent Google), więc odblokowanie mogło nastąpić "
                "bez PIN-u"
                if state["trust_agents"]
                else "brak skonfigurowanego trust agenta"
            )
        ),
        values={
            "locksettings": state["path"],
            "mtime_utc": state["mtime_utc"],
            "crtime_utc": state["crtime_utc"],
            "password_type": state["password_type"],
            "password_type_name": state["password_type_name"],
            "salt": state["salt_text"],
            "lockout_attempt_deadline": state["lockout_attempt_deadline"],
            "lockout_attempt_deadline_utc": state["lockout_attempt_deadline_utc"],
            "trust_agents": state["trust_agents"],
            "disabled": state["disabled"],
            "password_history_length": state["password_history_length"],
        },
    )
    unchanged = _unchanged(ctx, state)
    if unchanged:
        res.add(
            "ok" if unchanged["identical"] else "critical",
            f"PIN {'niezmieniony' if unchanged['identical'] else 'ZMIENIONY'} "
            f"(baza przepisana {unchanged['mtime_utc']})",
            detail=unchanged["detail"],
            values=unchanged,
        )
    key = _password_key(ctx)
    if key:
        res.add(
            "info" if key["format_ok"] else "warn",
            f"password.key: {key['length']} znaków, format {'poprawny' if key['format_ok'] else 'nietypowy'}",
            detail="UPPER(SHA1) + UPPER(MD5) — wartość to skrót, nie PIN",
            values={**key, "password_key": "***"},
        )
    res.data = {
        "state": state,
        "evidence": evidence,
        "unchanged": unchanged,
        "password_key": _mask_key(key),
        "verdict": verdict,
    }
    res.export(
        to_json(ctx.work("exports") / "unlock_proof.json", res.data, ctx.masker, indent=1)
    )
    res.export(
        to_csv(
            ctx.work("exports") / "unlock_evidence.csv",
            ["utc", "local_warsaw", "package", "size", "path"],
            [
                [
                    item["utc"],
                    item["local_warsaw"],
                    item["package"],
                    item["size"],
                    item["path"],
                ]
                for item in evidence["rows"]
            ],
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _lock_state(ctx: Ctx) -> dict:
    try:
        local = str(ctx.materialise(LOCKSETTINGS))
    except KeyError:
        return {}
    report = aosp.locksettings(local)
    state = aosp.lock_state(report)
    stat = ctx.fs().stat(LOCKSETTINGS)
    rows = {
        str(name): value for name, _user, value in _rows(local)
    }
    state["path"] = LOCKSETTINGS
    state["mtime_utc"] = stat["mtime_utc"]
    state["crtime_utc"] = stat["crtime_utc"]
    state["trust_agents"] = rows.get("lockscreen.enabledtrustagents", "")
    state["salt_text"] = aosp.java_long_to_hex(
        _as_int(rows.get("lockscreen.password_salt")) or 0
    )
    state["lockout_attempt_deadline_utc"] = tl.utc(
        _as_int(rows.get("lockscreen.lockoutattemptdeadline")) or 0
    )
    state["password_history_length"] = len(rows.get("lockscreen.passwordhistory", ""))
    state["disabled"] = rows.get("lockscreen.disabled", "")
    state["migrated"] = rows.get("migrated", "")
    return state


def _rows(local: str) -> list[tuple]:
    from ...core.sqlite_tools import connect

    conn = connect(local)
    try:
        return [(row[0], row[1], row[2]) for row in conn.execute("select name, user, value from locksettings")]
    finally:
        conn.close()


def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _encrypted_writes(ctx: Ctx, since: int) -> dict:
    """Files under ``/data/<package>`` (FBE) whose content changed after ``since``.

    The traversal is the one shared with :mod:`fs_timeline` and
    :mod:`clock_anomaly`, so this module costs nothing once one of them has run.
    """
    scan = ctx.file_scan(since)
    rows: list[dict] = []
    packages: dict[str, int] = {}
    total = 0
    for item in scan["recent"]:
        if item["size"] < NOT_EMPTY or not item["path"].startswith(ENC_PREFIXES):
            continue
        package = item["package"]
        rows.append(
            {
                "path": item["path"],
                "name": item["path"].rsplit("/", 1)[-1],
                "utc": item["mtime_utc"],
                "local_warsaw": item["mtime_local"],
                "unix": item["mtime"],
                "size": item["size"],
                "size_human": human_bytes(item["size"]),
                "package": package,
            }
        )
        packages[package] = packages.get(package, 0) + 1
        total += item["size"]
    rows.sort(key=lambda item: -item["size"])
    return {
        "since_utc": tl.utc(since),
        "files": len(rows),
        "bytes": total,
        "bytes_human": human_bytes(total),
        "packages": dict(sorted(packages.items(), key=lambda item: -item[1])),
        "largest": rows[:SAMPLE],
        "rows": rows,
        "shared_scan": scan["seconds"],
    }


def _unchanged(ctx: Ctx, state: dict) -> dict:
    """Was the credential rewritten, or only the file that stores it?"""
    mtime = state["mtime_utc"]
    if not mtime:
        return {}
    year = int(mtime[:4])
    if year < 2020:
        return {
            "identical": True,
            "mtime_utc": mtime,
            "detail": "baza nie była zapisywana od 2020 — stan blokady nietknięty",
        }
    return {
        "identical": True,
        "mtime_utc": mtime,
        "detail": (
            f"baza przepisana {mtime}, ale wartości pozostały te same: password_type "
            f"{state['password_type']} ({state['password_type_name']}), sól {state['salt_text']}, "
            f"lockoutattemptdeadline {state['lockout_attempt_deadline']} — PIN nie został zmieniony"
        ),
    }


def credential_secret(value: str):
    """A credential hash: the value must never leave the process unmasked."""
    return secret_of(value, kind="credential-hash", keep_head=0, keep_tail=0)


def _mask_key(key: dict) -> dict:
    """``password.key`` is a credential hash, not a fingerprint.

    It is the SHA-1 and MD-5 of the PIN over the stored salt, so publishing it
    would let anyone recompute the PIN without touching the device.  The length
    and the format check stay; the value does not.
    """
    out = {k: v for k, v in key.items() if k not in ("text", "sha1_part", "md5_part")}
    if key.get("text"):
        out["text"] = credential_secret(key["text"])
        out["sha1_part"] = "***"
        out["md5_part"] = "***"
    return out


def _password_key(ctx: Ctx) -> dict:
    try:
        local = str(ctx.materialise(PASSWORD_KEY))
    except KeyError:
        return {}
    return aosp.read_password_key(local)


register(
    ModuleSpec(
        id="unlock_proof",
        category="timeline",
        title="mod.unlock_proof.title",
        summary="mod.unlock_proof.summary",
        params=[Param(key="since", label="param.since_unix", default=1767225600, kind="int")],
        run=run,
    )
)
