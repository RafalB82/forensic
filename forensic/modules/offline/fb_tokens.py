# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Facebook access tokens left on the device (Messenger and Facebook Lite).

The tokens themselves are the finding, so they are wrapped as secrets and only
unwrapped by the reveal switch.  What matters as much is the *separation* of
real tokens from coincidences: ``EAA`` is part of the base64 alphabet, so blobs
such as expo push payloads contain plenty of strings that start with ``EAA``
without being tokens at all.  A token counts only when it sits in a named field
of a JSON document.
"""

from __future__ import annotations

import time
from pathlib import Path

from ...core import appdata
from ...core.appdata import MAGIC_PROBE_BYTES
from ...core.export import to_csv, to_json
from ...core.findings import ModuleResult
from ...core.masking import token_of
from ...core.session import Ctx
from ..registry import ModuleSpec, Param, register

ORCA_PREFS = "/data/com.facebook.orca/databases/prefs_db"
ORCA_PREFS_JOURNAL = "/data/com.facebook.orca/databases/prefs_db-journal"
LITE_STORE = "/data/com.facebook.lite/files/PropertiesStore_v02"
ACCOUNT_PREFIX = "/orca_accounts/saved_"


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("fb_tokens")
    include_journal = bool(params.get("journal", True))
    started = time.time()
    sources: list[dict] = []
    hits: list[dict] = []
    raw_total = 0
    for target, kind in (
        (ORCA_PREFS, "prefs_db"),
        (ORCA_PREFS_JOURNAL, "prefs_db-journal"),
        (LITE_STORE, "PropertiesStore_v02"),
    ):
        if kind.endswith("-journal") and not include_journal:
            continue
        source = _source(ctx, target, kind)
        if not source:
            continue
        raw_total += source["raw_hits"]
        hits.extend(source["tokens"])
        sources.append(
            {
                "source": target,
                "kind": kind,
                "format": source["format"],
                "raw_hits": source["raw_hits"],
                "noise_hits": source["noise_hits"],
                "real_tokens": len(source["tokens"]),
                "size": source["size"],
            }
        )
    real = _deduplicate(hits)
    for item in real:
        res.add(
            "critical",
            f"Token dostępu Facebooka dla {item['name'] or item['uid'] or 'konta bez nazwy'}",
            detail=(
                f"{item['length']} znaków, znaleziony w: {', '.join(item['sources'])}"
                f" ({item['occurrences']}×)"
            ),
            values={
                "uid": item["uid"],
                "name": item["name"],
                "sources": item["sources"],
                "occurrences": item["occurrences"],
                "field": item["field"],
                "length": item["length"],
                "token": item["token"],
            },
        )
    res.add(
        "ok" if real else "warn",
        f"Tokeny dostępu EAA: {len(real)} unikalnych ({len(hits)} wystąpień, "
        f"surowych trafień {raw_total})",
        detail=(
            "tokeny leżą w polach JSON o nazwach związanych z autoryzacją; pozostałe trafienia "
            "to fragmenty base64 w blobach (powiadomienia push, drzewa interstitiali), "
            "więc nie są tokenami"
        ),
        values={
            "tokens": len(real),
            "occurrences": len(hits),
            "raw_hits": raw_total,
            "noise_hits": sum(source["noise_hits"] for source in sources),
            "by_uid": _by_uid(real),
            "sources": sources,
        },
    )
    res.data = {
        "tokens": real,
        "token_count": len(real),
        "occurrences": len(hits),
        "raw_hits": raw_total,
        "noise_hits": sum(source["noise_hits"] for source in sources),
        "by_uid": _by_uid(real),
        "sources": sources,
    }
    res.export(to_json(ctx.work("exports") / "fb_tokens.json", res.data, ctx.masker))
    res.export(
        to_csv(
            ctx.work("exports") / "fb_tokens.csv",
            ["uid", "name", "sources", "occurrences", "length", "token"],
            [
                [
                    item["uid"],
                    item["name"],
                    ", ".join(item["sources"]),
                    item["occurrences"],
                    item["length"],
                    item["token"],
                ]
                for item in real
            ],
            ctx.masker,
        )
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


def _by_uid(tokens: list[dict]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in tokens:
        out[item["uid"] or "?"] = item["name"] or ""
    return out


def _deduplicate(hits: list[dict]) -> list[dict]:
    """One entry per token value, with every place it was found.

    A token kept in ``prefs_db`` is usually also present in the rollback
    journal, which holds older copies of the same pages.  The account is taken
    from the source that names it, because the journal itself only stores the
    page bytes without a key that ties a token to an account.
    """
    merged: dict[str, dict] = {}
    for hit in hits:
        entry = merged.get(hit["token"])
        if entry is None:
            merged[hit["token"]] = {
                "token": token_of(hit["token"]),
                "uid": hit["uid"],
                "name": hit["name"],
                "field": hit["field"],
                "length": hit["length"],
                "occurrences": 1,
                "sources": [hit["source"]],
            }
            continue
        entry["occurrences"] += 1
        if hit["source"] not in entry["sources"]:
            entry["sources"].append(hit["source"])
        if not entry["uid"] and hit["uid"]:
            entry["uid"] = hit["uid"]
            entry["name"] = hit["name"]
    out = sorted(merged.values(), key=lambda item: (item["uid"] or "~", item["name"]))
    for item in out:
        item["value_length"] = len(str(item["token"]))
    return out


def _source(ctx: Ctx, target: str, kind: str) -> dict | None:
    try:
        local = ctx.materialise(target)
    except KeyError:
        return None
    blob = Path(local).read_bytes()
    verdict = appdata.classify_checked(blob[:MAGIC_PROBE_BYTES])
    out: dict = {
        "source": target,
        "kind": kind,
        "size": len(blob),
        "format": verdict["report"],
        "format_ours": verdict["format"],
        "format_magic": verdict["magic"],
        "format_note": verdict["note"],
        "raw_hits": len(appdata.raw_token_hits(blob)),
        "noise_hits": 0,
        "documents": 0,
        "tokens": [],
    }
    if kind == "PropertiesStore_v02":
        store = appdata.properties_store(blob)
        out["format"] = store["format"]
        out["documents"] = len(store["documents"])
        found = appdata.access_tokens(store["documents"])
    elif kind == "prefs_db-journal":
        found = _journal_tokens(blob)
    else:
        out["documents"] = len(appdata.preferences_documents(local))
        found = appdata.access_tokens(appdata.preferences_documents(local))
    for item in found:
        if item["noise"]:
            continue
        out["tokens"].append(
            {
                "uid": item["uid"],
                "name": item["name"],
                "field": item["field"],
                "length": item["length"],
                "token": item["token"],
                "source": target,
            }
        )
    out["noise_hits"] = max(
        out["raw_hits"] - len({item["token"] for item in out["tokens"]}), 0
    )
    return out


def _journal_tokens(blob: bytes) -> list[dict]:
    """Access tokens visible in the rollback journal of ``prefs_db``.

    The journal holds whole copies of the pages, so a token that was in
    ``preferences`` is still readable after the row was updated.  No account is
    claimed here: the account is resolved from the identical token in
    ``prefs_db`` itself, which is stronger evidence than a nearby key.
    """
    out: list[dict] = []
    for token in appdata.raw_token_hits(blob):
        if token.startswith(appdata.FB_TOKEN_BASE64_NOISE):
            continue
        out.append(
            {
                "uid": "",
                "name": "",
                "field": "journal",
                "length": len(token),
                "token": token,
                "noise": False,
            }
        )
    return out


register(
    ModuleSpec(
        id="fb_tokens",
        category="apps",
        title="mod.fb_tokens.title",
        summary="mod.fb_tokens.summary",
        params=[Param(key="journal", label="param.journal_scan", default=True, kind="bool")],
        run=run,
    )
)
