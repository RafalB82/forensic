# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Chromium-family artefact readers: Login Data, Cookies, History.

All three databases come in two flavours on Android: the standalone browser and
the embedded WebView.  They share the schema, and what matters forensically is
whether a stored secret is *actually* protected.  Password and cookie blobs on
this class of device carry no ``v10``/``v20`` prefix and live in the plain
``value`` column, so the helpers below report that verdict explicitly instead of
pretending they were decrypted.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from .sqlite_tools import connect

SECRET_PREFIXES = {
    "v10": "AES-128-CBC (Windows/legacy), key = DPAPI or keystore",
    "v20": "AES-256-GCM (Chromium 80+), key in Local State or keystore",
    "v11": "AES-256-GCM, key in Local State or keystore",
}
FB_URL_HINTS = (
    ("story_fbid", re.compile(r"story_fbid=(\d+)")),
    ("ft_ent_identifier", re.compile(r"ft_ent_identifier=([\w]+)")),
    ("profile_id", re.compile(r"[?&]id=(\d+)")),
    ("post_id", re.compile(r"/posts/(\d+)")),
    ("viewer_av", re.compile(r"[?&]av=(\d+)")),
    ("viewer_lst", re.compile(r"[?&]lst=([^&]+)")),
    ("page_id", re.compile(r"/(?:pg|page)/([\w]+)")),
)
CHROMIUM_EPOCH_DELTA = 11644473600


def chromium_time(value: int | None) -> str:
    """WebKit/Chromium timestamp (microseconds since 1601) as ISO UTC."""
    if not value:
        return ""
    try:
        seconds = value / 1_000_000 - CHROMIUM_EPOCH_DELTA
        return (
            _dt.datetime.fromtimestamp(seconds, _dt.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    except (OverflowError, OSError, ValueError):
        return str(value)


#: Everything in this module that produces a *value* rather than a count is a
#: heuristic, and a report that prints one without saying so is asserting more
#: than it knows.  The three sources, and what each rests on:
#:
#: * :func:`url_identity_hints` — seven regular expressions over URL query
#:   strings.  A parameter called ``av`` really does carry the logged-in account
#:   on m.facebook.com, but that is a convention of one deployment, not a
#:   specification, and the value is a *hint about* an account rather than a
#:   confirmed identity.
#: * :func:`classify_secret` — a test for a version prefix.  It says which
#:   algorithm Chromium *would* use for a blob, not that the blob is encrypted;
#:   a plaintext password that happens to start with the prefix would be
#:   misreported, and an encrypted value whose prefix was stripped would be
#:   called plaintext.
#: * :func:`decode_facebook_xs` — an assumption about one field order.  The
#:   layout is not stable across deployments and the function reports an
#:   unexpected shape rather than guessing.
#:
#: There is no reference implementation for any of them, so nothing external can
#: confirm or refute a single value here.  The strongest corroboration available
#: is internal: the same identifier appearing in two unrelated stores, such as an
#: account id in a cookie and in the history URLs.
HEURISTIC = "heurystyka: wzorzec adresu URL, nie potwierdzona tożsamość"
SECRET_VERDICT_BASIS = (
    "heurystyka: rozpoznanie prefiksu wersji szyfrowania, "
    "nie potwierdzenie że wartość jest zaszyfrowana"
)
XS_BASIS = (
    "heurystyka: założony układ pól ciasteczka xs, "
    "niestabilny między wdrożeniami Facebooka"
)


def classify_secret(blob: bytes | str | None) -> str:
    """Verdict for a stored password or cookie value.

    See :data:`SECRET_VERDICT_BASIS` for what this verdict does and does not
    establish.  A prefix identifies the algorithm Chromium would use; it does
    not prove the value is encrypted.
    """
    if blob is None:
        return "brak"
    if isinstance(blob, str):
        return "pusty" if not blob else "jawny tekst"
    if len(blob) == 0:
        return "pusty"
    for prefix, description in SECRET_PREFIXES.items():
        if blob[: len(prefix)] == prefix.encode():
            return f"szyfrowany ({prefix}): {description}"
    printable = sum(1 for b in blob if 32 <= b < 127)
    if printable == len(blob):
        return "jawny tekst (bez prefiksu v10/v20)"
    return f"binarny ({len(blob)} B), nie rozpoznany prefiks"


@dataclass
class LoginEntry:
    """One saved login."""

    origin_url: str
    action_url: str
    username: str
    password: bytes | None
    password_field: str
    signon_realm: str
    date_created: str
    date_password_modified: str
    times_used: int

    @property
    def verdict(self) -> str:
        return classify_secret(self.password)

    @property
    def password_text(self) -> str:
        blob = self.password
        if not blob:
            return ""
        if isinstance(blob, bytes):
            try:
                return blob.decode("utf-8")
            except UnicodeDecodeError:
                return blob.hex()
        return str(blob)

    def as_dict(self, reveal: bool = False, keep_tail: int = 4) -> dict:
        text = self.password_text
        if text and not reveal:
            text = f"{text[:0]}…{text[-keep_tail:]}" if keep_tail else "…"
        return {
            "origin_url": self.origin_url,
            "action_url": self.action_url,
            "username": self.username,
            "password": text,
            "password_verdict": self.verdict,
            "password_field": self.password_field,
            "signon_realm": self.signon_realm,
            "date_created": self.date_created,
            "times_used": self.times_used,
        }


def login_data(path: str | Path) -> dict:
    """Read a Chromium ``Login Data`` database."""
    path = Path(path)
    out: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if not out["exists"]:
        return out
    conn = connect(path)
    try:
        tables = [row[0] for row in conn.execute("select name from sqlite_master where type='table'")]
        out["tables"] = tables
        if "logins" not in tables:
            out["entries"] = []
            out["error"] = "brak tabeli logins"
            return out
        columns = [row[1] for row in conn.execute('pragma table_info("logins")')]
        out["schema"] = columns
        entries: list[LoginEntry] = []

        def column(name: str, fallback: str) -> str:
            return name if name in columns else fallback

        query = (
            "select origin_url, action_url, username_value, password_value,"
            f" {column('password_element', 'null')},"
            f" {column('signon_realm', 'null')},"
            f" {column('date_created', '0')},"
            f" {column('date_password_modified', '0')},"
            f" {column('times_used', '0')}"
            " from logins order by origin_url"
        )
        out["query"] = query
        for row in conn.execute(query):
            entries.append(
                LoginEntry(
                    origin_url=row[0] or "",
                    action_url=row[1] or "",
                    username=row[2] or "",
                    password=row[3],
                    password_field=str(row[4] or ""),
                    signon_realm=str(row[5] or ""),
                    date_created=chromium_time(row[6]),
                    date_password_modified=chromium_time(row[7]),
                    times_used=int(row[8] or 0),
                )
            )
        out["entries"] = entries
        out["count"] = len(entries)
        out["plaintext"] = sum(1 for e in entries if e.verdict.startswith("jawny"))
        out["encrypted"] = sum(1 for e in entries if e.verdict.startswith("szyfrowany"))
        out["empty"] = sum(1 for e in entries if e.verdict == "pusty")
        stats = conn.execute("select count(*) from stats").fetchone()[0]
        out["stats_rows"] = stats
    finally:
        conn.close()
    return out


def cookies(path: str | Path) -> dict:
    """Read a Chromium cookie store, flagging encrypted values."""
    path = Path(path)
    out: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if not out["exists"]:
        return out
    conn = connect(path)
    try:
        columns = [r[1] for r in conn.execute('pragma table_info("cookies")')]
        out["schema"] = columns
        pick = lambda name, fallback="null": name if name in columns else fallback  # noqa: E731
        query = (
            "select host_key, name, value, encrypted_value,"
            f" {pick('path')}, {pick('expires_utc', '0')},"
            f" {pick('is_secure', '0')}, {pick('is_httponly', '0')},"
            f" {pick('last_access_utc', '0')} from cookies"
        )
        out["query"] = query
        rows = []
        for row in conn.execute(query):
            host, name, value, encrypted, cpath, expires, secure, httponly, accessed = row
            blob = encrypted or b""
            rows.append(
                {
                    "host_key": host,
                    "name": name,
                    "value": value,
                    "value_length": len(value or ""),
                    "encrypted_length": len(blob) if isinstance(blob, (bytes, bytearray)) else 0,
                    "verdict": classify_secret(value or blob),
                    "path": cpath,
                    "expires_utc": chromium_time(expires) if expires else "",
                    "last_access_utc": chromium_time(accessed) if accessed else "",
                    "is_secure": bool(secure),
                    "is_httponly": bool(httponly),
                }
            )
        out["rows"] = rows
        out["count"] = len(rows)
        out["plaintext"] = sum(1 for r in rows if r["verdict"].startswith("jawny") or r["verdict"] == "pusty")
        out["hosts"] = sorted({r["host_key"] for r in rows})
    finally:
        conn.close()
    return out


def decode_facebook_xs(value: str) -> dict:
    """Expand a Facebook ``xs`` session cookie.

    The layout is not stable across deployments; on the reference device it is
    ``<prefix>:<session_key>:<sig_version>:<ts>:-1:-1`` and the account id lives
    in the separate ``c_user`` cookie, so nothing is assumed about the first
    field beyond reporting it.
    """
    out: dict[str, Any] = {
        "raw": value,
        "decoded": unquote(value or ""),
        "basis": XS_BASIS,
        "heuristic": True,
    }
    parts = out["decoded"].split(":")
    out["parts"] = parts
    if len(parts) < 3:
        out["note"] = "nietypowy format, za mało pól"
        return out
    if parts[0].isdigit() and int(parts[0]) < 1000:
        out["prefix"] = int(parts[0])
        out["session_key"] = parts[1]
        rest = parts[2:]
    else:
        out["session_key"] = parts[0]
        rest = parts[1:]
    for item in rest:
        if item.lstrip("-").isdigit() and 946_684_800 < abs(int(item)) < 4_102_444_800:
            out["issued_unix"] = int(item)
            try:
                out["issued_utc"] = (
                    _dt.datetime.fromtimestamp(int(item), _dt.timezone.utc)
                    .isoformat(timespec="seconds")
                    .replace("+00:00", "Z")
                )
            except (OverflowError, OSError, ValueError):
                pass
            break
    if len(rest) > 1 and rest[0].isdigit():
        out["signature_version"] = int(rest[0])
    out["note"] = "uid konta znajduje się w ciasteczku c_user"
    return out


def url_identity_hints(url: str) -> dict:
    """Pull account and object identifiers out of a Facebook or Google URL."""
    hints: dict[str, Any] = {}
    for key, pattern in FB_URL_HINTS:
        match = pattern.search(url or "")
        if match:
            hints[key] = match.group(1)
    if "viewer_lst" in hints:
        parts = hints["viewer_lst"].split(":")
        if len(parts) == 3 and parts[0].isdigit():
            hints["viewer_uid"] = parts[0]
            hints["author_uid"] = parts[1]
            hints["story_ts"] = parts[2]
    return hints


def history(path: str | Path, with_samples: int = 0) -> dict:
    """Read a Chromium ``History`` database: urls, visits, search terms."""
    path = Path(path)
    out: dict[str, Any] = {"path": str(path), "exists": path.exists()}
    if not out["exists"]:
        return out
    conn = connect(path)
    try:
        counts = {}
        for table in ("urls", "visits", "keyword_search_terms", "downloads", "segments", "top_sites"):
            try:
                counts[table] = conn.execute(f"select count(*) from {table}").fetchone()[0]
            except Exception:
                counts[table] = None
        out["counts"] = counts
        row = conn.execute("select count(*), min(last_visit_time), max(last_visit_time) from urls").fetchone()
        out["url_count"] = row[0]
        out["first_visit"] = chromium_time(row[1])
        out["last_visit"] = chromium_time(row[2])
        row = conn.execute("select min(visit_time), max(visit_time) from visits").fetchone()
        out["first_visit_time"] = chromium_time(row[0])
        out["last_visit_time"] = chromium_time(row[1])
        out["visits_per_day"] = _visits_per_day(conn)
        out["top_domains"] = _top_domains(conn, 15)
        out["sessions"] = sessions(conn)
        out["identity_hints"] = identity_hints(conn)
        out["search_terms"] = search_terms(conn, limit=0)
        if with_samples:
            out["samples"] = recent_urls(conn, with_samples)
    finally:
        conn.close()
    return out


def _visit_url_column(conn) -> str:
    columns = [r[1] for r in conn.execute('pragma table_info("visits")')]
    return "url" if "url" in columns else "url_id"


def _visits_per_day(conn) -> list[tuple]:
    column = _visit_url_column(conn)
    rows = conn.execute(f"select visit_time, {column} from visits order by visit_time").fetchall()
    per_day: dict[str, int] = {}
    for visit_time, _url in rows:
        day = chromium_time(visit_time)[:10]
        per_day[day] = per_day.get(day, 0) + 1
    return sorted(per_day.items(), key=lambda item: item[0])


def _top_domains(conn, limit: int) -> list[tuple]:
    rows = conn.execute(
        "select url, visit_count from urls order by visit_count desc"
    ).fetchall()
    counts: dict[str, int] = {}
    for url, visits in rows:
        host = urlparse(url or "").netloc or "(brak)"
        counts[host] = counts.get(host, 0) + (visits or 0)
    return sorted(counts.items(), key=lambda item: -item[1])[:limit]


def identity_hints(conn) -> list[dict]:
    """URLs that expose the acting account or the object being viewed.

    Every row carries ``heuristic`` and ``basis`` so that a report which prints
    these values is visibly printing a reading of a URL pattern, not a confirmed
    account identity.  See :data:`HEURISTIC`.
    """
    out: list[dict] = []
    seen: set[str] = set()
    for (url,) in conn.execute(
        "select url from urls where url like '%av=%' or url like '%lst=%'"
        " or url like '%story_fbid%' or url like '%ft_ent_identifier%'"
        " order by last_visit_time desc"
    ):
        hints = url_identity_hints(url)
        if not hints:
            continue
        key = json.dumps(hints, sort_keys=True) + url[:60]
        if key in seen:
            continue
        seen.add(key)
        hints["url"] = url[:220]
        hints["heuristic"] = True
        hints["basis"] = HEURISTIC
        out.append(hints)
    return out


def search_terms(conn, limit: int = 500) -> list[dict]:
    """Typed search terms with the URL they produced."""
    rows = conn.execute(
        "select k.term, u.url, u.last_visit_time, u.visit_count from keyword_search_terms k"
        " join urls u on u.id = k.url_id order by u.last_visit_time desc"
    ).fetchall()
    out = [
        {
            "term": row[0],
            "url": (row[1] or "")[:160],
            "last_visit": chromium_time(row[2]),
            "visit_count": row[3],
        }
        for row in (rows if not limit else rows[:limit])
    ]
    return out


def recent_urls(conn, limit: int = 20) -> list[dict]:
    rows = conn.execute(
        "select last_visit_time, url, title, visit_count from urls order by last_visit_time desc limit ?",
        (limit,),
    ).fetchall()
    return [
        {
            "last_visit": chromium_time(row[0]),
            "url": row[1],
            "title": row[2],
            "visit_count": row[3],
        }
        for row in rows
    ]


def sessions(conn, gap_seconds: int = 1800, min_size: int = 1) -> list[dict]:
    """Cluster consecutive visits into browsing sessions."""
    column = _visit_url_column(conn)
    rows = conn.execute(
        "select v.visit_time, v.id, v.from_visit, u.url, u.title from visits v"
        f" join urls u on u.id = v.{column} order by v.visit_time"
    ).fetchall()
    out: list[dict] = []
    current: dict | None = None
    previous: int | None = None
    for visit_time, visit_id, from_visit, url, title in rows:
        seconds = visit_time / 1_000_000
        if current is None or (previous is not None and seconds - previous > gap_seconds):
            current = {
                "start": chromium_time(visit_time),
                "start_unix": seconds,
                "end": chromium_time(visit_time),
                "visits": 0,
                "urls": [],
                "viewers": set(),
            }
            out.append(current)
        current["end"] = chromium_time(visit_time)
        current["visits"] += 1
        if len(current["urls"]) < 40:
            current["urls"].append((url or "")[:160])
        hints = url_identity_hints(url or "")
        if "viewer_uid" in hints:
            current["viewers"].add(hints["viewer_uid"])
        if "viewer_av" in hints:
            current["viewers"].add(hints["viewer_av"])
        previous = seconds
    for entry in out:
        entry["viewers"] = sorted(entry["viewers"])
        entry["domains"] = sorted({urlparse(u).netloc for u in entry["urls"] if u})[:10]
    return [entry for entry in out if entry["visits"] >= min_size]


def parse_query(url: str) -> dict:
    """Query parameters of a URL, values flattened."""
    try:
        return {key: value[0] for key, value in parse_qs(urlparse(url).query).items()}
    except Exception:
        return {}
