# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Parsers for per-application data left in an Android image.

Everything here is standard library only and works on raw bytes, so a module
can hand it what it read out of ext4 without materialising the file.  Two rules
run through the whole module:

* a blob is never silently reinterpreted — the format is detected and reported,
  and a blob that cannot be parsed yields a verdict instead of an exception;
* keys, blobs and tokens that are secret by nature are handed back as plain
  strings, and the *caller* decides to wrap them in :class:`Secret`.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import sqlite3
import subprocess
import xml.etree.ElementTree as ET
from typing import Any
from collections.abc import Iterable

from .readlog import ReadLog
from .xmlsafe import safe_fromstring

FB_TOKEN_RE = re.compile(rb"EAA[A-Za-z0-9_\-]{40,}")
FB_TOKEN_BASE64_NOISE = "EAAAAAAQ"
FB_TOKEN_FIELDS = ("unseen_count_access_token", "access_token", "auth_token", "token")

JAVA_MAGIC = b"\xac\xed"
JAVA_STRING_RE = re.compile(rb"[\x20-\x7e]{4,}")
SQLITE_MAGIC = b"SQLite format 3\x00"
MIB_RE = re.compile(rb"[\x20-\x7e]{16,}\.db")
PLAUSIBLE_FROM_MS = 1420070400000


def utc_from_ms(value: int | str | None) -> str:
    return _iso(_number(value) / 1000.0)


def utc_from_s(value: int | str | None) -> str:
    return _iso(_number(value))


def epoch_auto(value: int | str | None) -> dict[str, Any]:
    """Messenger mixes seconds and milliseconds in the same JSON documents.

    A value below 1e11 cannot be a millisecond stamp of this century, so it is
    read as seconds.  The unit that was assumed is reported alongside the date
    rather than hidden.
    """
    number = _number(value)
    if number <= 0:
        return {"value": value, "utc": "", "unit": ""}
    unit = "s" if number < 1e11 else "ms"
    seconds = number if unit == "s" else number / 1000.0
    return {"value": value, "utc": _iso(seconds), "unit": unit}


def _number(value: Any) -> float:
    if value is None or value == "":
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _iso(seconds: float) -> str:
    if not seconds:
        return ""
    try:
        return (
            _dt.datetime.fromtimestamp(seconds, _dt.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    except (OSError, OverflowError, ValueError):
        return ""


def classify(blob: bytes) -> str:
    """Name the container format of a blob without interpreting its contents."""
    if blob.startswith(SQLITE_MAGIC):
        return "sqlite"
    if blob.startswith(JAVA_MAGIC):
        return "java-serialized"
    head = blob[:512].lstrip()
    if head.startswith(b"<?xml") or head.startswith(b"<map>"):
        return "shared-prefs-xml"
    if head.startswith(b"{") or head.startswith(b"["):
        return "json"
    if len(blob) > 8 and int.from_bytes(blob[:2], "big") == 0x0002:
        return "ber-properties-store"
    return "opaque"


#: How many bytes libmagic is given.  Enough for a SQLite header, a Java
#: serialisation stream header and an XML prolog, and small enough that piping
#: a blob of any size costs the same.
MAGIC_PROBE_BYTES = 65536

#: libmagic's wording mapped onto our vocabulary.  "data" is deliberately
#: absent: it carries no information, and translating it into a class of our own
#: would invent certainty.  Text *is* mapped, because calling a readable
#: identifier file "opaque" is how an analyst ends up not looking inside it.
MAGIC_MAP = (
    ("sqlite", "sqlite"),
    ("java serialization", "java-serialized"),
    ("java class", "java-serialized"),
    ("json", "json"),
    ("xml", "shared-prefs-xml"),
    ("ascii text", "text"),
    ("utf-8 text", "text"),
    ("unicode text", "text"),
    ("iso-8859", "text"),
)


def magic_available() -> bool:
    """True when the ``file`` utility is installed, so libmagic can be asked."""
    from .imagemount import tool_path

    return bool(tool_path("file"))


def magic_verdict(blob: bytes) -> tuple[str, str]:
    """Ask libmagic what a blob is.

    Returns ``(our label, libmagic's own wording)``.  The label is ``""`` when
    libmagic says nothing useful, so the caller can tell "it disagreed" from
    "it had no opinion".

    This is the second opinion on :func:`classify`, and it exists because
    ``classify`` is ours: it was written by the same author as the report that
    cites it, so a rule that is wrong is wrong everywhere at once.  libmagic is
    a separate project with its own magic database, and the two agreeing on a
    real image is worth more than either being confident.
    """
    from .imagemount import tool_path

    binary = tool_path("file")
    if not binary or not blob:
        return "", ""
    try:
        proc = subprocess.run(
            [binary, "-b", "-"], input=blob[:MAGIC_PROBE_BYTES],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return "", ""
    raw = (proc.stdout or b"").decode("utf-8", "replace").strip()
    lowered = raw.lower()
    for needle, label in MAGIC_MAP:
        if needle in lowered:
            return label, raw
    return "", raw


def classify_checked(blob: bytes) -> dict[str, Any]:
    """Classify a blob twice — ours and libmagic's — and say whether they agree.

    The two answers are reported side by side rather than merged, because a
    disagreement is itself the finding: it means one of two independent
    implementations met something it does not handle, and the analyst should
    know which.  ``report`` is the label to print, which is ours unless we
    return ``opaque`` and libmagic recognised something.
    """
    ours = classify(blob)
    theirs, raw = magic_verdict(blob)
    out: dict[str, Any] = {
        "format": ours,
        "report": ours if ours != "opaque" or not theirs else theirs,
        "magic": theirs,
        "magic_raw": raw,
        "magic_available": magic_available(),
    }
    if not raw:
        out["note"] = "libmagic nie odpowiedział (brak narzędzia `file` lub pusty wynik)"
    elif not theirs:
        out["note"] = f"libmagic bez użytecznej etykiety: {raw}"
    elif ours == theirs:
        out["note"] = f"zgodne z libmagic ({raw})"
    elif ours == "opaque":
        out["note"] = f"nasz klasyfikator: opaque, libmagic: {raw} → raportujemy {theirs}"
    else:
        out["note"] = f"niezgodność: nasz {ours} vs libmagic {raw} → raportujemy {ours}"
    return out


def text_strings(blob: bytes, limit: int = 0) -> list[str]:
    """Printable ASCII runs, longest first — a last resort, reported as such."""
    found = {m.group().decode("ascii") for m in JAVA_STRING_RE.finditer(blob)}
    ordered = sorted(found, key=lambda item: (-len(item), item))
    return ordered[:limit] if limit else ordered


def is_encrypted(blob: bytes) -> bool:
    """Heuristic: no SQLite/XML magic, no printable text, no zero page runs."""
    if not blob or blob.startswith(SQLITE_MAGIC) or blob.startswith(JAVA_MAGIC):
        return False
    if len(blob) < 512:
        return False
    if JAVA_STRING_RE.search(blob[:4096]):
        return False
    sample = blob[:8192]
    return sample.count(b"\x00") < len(sample) // 64


def shared_prefs(blob: bytes) -> dict[str, Any]:
    """Read an Android ``shared_prefs/*.xml`` map into a flat dict."""
    out: dict[str, Any] = {}
    try:
        root = safe_fromstring(blob.decode("utf-8", "replace"))
    except ET.ParseError as exc:
        return {"error": str(exc)}
    for node in root:
        name = node.get("name")
        if not name:
            continue
        tag = node.tag
        value = node.get("value")
        if tag == "string":
            out[name] = value if value is not None else (node.text or "")
        elif tag == "int" or tag == "long":
            try:
                out[name] = int(value or 0)
            except ValueError:
                out[name] = value
        elif tag == "boolean":
            out[name] = value == "true"
        elif tag == "float":
            try:
                out[name] = float(value or 0.0)
            except ValueError:
                out[name] = value
        elif tag == "set":
            out[name] = [(child.text or "") for child in node]
        else:
            out[name] = value if value is not None else (node.text or "")
    return out


def java_serialized(blob: bytes) -> dict[str, Any]:
    """Describe a Java-serialised blob: stream magic, type names, string values.

    Java object streams are not parsed field by field here — the forensic value
    is in *which* class was written and which literals are inside it, which is
    exactly what a ``grep`` of the stream would show.
    """
    out: dict[str, Any] = {
        "magic": blob[:4].hex(),
        "is_java_stream": blob.startswith(JAVA_MAGIC),
        "strings": text_strings(blob),
    }
    out["types"] = sorted(
        {
            name
            for name in out["strings"]
            if len(name) <= 60 and " " not in name and ("." in name or name.startswith("["))
        }
    )
    out["type_descriptors"] = sorted(
        {m.group().decode("ascii") for m in TYPE_DESCRIPTOR_RE.finditer(blob)}
    )
    return out


JID_RE = re.compile(rb"(\d{6,15})@s\.whatsapp\.net")
DIGITS_RE = re.compile(rb"(?<![0-9])(\d{6,15})(?![0-9])")
TYPE_DESCRIPTOR_RE = re.compile(rb"\[(?:L[^;]{1,120};|[BCDFIJSZ])")


def whatsapp_identity(blob: bytes) -> dict[str, Any]:
    """Read ``com.whatsapp.files/me``, a Java-serialised ``Me`` object.

    The stream stores three numbers — country code, the e164 number and the
    national number — and *not* the Jabber ID, so the identifier is composed
    from the e164 value and is reported as derived.  The stream itself is
    described as a stream, so a composed value cannot be mistaken for a field
    that was read.
    """
    verdict = classify_checked(blob)
    out: dict[str, Any] = {
        "format": verdict["report"],
        "format_ours": verdict["format"],
        "format_magic": verdict["magic"],
        "format_note": verdict["note"],
        "size": len(blob),
        "is_java_stream": blob.startswith(JAVA_MAGIC),
    }
    parsed = java_serialized(blob)
    out["types"] = parsed["types"]
    out["type_descriptors"] = parsed["type_descriptors"]
    match = JID_RE.search(blob)
    if match:
        out["jabber_id"] = match.group(0).decode("ascii")
        out["jabber_id_derived"] = False
        out["e164"] = match.group(1).decode("ascii")
    digits = sorted(
        {item.group(1).decode("ascii") for item in DIGITS_RE.finditer(blob)},
        key=lambda value: (-len(value), value),
    )
    out["digit_fields"] = digits
    e164 = next((value for value in digits if value.startswith("48") and len(value) >= 10), "")
    national = next((value for value in digits if 8 <= len(value) <= 10), "")
    if e164:
        out["e164"] = out.get("e164", e164)
        out.setdefault("jabber_id", f"{e164}@s.whatsapp.net")
        out.setdefault("jabber_id_derived", True)
        out["country_code"] = "48" if e164.startswith("48") else ""
    out["number"] = out.get("number", national)
    return out


def properties_store(blob: bytes) -> dict[str, Any]:
    """Facebook Lite ``files/PropertiesStore_v02``.

    The file is a private key/value container (not protobuf, not SQLite).  What
    survives the format is the set of JSON documents written into it, so the
    store is scanned for complete JSON objects and they are returned as decoded
    records.  The container is reported as unknown rather than guessed at.
    """
    verdict = classify_checked(blob)
    out: dict[str, Any] = {
        "size": len(blob),
        "format": verdict["report"],
        "format_ours": verdict["format"],
        "format_magic": verdict["magic"],
        "format_note": verdict["note"],
        "container": "nieznany (własny magazyn par klucz/wartość Facebook Lite)",
        "documents": [],
    }
    seen: set[str] = set()
    text = blob.decode("utf-8", "replace")
    index = 0
    while True:
        start = text.find("{", index)
        if start < 0:
            break
        end = _json_end(text, start)
        if end is None:
            index = start + 1
            continue
        candidate = text[start:end]
        if candidate not in seen:
            seen.add(candidate)
            try:
                out["documents"].append(json.loads(candidate))
            except ValueError:
                pass
        index = max(end, start + 1)
    return out


def _json_end(text: str, start: int, limit: int = 1_000_000) -> int | None:
    """End offset (exclusive) of the JSON object opening at ``start``."""
    depth = 0
    in_string = False
    escaped = False
    for pos in range(start, min(len(text), start + limit)):
        char = text[pos]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return pos + 1
    return None


def preferences_rows(path: str, log: ReadLog | None = None) -> list[tuple]:
    """Every ``(key, type, value)`` row of Messenger's ``preferences`` table.

    Returns an empty list when the table cannot be read, because that is what a
    caller iterating rows expects — so a caller that reports a **count** has to
    say what an empty list means, and that is what ``log`` is for.  Without it
    this function cannot tell its caller anything, and both of its callers did
    read the empty list as "there is nothing here": ``fb_tokens`` reported zero
    access tokens and ``login_timeline`` reported an empty Messenger timeline,
    one of them from a database neither had opened successfully.
    """
    conn = _open(path)
    try:
        return [(str(k), t, v) for k, t, v in conn.execute("select key, type, value from preferences")]
    except sqlite3.Error as exc:
        if log is not None:
            log.unreadable(path, exc, where="preferences")
        return []
    finally:
        conn.close()


def preferences_documents(path: str, log: ReadLog | None = None) -> list[Any]:
    """JSON documents stored in ``preferences``, decoded.

    Messenger keeps interstitial trees and push payloads in the same table as
    the account records, so the whole table is needed to tell a real token from
    a base64 coincidence.
    """
    out: list[Any] = []
    for _key, _kind, value in preferences_rows(path, log):
        if not isinstance(value, str) or '"' not in value:
            continue
        try:
            document = json.loads(value)
        except ValueError:
            continue
        if isinstance(document, (dict, list)):
            out.append(document)
    return out


def _uid_of(document: Any) -> str:
    if isinstance(document, dict):
        for key in ("uid", "fbid", "id"):
            value = document.get(key)
            if isinstance(value, (str, int)):
                return str(value)
        for value in document.values():
            found = _uid_of(value)
            if found:
                return found
    return ""


def _name_of(document: Any) -> str:
    if isinstance(document, dict):
        for key in ("name", "display_name", "username"):
            value = document.get(key)
            if isinstance(value, str) and value:
                return value
        for value in document.values():
            found = _name_of(value)
            if found:
                return found
    return ""


def access_tokens(documents: Iterable[Any]) -> list[dict[str, Any]]:
    """Facebook access tokens (``EAA*``) with the account they belong to.

    Two classes of match are kept apart on purpose: a token sitting in a named
    JSON field is a real access token, while ``EAA...`` inside a base64 blob
    (expo push payloads, interstitial trees) is a coincidence of the alphabet.
    """
    out: list[dict[str, Any]] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        for key, value in document.items():
            if not isinstance(value, str) or not value.startswith("EAA"):
                continue
            entry = {
                "field": key,
                "uid": _uid_of(document),
                "name": _name_of(document),
                "length": len(value),
                "noise": value.startswith(FB_TOKEN_BASE64_NOISE) or key not in FB_TOKEN_FIELDS,
                "token": value,
            }
            out.append(entry)
    return out


def raw_token_hits(blob: bytes) -> list[str]:
    """Every ``EAA*`` run in a blob, deduplicated, in order of appearance."""
    out: list[str] = []
    for match in FB_TOKEN_RE.finditer(blob):
        value = match.group().decode("ascii")
        if value not in out:
            out.append(value)
    return out


def messenger_accounts(rows: Iterable[tuple]) -> list[dict[str, Any]]:
    """``/orca_accounts/saved_*`` rows of Messenger's ``prefs_db``."""
    out: list[dict[str, Any]] = []
    for key, _kind, value in rows:
        key = str(key)
        if not key.startswith("/orca_accounts/saved_"):
            continue
        try:
            document = json.loads(value) if isinstance(value, str) else {}
        except ValueError:
            continue
        if not isinstance(document, dict):
            continue
        uid = str(document.get("uid") or key.rsplit("/", 1)[-1])
        logout = epoch_auto(document.get("last_logout_timestamp"))
        unseen = epoch_auto(document.get("last_unseen_timestamp"))
        out.append(
            {
                "uid": uid,
                "name": document.get("name", ""),
                "kind": "page" if document.get("is_page_account") else "user",
                "is_soap_account": bool(document.get("is_soap_account")),
                "last_logout": logout,
                "last_logout_utc": logout["utc"],
                "last_unseen": unseen,
                "last_unseen_utc": unseen["utc"],
                "access_token": document.get("unseen_count_access_token")
                or document.get("access_token")
                or "",
                "key": key,
            }
        )
    out.sort(key=lambda item: int(item["uid"]) if item["uid"].isdigit() else 0)
    return out


def _open(path: str) -> sqlite3.Connection:
    """Read-only, immutable open of an extracted database.

    Goes through :func:`sqlite_tools.connect` so the URI is percent-encoded
    there: a name with ``#``, ``?`` or ``%`` in it has to survive being put in
    a URI, and that is one implementation, not two.
    """
    from .sqlite_tools import connect

    return connect(path, immutable=True)


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {row[0] for row in conn.execute("select name from sqlite_master where type='table'")}


def _count(conn: sqlite3.Connection, table: str) -> int:
    if table not in _table_names(conn):
        return -1
    quoted = '"' + table.replace('"', '""') + '"'
    try:
        return int(conn.execute(f"select count(*) from {quoted}").fetchone()[0])
    except sqlite3.Error:
        return -1


def integrity(path: str) -> str:
    conn = _open(path)
    try:
        return str(conn.execute("PRAGMA integrity_check").fetchone()[0])
    except sqlite3.Error as exc:
        return f"error: {exc}"
    finally:
        conn.close()


def messenger_threads_db(path: str, top_threads: int = 20, top_senders: int = 20) -> dict[str, Any]:
    """``threads_db2`` — the local Messenger store with the message text."""
    out: dict[str, Any] = {"file": path, "verdict": "", "counts": {}}
    conn = _open(path)
    try:
        names = _table_names(conn)
        out["integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        for table in (
            "threads",
            "messages",
            "thread_users",
            "thread_participants",
            "message_reactions",
            "folders",
            "properties",
        ):
            out["counts"][table] = _count(conn, table)
        if "messages" in names:
            row = conn.execute(
                "select count(*),"
                " min(case when timestamp_ms > 0 then timestamp_ms end),"
                " max(case when timestamp_ms > 0 then timestamp_ms end),"
                " sum(case when timestamp_ms = 0 then 1 else 0 end),"
                " sum(case when text is not null and text != '' then 1 else 0 end),"
                " sum(case when attachments is not null and attachments != '' then 1 else 0 end)"
                " from messages"
            ).fetchone()
            out["messages_total"] = int(row[0] or 0)
            out["first_message_utc"] = utc_from_ms(row[1])
            out["last_message_utc"] = utc_from_ms(row[2])
            out["zero_timestamps"] = int(row[3] or 0)
            out["with_text"] = int(row[4] or 0)
            out["with_attachments"] = int(row[5] or 0)
            if row[1] and row[2]:
                out["valid_range_utc"] = [utc_from_ms(row[1]), utc_from_ms(row[2])]
            sane = conn.execute(
                "select min(case when timestamp_ms >= %d then timestamp_ms end),"
                " max(case when timestamp_ms >= %d then timestamp_ms end),"
                " sum(case when timestamp_ms > 0 and timestamp_ms < %d then 1 else 0 end)"
                " from messages" % (PLAUSIBLE_FROM_MS, PLAUSIBLE_FROM_MS, PLAUSIBLE_FROM_MS)
            ).fetchone()
            out["implausible_before"] = utc_from_ms(PLAUSIBLE_FROM_MS)
            out["implausible_timestamps"] = int(sane[2] or 0)
            out["plausible_range_utc"] = [utc_from_ms(sane[0]), utc_from_ms(sane[1])]
        if "threads" in names:
            people = _people(conn, names)
            out["threads"] = [
                {
                    "thread_key": r[0],
                    "name": r[1] or people.get(r[0], ""),
                    "named_by": "threads.name" if r[1] else ("thread_participants" if people.get(r[0]) else ""),
                    "messages": r[2],
                    "unread": r[3],
                    "last_message_utc": utc_from_ms(r[4]),
                    "snippet": (r[5] or "")[:160],
                }
                for r in conn.execute(
                    "select thread_key, name, approx_total_message_count,"
                    " unread_message_count, timestamp_ms, snippet"
                    " from threads order by timestamp_ms desc limit ?",
                    (top_threads,),
                )
            ]
        if "thread_users" in names:
            out["top_senders"] = [
                {"name": r[0], "messages": r[1]}
                for r in conn.execute(
                    "select u.name, count(*) as c from messages m"
                    " join thread_users u on u.user_key ="
                    " (select json_extract(m.sender, '$.user_key'))"
                    " where u.name is not null and u.name != ''"
                    " group by u.name order by c desc limit ?",
                    (top_senders,),
                )
            ] or _senders_by_snippet(conn, top_senders)
        out["verdict"] = (
            "baza z treścią rozmów (text w messages) — odzysk możliwy"
            if out.get("with_text")
            else "brak tekstu w messages"
        )
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    finally:
        conn.close()
    return out


def _people(conn: sqlite3.Connection, names: set[str]) -> dict[str, str]:
    """Thread key → contact name, for threads Messenger itself left unnamed.

    A one-to-one thread carries no ``name``, and the viewer is a participant of
    it too, so the counterpart is taken from the thread key itself
    (``ONE_TO_ONE:<uid>:<viewer uid>``) and resolved through ``thread_users``.
    """
    if "thread_participants" not in names or "thread_users" not in names:
        return {}
    try:
        by_key: dict[str, str] = {
            str(user_key): str(name)
            for user_key, name in conn.execute(
                "select user_key, name from thread_users where name is not null and name != ''"
            )
        }
        members: dict[str, list[str]] = {}
        for thread_key, user_key in conn.execute(
            "select thread_key, user_key from thread_participants"
        ):
            members.setdefault(str(thread_key), []).append(str(user_key))
    except sqlite3.Error:
        return {}
    out: dict[str, str] = {}
    for thread_key, keys in members.items():
        if thread_key.startswith("ONE_TO_ONE:"):
            parts = thread_key.split(":")
            if len(parts) == 3:
                counterpart = next(
                    (by_key.get(key) for key in keys if key.endswith(":" + parts[1])),
                    None,
                )
                if counterpart:
                    out[thread_key] = counterpart
                    continue
        names_here = sorted(by_key.get(key, "") for key in keys if key in by_key)
        if names_here and names_here[0]:
            out[thread_key] = names_here[0]
    return out


def _senders_by_snippet(conn: sqlite3.Connection, limit: int) -> list[dict[str, Any]]:
    """Sender names, counted from the snippets Messenger keeps per thread."""
    if "threads" not in _table_names(conn):
        return []
    out = []
    for name, count in conn.execute(
        "select snippet_sender, count(*) from threads"
        " where snippet_sender is not null and snippet_sender != ''"
        " group by snippet_sender order by count(*) desc limit ?",
        (limit,),
    ):
        out.append({"name": str(name)[:120], "messages": int(count)})
    return out


def messenger_prefs_db(path: str) -> dict[str, Any]:
    """Messenger ``prefs_db``: saved accounts, login markers, machine id."""
    out: dict[str, Any] = {"file": path, "accounts": [], "keys": {}}
    conn = _open(path)
    try:
        out["integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        out["rows"] = _count(conn, "preferences")
        rows = list(conn.execute("select key, type, value from preferences"))
    except sqlite3.Error as exc:
        out["error"] = str(exc)
        conn.close()
        return out
    conn.close()
    out["accounts"] = messenger_accounts(rows)
    for key, _kind, value in rows:
        key = str(key)
        if key == "/auth/auth_machine_id":
            out["machine_id"] = value if isinstance(value, str) else ""
        elif key == "/unified_account_login/login_last_success_ts":
            out["last_login"] = epoch_auto(value)
            out["last_login_utc"] = out["last_login"]["utc"]
        elif key.startswith("/unified_account_login/"):
            out["keys"][key.rsplit("/", 1)[-1]] = value
    out["account_uids"] = [item["uid"] for item in out["accounts"]]
    return out


def messenger_msys(path: str) -> dict[str, Any]:
    """``msys_database_*`` — the table holding the E2EE identity and auth token."""
    out: dict[str, Any] = {
        "file": path,
        "tables_present": [],
        "counts": {},
        "auth_tokens": [],
        "identities": [],
    }
    conn = _open(path)
    try:
        out["integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        names = _table_names(conn)
        for table in (
            "crypto_auth_token",
            "secure_message_client_identity_v2",
            "secure_message_sender_key",
            "secure_message_pre_keys_v2",
            "contacts",
            "client_threads",
        ):
            if table in names:
                out["tables_present"].append(table)
                out["counts"][table] = _count(conn, table)
        if "crypto_auth_token" in names:
            for uid, length, expiry, session in conn.execute(
                "select verifier_id, length(token), expiration_timestamp_sec, session_id"
                " from crypto_auth_token"
            ):
                out["auth_tokens"].append(
                    {
                        "verifier_id": uid,
                        "token_bytes": length,
                        "expires_unix": expiry,
                        "expires_utc": utc_from_s(expiry),
                        "session_id": session,
                    }
                )
        if "secure_message_client_identity_v2" in names:
            for row in conn.execute(
                "select crypto_mailbox_type, local_registration_id,"
                " length(identity_key_public_blob), length(identity_key_private_blob),"
                " length(wcc_client_key_private_blob), uuid, wa_device_id"
                " from secure_message_client_identity_v2"
            ):
                out["identities"].append(
                    {
                        "crypto_mailbox_type": row[0],
                        "local_registration_id": row[1],
                        "identity_key_public_bytes": row[2],
                        "identity_key_private_bytes": row[3],
                        "wcc_client_key_private_bytes": row[4],
                        "uuid": row[5],
                        "wa_device_id": row[6],
                        "private_key_present": bool(row[3]),
                    }
                )
        if "secure_message_sender_key" in names:
            out["sender_keys"] = _count(conn, "secure_message_sender_key")
        out["message_base_key_rows"] = _count(conn, "message_base_key")
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    finally:
        conn.close()
    out.setdefault("counts", {})
    if out.get("identities") and any(item["private_key_present"] for item in out["identities"]):
        out["verdict"] = "para kluczy E2EE obecna lokalnie (bloby prywatne)"
    elif out.get("auth_tokens"):
        out["verdict"] = "brak blobów prywatnych; dostępne tylko tokeny autoryzacji"
    else:
        out["verdict"] = "brak danych o parach kluczy i tokenach"
    return out


METADATA_TABLES = ("_shared_version", "android_metadata", "sqlite_sequence")


def messenger_tincan(path: str) -> dict[str, Any]:
    """``tincan_db_*`` — P2P store; the verdict is about it being empty."""
    out: dict[str, Any] = {"file": path, "non_empty": {}, "tables_total": 0}
    conn = _open(path)
    try:
        out["integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        names = _table_names(conn)
        out["tables_total"] = len(names)
        for table in sorted(names):
            if table in METADATA_TABLES:
                continue
            count = _count(conn, table)
            if count > 0:
                out["non_empty"][table] = count
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    finally:
        conn.close()
    out["verdict"] = (
        "poprawna baza, ale bez rekordów (0 wierszy w tabelach treści)"
        if not out["non_empty"]
        else f"tabele z danymi: {sorted(out['non_empty'])}"
    )
    return out


#: The database header every SQLite file starts with.  Its absence is the first
#: thing to notice about a file that is supposed to be one.
SQLITE_HEADER = b"SQLite format 3\x00"

#: WhatsApp's end-to-end-encrypted backup stores carry a protobuf header in
#: front of the database, so the file does **not** begin with the SQLite header
#: and libsqlite3 answers only "file is not a database".  The layout is:
#:
#:     [1 byte: length of the protobuf][optional 0x01: a features table follows]
#:     [protobuf][ciphertext]
#:
#: and inside the protobuf, field 2 is the crypt14 cipher block and field 3 the
#: crypt15 IV; each carries a 16-byte IV in a sub-field (5 for crypt14, 1 for
#: crypt15).  crypt15 has been the current format since 2021.
#:
#: The header is a **length-prefixed protobuf**, not an encryption — reading it
#: needs no key.  That is the whole point of parsing it here: the version, the IV
#: and the offset where the ciphertext starts are all obtainable from a file we
#: cannot decrypt, and "this is an encrypted WhatsApp backup" is a finding in its
#: own right.  Only the payload stays closed.
WA_CRYPT15 = "crypt15"
WA_CRYPT14 = "crypt14"


def _protobuf_fields(buf: bytes) -> list[tuple[int, int, bytes]]:
    """Walk length-delimited protobuf fields, returning ``(number, wiretype, value)``.

    Only wire type 2 (length-delimited) is decoded, which is all the header uses.
    A minimal varint reader is spelled out rather than taken from a library
    because this is the only place in the project that touches protobuf, and the
    format is stable and tiny.
    """
    out: list[tuple[int, int, bytes]] = []
    pos = 0
    end = len(buf)
    while pos < end:
        try:
            tag = 0
            shift = 0
            while True:
                byte = buf[pos]
                pos += 1
                tag |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
                if shift > 63 or pos >= end:
                    return out
            number, wire = tag >> 3, tag & 0x07
            if wire != 2:
                # Anything else (varint, fixed) is skipped by its own length,
                # which this header never uses; bail out rather than guess.
                return out
            size = 0
            shift = 0
            while True:
                byte = buf[pos]
                pos += 1
                size |= (byte & 0x7F) << shift
                if not byte & 0x80:
                    break
                shift += 7
                if shift > 63 or pos >= end:
                    return out
            if pos + size > end:
                return out
            out.append((number, wire, buf[pos : pos + size]))
            pos += size
        except IndexError:
            return out
    return out


def whatsapp_crypt_header(head: bytes) -> dict[str, Any] | None:
    """Recognise a crypt14/crypt15 WhatsApp backup header.

    Returns ``None`` when the bytes are not such a header, which is the common
    case: a plain SQLite database, a truncated file, or an unrelated blob.  The
    test is deliberately strict — a 16-byte IV has to come out — because a wrong
    "this is encrypted" is worse than a plain "not a database": one sends the
    analyst looking for a key they do not have.
    """
    if not head or head.startswith(SQLITE_HEADER) or len(head) < 3:
        return None
    size = head[0]
    pos = 1
    if head[1] == 0x01:  # a feature table precedes the protobuf, msgstore only
        pos = 2
    if not 2 <= size <= len(head) - pos:
        return None
    body = head[pos : pos + size]
    version = iv = None
    iv_field = None
    for number, _wire, value in _protobuf_fields(body):
        if number == 2:
            version, iv_field = WA_CRYPT14, 5
        elif number == 3:
            version, iv_field = WA_CRYPT15, 1
        else:
            continue
        for sub, _w, sub_value in _protobuf_fields(value):
            if sub == iv_field and len(sub_value) == 16:
                iv = sub_value
        if iv is not None:
            break
    if version is None or iv is None:
        return None
    return {
        "encrypted": True,
        "version": version,
        "iv": iv.hex(),
        "header_len": pos + size,
        "key_available": False,
        "verdict": (
            f"zaszyfrowana kopia WhatsApp ({version}), "
            f"IV w nagłówku, brak klucza w obrazie — treść bazy zamknięta"
        ),
        "note": (
            "Nagłówek to protobuf długością poprzedzony, nie szyfrowanie: wersję, IV "
            "i przesunięcie na tekst szyfrowany widać bez klucza. Odszyfrowanie "
            "wymaga klucza (crypt15: pętla HMAC-SHA256 z ziarna prywatnego), "
            "którego w obrazie nie ma."
        ),
    }


#: WhatsApp's Android message-type numbering, keyed by **canonical kind**.
#:
#: Provenance, stated because it is the whole lesson of this table.  The first
#: version took its labels from a third-party tool and put "13 = GIF" in the
#: dictionary.  The reference image then contradicted it: its one type-13 message
#: carries ``mime_type = video/mp4``, 274 412 bytes, ``gif_attribution = 0`` and no
#: ``is_animated_sticker`` — an ordinary video, not a GIF.  A table copied from
#: someone else's tool is exactly as wrong as one remembered from documentation,
#: and nothing in the code would have said so.
#:
#: So the labels here are deliberately small, and every one is checked against
#: what the image actually holds: :func:`_whatsapp_type_profile` reports the MIME
#: types observed for each code and flags the code as **disputed** when they
#: disagree with the label below.  A disputed label is printed with the
#: observation attached, not hidden and not trusted.
#:
#: The only source of record here is the published forensic analysis of the
#: application (Arenaz Benito, *Análisis forense de la aplicación WhatsApp en
#: sistemas Android e iOS*, Salamanca 2026); GPL-3.0 third-party tools were used
#: to cross-check and one of them proved unreliable, so none is cited as
#: authority.
WA_KIND_LABELS = {
    "text": "tekst",
    "image": "obraz",
    "audio": "audio lub notatka głosowa",
    "video": "wideo",
    "contact": "wizytówka",
    "location": "lokalizacja",
    "live_location": "lokalizacja w czasie rzeczywistym",
    "system": "wiadomość systemowa",
    "document": "dokument",
    "call": "połączenie",
    "call_missed": "połączenie nieodebrane",
    "gif": "GIF",
    "sticker": "naklejka",
    "view_once": "jednorazowa",
    "ephemeral": "znikająca wiadomość",
    "poll": "ankieta",
    "reaction": "reakcja",
    "deleted": "usunięta",
    "album": "album",
}

#: Code -> canonical kind, for the two Android columns.  Kept separate from the
#: labels because the two columns have their own numbering, and applying the
#: newer table to the older column is how a plausible wrong label gets in.
WA_MEDIA_WA_TYPE = {
    0: "text", 1: "image", 2: "audio", 3: "video", 4: "contact", 5: "location",
    8: "call", 9: "document", 10: "call_missed", 13: "gif", 16: "live_location",
    20: "sticker",
}
WA_MESSAGE_TYPE = {
    0: "text", 1: "image", 2: "audio", 3: "video", 4: "contact", 5: "location",
    7: "system", 9: "document", 10: "call", 13: "gif", 16: "call_missed",
    20: "live_location", 35: "ephemeral", 47: "view_once", 49: "reaction",
    51: "poll", 53: "album",
}

#: MIME major type each kind must fall under.  A code whose observed MIME falls
#: outside this is reported as disputed rather than relabelled silently: the
#: dictionary may be outdated, the MIME may be a container choice, and the
#: analyst is better served by seeing both than by being told one of them.
WA_KIND_MIME = {
    "image": {"image"},
    "audio": {"audio"},
    "video": {"video"},
    "document": {"application", "text"},
    # GIF oczekuje obrazu. Pierwsza wersja dopuszczała tu "video", bo
    # WhatsApp czasem trzyma GIF-y jako mp4 — ale wtedy `gif_attribution`
    # bywa ustawione, a na obrazie referencyjnym jest zerowe. Rozszerzenie
    # rodziny wyłączyłoby sam check, który ma tę rozbieżność wychwycić.
    "gif": {"image"},
    "sticker": {"image"},
    "view_once": {"image", "video", "audio"},
    "contact": {"text", "vcard"},
    "location": {"", "text"},
    "live_location": {"", "text"},
    "poll": {"text", "application"},
    "reaction": {"", "text"},
    "deleted": set(),
    "album": {"image", "video", "text"},
    "system": {"", "text"},
    "call": {"", "text"},
    "call_missed": {"", "text"},
    "text": {"", "text"},
    "ephemeral": {"", "text"},
}


def _kind_for(value: Any, column: str) -> dict[str, Any]:
    """One message-type code: its canonical kind, or an admission of ignorance."""
    try:
        code = int(value)
    except (TypeError, ValueError):
        return {"code": None, "kind": None, "label": "brak kodu typu", "disputed": False}
    table = WA_MESSAGE_TYPE if column == "message_type" else WA_MEDIA_WA_TYPE
    kind = table.get(code)
    if kind is None:
        return {
            "code": code,
            "kind": "uncatalogued",
            "label": f"niekatalogowany ({code})",
            "disputed": False,
        }
    return {
        "code": code,
        "kind": kind,
        "label": WA_KIND_LABELS.get(kind, kind),
        "disputed": False,
    }


def whatsapp_message_type(value: Any, column: str = "media_wa_type") -> dict[str, Any]:
    """Public wrapper, for callers that only have a code."""
    return _kind_for(value, column)



def _whatsapp_type_profile(conn: sqlite3.Connection) -> dict[str, Any]:
    """Message types and directions, which say what the conversation *was*.

    Two columns carry this depending on the WhatsApp generation: ``message_type``
    in recent schemas, ``media_wa_type`` in the older ones that the reference
    image uses.  Both are read when present and the one used is named, because
    "206 messages" says nothing while "169 text, 36 images, 1 GIF, 7 outgoing
    views" describes an account.

    Codes outside the documented table are counted and labelled ``niekatalogowany
    (N)`` rather than dropped: an unrecognised code is itself a fact about which
    WhatsApp build wrote the row, and losing it would make the counts lie.

    The dictionary is treated as a **claim to be checked**, not as an answer.  For
    every code the MIME types actually observed in this image are reported
    alongside the label, and a code whose MIME falls outside its declared family
    is marked ``disputed``.  That is not decoration: it is what caught a wrong
    entry the moment this was written, on a table that had been copied from a
    third-party tool and looked perfectly reasonable.
    """
    names = _table_names(conn)
    if "messages" not in names:
        return {}
    columns = {row[1] for row in conn.execute("pragma table_info('messages')")}
    column = "message_type" if "message_type" in columns else (
        "media_wa_type" if "media_wa_type" in columns else ""
    )
    if not column:
        return {}
    profile: dict[str, Any] = {
        "type_column": column,
        "types": {},
        "type_kinds": {},
        "type_mimes": {},
        "type_disputed": {},
    }
    try:
        rows = conn.execute(
            f'select "{column}", count(*) from messages group by 1 order by 2 desc'
        ).fetchall()
    except sqlite3.Error:
        return profile
    has_media = "message_media" in names
    for value, count in rows:
        entry = _kind_for(value, column)
        code = str(entry["code"])
        profile["types"][code] = int(count)
        profile["type_kinds"][entry["kind"]] = (
            profile["type_kinds"].get(entry["kind"], 0) + int(count)
        )
        if has_media:
            try:
                mimes = sorted(
                    {
                        str(r[0]).split("/")[0].lower()
                        for r in conn.execute(
                            "select distinct mm.mime_type from message_media mm"
                            " join messages m on m._id = mm.message_row_id"
                            f' where m."{column}" = ?',
                            (value,),
                        )
                        if r[0]
                    }
                )
            except sqlite3.Error:
                mimes = []
            if mimes:
                profile["type_mimes"][code] = mimes
                allowed = WA_KIND_MIME.get(entry["kind"])
                if allowed is not None and not (set(mimes) & allowed):
                    entry["disputed"] = True
                    entry["label"] = f"{entry['label']} (sporne: {','.join(mimes)})"
                    profile["type_disputed"][code] = {
                        "dictionary": WA_KIND_LABELS.get(entry["kind"], entry["kind"]),
                        "observed_mime": mimes,
                        "why": (
                            "MIME obserwowane w obrazie nie należy do rodziny "
                            f"deklarowanej dla typu '{entry['kind']}'; słownik może być "
                            "nieaktualny albo MIME może być kontenerem wybranym przez "
                            "Whatsappa. Oba odczyty zostawione, żeby analityk widział "
                            "sprzeczność zamiast wybrać jedną z wersji po cichu."
                        ),
                    }
        profile.setdefault("type_labels", {})[code] = entry["label"]

    if "starred" in columns:
        try:
            profile["starred"] = int(
                conn.execute("select count(*) from messages where starred = 1").fetchone()[0]
            )
        except sqlite3.Error:
            # ``None`` and not an absent key.  The caller used to read this with
            # ``msgstore.get("starred", 0)``, so leaving the key out turned a
            # failed query into "0 oznaczonych gwiazdką" — a finding that the
            # device starred nothing, printed on evidence we never read.
            profile["starred"] = None
    if "forwarded" in columns:
        try:
            profile["forwarded"] = int(
                conn.execute(
                    "select count(*) from messages where forwarded is not null"
                    " and forwarded != 0"
                ).fetchone()[0]
            )
        except sqlite3.Error:
            profile["forwarded"] = None
    return profile


def whatsapp_msgstore(path: str, media_limit: int = 200) -> dict[str, Any]:
    """``msgstore.db`` — messages, media references and the phone's own jid.

    A file that turns out to be an end-to-end-encrypted backup is reported as
    such and left closed.  The alternative — handing it to libsqlite3 and
    relaying "file is not a database" — tells the analyst nothing and suggests
    the extraction failed, when in fact the file is intact and simply sealed.
    """
    out: dict[str, Any] = {"file": path, "counts": {}}
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
    except OSError as exc:
        out["error"] = f"nieczytelny plik: {exc}"
        return out
    sealed = whatsapp_crypt_header(head)
    if sealed:
        out.update(sealed)
        out["counts"] = {}
        return out
    if not head.startswith(SQLITE_HEADER):
        out["error"] = (
            "plik nie zaczyna się nagłówkiem SQLite i nie jest kopią zaszyfrowaną "
            "WhatsApp (crypt14/crypt15) — albo jest uszkodzony, albo to inny format"
        )
        out["sqlite_header"] = False
        return out
    conn = _open(path)
    try:
        out["integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        for table in ("messages", "chat", "jid", "message_media", "receipts", "message_forwarded"):
            out["counts"][table] = _count(conn, table)
        if "messages" in _table_names(conn):
            row = conn.execute(
                "select count(*), min(timestamp), max(timestamp),"
                " sum(case when data is not null and data != '' then 1 else 0 end),"
                " sum(case when key_from_me = 1 then 1 else 0 end)"
                " from messages"
            ).fetchone()
            out["messages_total"] = int(row[0] or 0)
            out["first_message_utc"] = utc_from_ms(row[1])
            out["last_message_utc"] = utc_from_ms(row[2])
            out["with_text"] = int(row[3] or 0)
            out["outgoing"] = int(row[4] or 0)
            out.update(_whatsapp_type_profile(conn))
        if "props" in _table_names(conn):
            out["props"] = {
                str(r[0]): r[1] for r in conn.execute("select key, value from props")
            }
        if "message_media" in _table_names(conn):
            out["media"] = [
                {"file_path": r[0], "mime_type": r[1], "bytes": r[2], "uploaded": r[3]}
                for r in conn.execute(
                    "select file_path, mime_type, file_size, transferred"
                    " from message_media order by message_row_id limit ?",
                    (media_limit,),
                )
            ]
            out["media_mime_kinds"] = _kinds([item["mime_type"] for item in out["media"]])
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    finally:
        conn.close()
    out["verdict"] = (
        f"{out.get('messages_total', 0)} wiadomości, {out.get('with_text', 0)} z tekstem"
        if out.get("messages_total")
        else "brak wiadomości"
    )
    return out


def whatsapp_axolotl(path: str) -> dict[str, Any]:
    """``axolotl.db`` — Signal state: sessions, identities, sender keys."""
    out: dict[str, Any] = {"file": path, "counts": {}}
    conn = _open(path)
    try:
        out["integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        names = _table_names(conn)
        for table in (
            "sessions",
            "identities",
            "sender_keys",
            "prekeys",
            "signed_prekeys",
            "prekey_uploads",
            "message_base_key",
        ):
            out["counts"][table] = _count(conn, table)
        if "identities" in names:
            columns = {row[1] for row in conn.execute("pragma table_info('identities')")}
            out["identity_columns"] = sorted(columns)
            if "trusted" in columns:
                out["trusted_identities"] = int(
                    conn.execute("select count(*) from identities where trusted = 1").fetchone()[0]
                )
            else:
                out["verdict_note"] = (
                    "brak kolumny `trusted` w tej wersji schematu — zaufanie do tożsamości "
                    "nie jest zapisywane"
                )
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    finally:
        conn.close()
    out["verdict"] = (
        "brak message_base_key — pary sesji nie są zapisane, treść zaszyfrowana"
        if out["counts"].get("message_base_key", -1) == 0
        else "stan sesji Signal zapisany"
    )
    return out


def whatsapp_contacts(path: str, limit: int = 50) -> dict[str, Any]:
    """``wa.db`` — contact names and the count of chats."""
    out: dict[str, Any] = {"file": path}
    conn = _open(path)
    try:
        out["integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        out["contacts"] = _count(conn, "wa_contacts")
        out["named_contacts"] = int(
            conn.execute(
                "select count(*) from wa_contacts where display_name is not null and display_name != ''"
            ).fetchone()[0]
        )
        out["sample"] = [
            {"jid": r[0], "name": r[1], "number": r[2]}
            for r in conn.execute(
                "select jid, display_name, number from wa_contacts"
                " where display_name is not null and display_name != '' limit ?",
                (limit,),
            )
        ]
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    finally:
        conn.close()
    return out


def play_localappstate(path: str, package: str = "") -> dict[str, Any]:
    """Play Store ``localappstate.db`` — what was installed, when and by whom."""
    out: dict[str, Any] = {"file": path, "apps": [], "package": package}
    conn = _open(path)
    try:
        out["integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        names = _table_names(conn)
        out["rows"] = _count(conn, "appstate")
        if "appstate" in names:
            out["apps"] = _appstate_rows(conn, package)
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    finally:
        conn.close()
    out["by_year"] = _downloads_by_year(out["apps"])
    out["accounts"] = sorted({app["account"] for app in out["apps"] if app["account"]})
    if package:
        found = [app for app in out["apps"] if app["package_name"] == package]
        out["found"] = found
    return out


def _appstate_rows(conn: sqlite3.Connection, package: str = "") -> list[dict[str, Any]]:
    columns = {row[1] for row in conn.execute("pragma table_info('appstate')")}

    def col(name: str, fallback: str = "null") -> str:
        return name if name in columns else fallback

    query = (
        "select package_name, title, first_download_ms, last_update_timestamp_ms,"
        " delivery_data_timestamp_ms, last_notified_version, desired_version, account,"
        " referrer, installer_state, install_request_timestamp_ms,"
        " external_referrer_timestamp_ms, delivery_token"
        f", {col('first_download_ms', '0')} as first_ms"
        " from appstate"
    )
    args: tuple = ()
    if package:
        query += " where package_name = ?"
        args = (package,)
    out: list[dict[str, Any]] = []
    for row in conn.execute(query, args):
        out.append(
            {
                "package_name": row[0],
                "title": row[1],
                "first_download_ms": row[2],
                "first_download_utc": utc_from_ms(row[2]),
                "last_update_ms": row[3],
                "last_update_utc": utc_from_ms(row[3]),
                "delivery_data_ms": row[4],
                "delivery_data_utc": utc_from_ms(row[4]),
                "last_notified_version": row[5],
                "desired_version": row[6],
                "account": row[7],
                "referrer": (row[8] or "")[:200],
                "installer_state": row[9],
                "install_request_ms": row[10],
                "install_request_utc": utc_from_ms(row[10]),
                "external_referrer_utc": utc_from_ms(row[11]),
                "delivery_token": bool(row[12]),
            }
        )
    return out


def _downloads_by_year(apps: list[dict[str, Any]]) -> dict[str, int]:
    out: dict[str, int] = {}
    for app in apps:
        stamp = app.get("first_download_utc") or ""
        if len(stamp) >= 4:
            out[stamp[:4]] = out.get(stamp[:4], 0) + 1
    return dict(sorted(out.items()))


def wpa_supplicant(blob: bytes) -> dict[str, Any]:
    """Parse ``wpa_supplicant.conf`` into its ``network={...}`` blocks.

    The file is an INI-like format with nested blocks; PSK values sit in the file
    in the clear on this device, so they are returned as plain strings and the
    caller decides to wrap them as secrets.
    """
    out: dict[str, Any] = {"networks": [], "globals": {}}
    block: dict[str, str] | None = None
    for raw in blob.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("network=") or line == "network={":
            block = {}
            continue
        if line == "}":
            if block:
                out["networks"].append(block)
            block = None
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if block is None:
            out["globals"][key] = value
            continue
        block[key] = value.strip('"')
    out["ssids"] = sorted({item["ssid"] for item in out["networks"] if item.get("ssid")})
    out["with_psk"] = [item for item in out["networks"] if item.get("psk")]
    out["verdict"] = (
        f"{len(out['networks'])} sieci, {len(out['with_psk'])} z hasłem w pliku"
    )
    return out


def wifi_settings(path: str) -> dict[str, Any]:
    """``com.android.settings/databases/wifi_settings.db`` — saved networks.

    Android 7 keeps the pre-shared keys in this database without encrypting
    them; the ``psk`` column even keeps the surrounding quotes of the file
    format, which is reported rather than stripped away silently.
    """
    out: dict[str, Any] = {"file": path, "networks": [], "sync": []}
    conn = _open(path)
    try:
        out["integrity"] = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        names = _table_names(conn)
        if "wifi" in names:
            columns = {row[1] for row in conn.execute("pragma table_info('wifi')")}
            wanted = [
                name
                for name in ("_id", "ssid", "bssid", "psk", "keyMgmt", "priority", "account", "marker", "deleted")
                if name in columns
            ]
            query = "select " + ", ".join(f'"{name}"' for name in wanted) + ' from "wifi" order by _id'
            for row in conn.execute(query):
                item = dict(zip(wanted, row))
                item["ssid"] = (item.get("ssid") or "").strip('"')
                item["psk"] = (item.get("psk") or "").strip('"')
                out["networks"].append(item)
        if "wifi_sync" in names:
            columns = {row[1] for row in conn.execute("pragma table_info('wifi_sync')")}
            wanted = [name for name in ("account_name", "marker", "sync_extra_info") if name in columns]
            query = "select " + ", ".join(f'"{name}"' for name in wanted) + ' from "wifi_sync"'
            for row in conn.execute(query):
                item = dict(zip(wanted, row))
                blob = item.get("sync_extra_info") or ""
                item["sync_extra_info_bytes"] = len(blob)
                decoded = _protobuf_strings(blob) if blob else []
                item["sync_extra_info_strings"] = decoded
                item["sync_extra_info_decodable"] = bool(decoded)
                out["sync"].append(item)
    except sqlite3.Error as exc:
        out["error"] = str(exc)
    finally:
        conn.close()
    out["count"] = len(out["networks"])
    out["ssids"] = sorted({item["ssid"] for item in out["networks"] if item.get("ssid")})
    out["with_psk"] = [item for item in out["networks"] if item.get("psk")]
    out["distinct_psk"] = sorted({item["psk"] for item in out["with_psk"]})
    out["accounts"] = sorted({item["account"] for item in out["networks"] if item.get("account")})
    out["verdict"] = (
        f"{out['count']} zapisanych sieci, {len(out['with_psk'])} z kluczem WPA w bazie"
    )
    return out


def _protobuf_strings(blob: bytes | str, depth: int = 0) -> list[str]:
    """Strings inside a protobuf message, without knowing its schema.

    Android stores a fair number of opaque blobs as protobuf, so the only honest
    reading is a structural walk: length-delimited fields that decode as text are
    strings, and the ones that do not are treated as nested messages and walked
    again.
    """
    from .sqlite_tools import varint

    if isinstance(blob, str):
        import base64

        try:
            blob = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except Exception:
            return []
    out: list[str] = []
    index = 0
    while index < len(blob):
        try:
            key, index = varint(blob, index)
        except IndexError:
            break
        wire = key & 7
        if wire == 0:
            try:
                _value, index = varint(blob, index)
            except IndexError:
                break
            continue
        if wire == 2:
            try:
                length, index = varint(blob, index)
            except IndexError:
                break
            chunk = blob[index : index + length]
            index += length
            try:
                text = chunk.decode("utf-8")
            except UnicodeDecodeError:
                text = ""
            if text.isprintable() and text.strip():
                out.append(text.strip())
            elif depth < 4 and length:
                out.extend(_protobuf_strings(chunk, depth + 1))
            continue
        if wire == 5:
            index += 4
            continue
        if wire == 1:
            index += 8
            continue
        break
    return out


def network_stats(blob: bytes, name: str = "") -> dict[str, Any]:
    """Android network-statistics log (``ANET``) — the traffic counters.

    The container has no schema in this project: ``ConnectivityService`` writes
    it and the field layout is a framework internal.  So only what can be read
    without guessing is reported — the magic, the version word, the network
    interface names it mentions, and the state word, which is handed back as a
    number rather than a name.  The file name carries the millisecond stamp of
    the record set, which is more reliable than any field inside.
    """
    out: dict[str, Any] = {
        "file": name,
        "size": len(blob),
        "magic": blob[:4].decode("ascii", "replace"),
        "is_anet": blob[:4] == b"ANET",
        "ifaces": [],
        "state": None,
        "stamp_ms": None,
    }
    if not out["is_anet"]:
        out["verdict"] = "nie jest plikiem ANET"
        return out
    out["version"] = int.from_bytes(blob[4:8], "big")
    for match in re.finditer(rb"\x0a\"([\x20-\x7e]{1,32})\"", blob):
        iface = match.group(1).decode("ascii")
        if iface not in out["ifaces"]:
            out["ifaces"].append(iface)
        if out["state"] is None:
            out["state"] = int.from_bytes(blob[match.end() : match.end() + 4], "little")
    stem = name.rsplit(".", 1)[-1].rstrip("-")
    if stem.isdigit():
        out["stamp_ms"] = int(stem)
        out["stamp_utc"] = epoch_auto(int(stem))["utc"]
    out["kind"] = name.split(".")[0] if "." in name else "?"
    out["verdict"] = (
        f"licznik sieciowy zapisany {out.get('stamp_utc', '?')}; interfejs: "
        f"{', '.join(repr(item) for item in out['ifaces']) or 'brak w pliku'}; "
        f"state={out['state']}"
    )
    return out


def package_usage(blob: bytes) -> list[dict[str, Any]]:
    """``/system/package-usage.list`` — last use per package."""
    out: list[dict[str, Any]] = []
    for line in blob.decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            millis = int(parts[1])
        except ValueError:
            continue
        out.append({"package": parts[0], "last_used_ms": millis, "last_used_utc": utc_from_ms(millis)})
    out.sort(key=lambda item: item["last_used_ms"], reverse=True)
    return out


def miui_backup_records(blob: bytes, package: str = "") -> dict[str, Any]:
    """MIUI cloud backup ``backup_record.xml``."""
    out: dict[str, Any] = {"packages": [], "package": package}
    try:
        root = safe_fromstring(blob.decode("utf-8", "replace"))
    except ET.ParseError as exc:
        out["error"] = str(exc)
        return out
    for node in root.findall("package"):
        name = node.get("name") or ""
        if package and name != package:
            continue
        record = {"package": name}
        for child in node:
            record[child.tag] = (child.text or "").strip()
        out["packages"].append(record)
    if package:
        out["found"] = out["packages"][0] if out["packages"] else None
    out["count"] = len(out["packages"])
    return out


def miui_gallery_history(blob: bytes, package: str = "") -> dict[str, Any]:
    """MIUI gallery ``components-history.json`` — last opened component per app."""
    out: dict[str, Any] = {"entries": [], "package": package}
    try:
        entries = json.loads(blob.decode("utf-8", "replace"))
    except ValueError as exc:
        out["error"] = str(exc)
        return out
    if not isinstance(entries, list):
        out["error"] = "nieoczekiwany kształt JSON"
        return out
    for item in entries:
        if not isinstance(item, dict):
            continue
        if package and item.get("package") != package:
            continue
        out["entries"].append(
            {
                "package": item.get("package", ""),
                "component": item.get("component", ""),
                "recent_ms": item.get("recent"),
                "recent_utc": utc_from_ms(item.get("recent")),
                "history": item.get("history", {}),
                "launches": sum(item.get("history", {}).values()) if isinstance(item.get("history"), dict) else 0,
            }
        )
    out["count"] = len(out["entries"])
    return out


def media_inventory(paths: Iterable[str]) -> dict[str, int]:
    """Count file extensions — used for app media folders inside the image."""
    counts: dict[str, int] = {}
    for path in paths:
        name = str(path).rsplit("/", 1)[-1]
        if "." not in name:
            counts["(bez rozszerzenia)"] = counts.get("(bez rozszerzenia)", 0) + 1
            continue
        ext = "." + name.rsplit(".", 1)[-1].lower()
        counts[ext] = counts.get(ext, 0) + 1
    return dict(sorted(counts.items(), key=lambda item: -item[1]))


def mib_names(blob: bytes) -> list[str]:
    """Database names visible as literals in a binary blob (misplaced files)."""
    return sorted({match.group().decode("ascii") for match in MIB_RE.finditer(blob)})


def _kinds(values: Iterable[str | None]) -> dict[str, int]:
    out: dict[str, int] = {}
    for value in values:
        top = (value or "").split("/", 1)[0]
        out[top or "?"] = out.get(top or "?", 0) + 1
    return dict(sorted(out.items(), key=lambda item: -item[1]))
