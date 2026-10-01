# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Fixtures for the Android application readers.

Everything the readers in :mod:`forensic.core.appdata` are pointed at has to look
like the real thing, because the whole difficulty of that module is that it reads
formats nobody documents forensically: a WhatsApp ``msgstore.db`` whose type
codes moved between Android columns, a Messenger ``threads_db2`` keyed by opaque
strings, a Facebook Lite container whose format is private.

So these builders make **real files** with the schemas the readers query, and the
tests assert on what the readers say about them.  Two rules the fixtures follow:

**Schemas are quoted from the readers, and the readers are checked against them.**
A fixture invented from a guess of what a WhatsApp database looks like would
pass a reader that had the guess wrong.  Where a schema comes from a table in the
module, the comment says so.

**A fixture states its own premise.**  ``test_msgstore_fixture_is_the_schema_the_reader_expects``
fails if the builder and the reader ever disagree about the column names, so a
reader that starts querying a column the fixture does not have is caught by the
test that meant to cover something else.

No images are needed, which is the point: the reference image is 27 GB and is not
something a test suite may require.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

#: ``media_wa_type`` — the older WhatsApp column the reference image uses.  From
#: :data:`forensic.core.appdata.WA_MEDIA_WA_TYPE`, which is the table the reader
#: applies, so a fixture built from the same table cannot catch the table being
#: wrong.  That is deliberate: what is under test is the *reading*, and the table
#: itself is checked by ``ext4_selftest`` and by ``verify`` against the device.
WA_TEXT, WA_IMAGE, WA_AUDIO, WA_VIDEO, WA_DOCUMENT, WA_GIF, WA_STICKER = 0, 1, 2, 3, 9, 13, 20


def make_sqlite(path: Path, statements: list[str]) -> Path:
    """Run DDL and ``INSERT`` statements against a new database at ``path``."""
    conn = sqlite3.connect(path)
    try:
        for statement in statements:
            conn.execute(statement)
        conn.commit()
    finally:
        conn.close()
    return path


@pytest.fixture
def wa_msgstore(tmp_path) -> Path:
    """A WhatsApp ``msgstore.db`` on the older ``media_wa_type`` schema.

    Carries one of everything the type profile reports: text, image, document,
    an **uncatalogued code** (99) which must be counted rather than dropped, and a
    message whose ``media_wa_type`` is ``NULL`` — the "no code" case that
    ``_kind_for`` turns into a label instead of a kind.

    The ``starred`` and ``forwarded`` columns exist because a previous version
    read them with ``get(key, 0)``: when the query failed the key was absent and
    the report printed "0 oznaczonych gwiazdką" on a database it had not read.
    """
    path = tmp_path / "msgstore.db"
    return make_sqlite(
        path,
        [
            """create table messages(
                 _id integer primary key,
                 key_from_me integer,
                 timestamp integer,
                 data text,
                 media_wa_type integer,
                 starred integer,
                 forwarded integer)""",
            """create table message_media(
                 message_row_id integer,
                 file_path text,
                 mime_type text,
                 file_size integer,
                 transferred integer)""",
            "create table jid(_id integer primary key, jid text, display_name text)",
            "create table chat(_id integer primary key, jid_raw_id text, name text)",
            "create table props(key text, value text)",
            "insert into jid values(1,'4815162342@s.whatsapp.net','Rafał')",
            "insert into chat values(1,'1@s.whatsapp.net','Rafał')",
            "insert into props values('last_push','2026-08-26T10:00:00Z')",
            "insert into messages values(1,1,1756199200000,'tekst',0,1,0)",
            "insert into messages values(2,0,1756199260000,NULL,1,0,0)",
            "insert into messages values(3,0,1756199320000,NULL,9,0,1)",
            "insert into messages values(4,0,1756199380000,NULL,99,0,0)",
            "insert into messages values(5,0,1756199440000,NULL,NULL,0,0)",
            "insert into message_media values(2,'/data/media/01.jpg','image/jpeg',10240,1)",
            "insert into message_media values(3,'/data/media/doc.pdf','application/pdf',2048,1)",
        ],
    )


@pytest.fixture
def wa_msgstore_new_types(tmp_path) -> Path:
    """The same content on the newer ``message_type`` column.

    The two columns have their own numbering — 9 is ``call_missed`` in the old
    table and ``document`` in the new one — so reading a ``message_type`` value
    with the ``media_wa_type`` dictionary produces a plausible wrong label.  This
    fixture exists so that mistake cannot come back.
    """
    path = tmp_path / "msgstore_new.db"
    return make_sqlite(
        path,
        [
            """create table messages(
                 _id integer primary key,
                 key_from_me integer,
                 timestamp integer,
                 data text,
                 message_type integer,
                 starred integer,
                 forwarded integer)""",
            "insert into messages values(1,0,1756199200000,'tekst',0,0,0)",
            "insert into messages values(2,0,1756199260000,NULL,9,0,0)",
            "insert into messages values(3,0,1756199320000,NULL,16,0,0)",
        ],
    )


@pytest.fixture
def wa_sealed_msgstore(tmp_path) -> Path:
    """A crypt15 ``msgstore.db``: protobuf header with a 16-byte IV, then opaque bytes.

    Hand-built rather than copied, so the length prefix, the version field and
    the IV are exactly the shape ``whatsapp_crypt_header`` claims to require.  A
    wrong "this is encrypted" is worse than a plain "not a database" — it sends
    the analyst looking for a key they do not have.
    """
    path = tmp_path / "msgstore_sealed.db"
    iv = bytes(range(16))

    def varint(value: int) -> bytes:
        out = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            out.append(byte | (0x80 if value else 0))
            if not value:
                return bytes(out)

    def field(number: int, payload: bytes) -> bytes:
        return varint(number << 3 | 2) + varint(len(payload)) + payload

    inner = field(1, iv)  # field 1 of the crypt15 header is the IV
    body = field(3, inner)  # field 3 selects crypt15
    path.write_bytes(bytes([len(body)]) + body + bytes(range(200)))
    return path


@pytest.fixture
def messenger_prefs(tmp_path) -> Path:
    """Messenger ``prefs_db`` with a ``preferences`` table and JSON documents.

    The document carrying a Facebook access token is what ``fb_tokens`` hunts for,
    so the shape here is the shape that module has to survive: a token in
    ``unseen_count_access_token``, the same token elsewhere as noise, and a JSON
    document that is *not* a token at all.
    """
    token = "EAA" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-x"
    noise = "EAAAAAAQnotarealtokenbutlongenoughtolooklikeone0123456789"
    path = tmp_path / "prefs_db"
    documents = {
        "unseen_count_access_token": json.dumps({"token": token, "uid": 10001}),
        "last_login": json.dumps({"ts": 1756199200, "device": "pixel"}),
        "not_a_token": json.dumps({"note": "unrelated payload"}),
        "truncated": '{"token": "' + token + '"',
    }
    return make_sqlite(
        path,
        [
            "create table preferences(key text, type text, value blob)",
            f"insert into preferences values('unseen_count_access_token','s',{_blob(documents['unseen_count_access_token'])})",
            # The rows `messenger_accounts` and `messenger_prefs_db` actually read:
            # /orca_accounts/saved_* and /unified_account_login/*.  The first
            # version of this fixture had neither, and the two tests that read
            # them passed vacuously on empty results.
            "insert into preferences values('/orca_accounts/saved_10001','s',"
            + _text(json.dumps({"name": "Rafał", "uid": 10001,
                                "last_logout_timestamp": 1756199200,
                                "is_page_account": False})) + ")",
            "insert into preferences values('/orca_accounts/saved_page','s',"
            + _text(json.dumps({"name": "Strona", "is_page_account": True,
                                "unseen_count_access_token": token})) + ")",
            "insert into preferences values('/orca_accounts/saved_broken','s',"
            + _text("not json") + ")",
            "insert into preferences values('/unified_account_login/login_last_success_ts','i','1756199200')",
            "insert into preferences values('/unified_account_login/device_id','s','android-abc123')",
            "insert into preferences values('/auth/auth_machine_id','s','MACHINE-ID-1')",
            f"insert into preferences values('noise_row','s',{_blob(noise)})",
            f"insert into preferences values('last_login','s',{_blob(documents['last_login'])})",
            f"insert into preferences values('not_a_token','s',{_blob(documents['not_a_token'])})",
            f"insert into preferences values('truncated','s',{_blob(documents['truncated'])})",
        ],
    )


@pytest.fixture
def messenger_threads(tmp_path) -> Path:
    """Messenger ``threads_db2``: opaque thread keys, participants, timestamps."""
    path = tmp_path / "threads_db2"
    return make_sqlite(
        path,
        [
            "create table threads(threads_id text primary key, sortkey integer, "
            "timestamp_ms integer, is_pin integer)",
            "create table thread_users(user_key text, thread_key text, name text, "
            "timestamp_ms integer)",
            "insert into threads values('ONE_TO_ONE:4815162342:1',1,1756199200000,1)",
            "insert into threads values('GROUP:abc:def',0,1756199100000,0)",
            "insert into thread_users values('4815162342','ONE_TO_ONE:4815162342:1',"
            "'Rafał B',1756199100000)",
            "insert into thread_users values('4815162342','GROUP:abc:def',NULL,"
            "1756199000000)",
        ],
    )


@pytest.fixture
def broken_sqlite(tmp_path) -> Path:
    """A file that is not a database at all, and one that looks like one.

    Both are in one fixture because the distinction is the whole point: a file
    that fails to open and a file that opens and then fails on a query are two
    different states, and the module that reads it has to be able to tell them.
    """
    path = tmp_path / "broken.db"
    path.write_bytes(b"SQLite format 3\x00" + b"\x00" * 4096)
    return path


@pytest.fixture
def fb_properties_store(tmp_path) -> Path:
    """A Facebook Lite ``PropertiesStore_v02``: opaque container, JSON inside.

    The container format is private and the module says so rather than guessing.
    What survives is the set of complete JSON documents, which is what the token
    hunter reads — so this carries one token, one truncated document that must be
    skipped, and one nested object that must come out whole.
    """
    token = "EAA" + "QrstUvWxYz0123456789abcdefghijklmnop_-q"
    blob = (
        b"\x00\x01FBLT\x00\x00\x00\x00"
        + json.dumps({"unseen_count_access_token": token, "v": 1}).encode()
        + b"\x00\x00padding\x00"
        + b'{"broken": "no closing brace"'
        + b"\x00"
        + json.dumps({"outer": {"inner": [1, 2, 3]}, "s": 'has "quotes" and } brace'}).encode()
        + b"\x00\x00trailer"
    )
    path = tmp_path / "PropertiesStore_v02"
    path.write_bytes(blob)
    return path


@pytest.fixture
def shared_prefs_xml() -> bytes:
    """An Android ``shared_prefs`` map with one of each value type."""
    return (
        b'<?xml version="1.0" encoding="utf-8" standalone="yes" ?>\n'
        b'<map>\n'
        b'  <string name="device_id">abc-123</string>\n'
        b'  <int name="attempts" value="3" />\n'
        b'  <long name="last_seen_ms" value="1756199200000" />\n'
        b'  <boolean name="enabled" value="true" />\n'
        b'  <float name="score" value="0.5" />\n'
        b'  <string name="empty"></string>\n'
        b'</map>\n'
    )


def _blob(text: str) -> str:
    """A SQL literal for a **BLOB** value.

    Real, and load-bearing in one place: ``preferences.value`` is declared BLOB and
    some rows genuinely hold bytes.  But Messenger's JSON rows are TEXT, and a
    reader that requires ``isinstance(value, str)`` cannot parse a blob — the
    first version of this fixture wrote every row as a blob and the account scan
    then produced three nameless accounts instead of two.
    """
    return "x'" + text.encode("utf-8").hex() + "'"


def _text(value: str) -> str:
    """A SQL literal for a TEXT value, where the reader expects a string."""
    return "'" + value.replace("'", "''") + "'"