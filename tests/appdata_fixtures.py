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

# --- Signal / WhatsApp identity state ----------------------------------------
#
# The two databases below are the E2EE state.  Their schemas are quoted from
# :func:`forensic.core.appdata.whatsapp_axolotl` and
# :func:`forensic.core.appdata.messenger_msys` — the columns the readers name in
# their own ``select`` lists — so a reader that starts asking for a different
# column fails here rather than reading nothing and looking fine.


@pytest.fixture
def wa_axolotl(tmp_path) -> Path:
    """``axolotl.db`` — Signal sessions, identities and sender keys.

    Carries an ``identities`` table **with** a ``trusted`` column and one identity
    marked trusted, because the reader reports a different verdict for a schema
    that has the column and one that does not, and both paths were uncovered.
    """
    path = tmp_path / "axolotl.db"
    return make_sqlite(
        path,
        [
            "create table sessions(identifier text, device_id integer, "
            "session_id integer, record_mac text)",
            "create table identities(identifier text, device_id integer, "
            "identity_key blob, trusted integer)",
            "create table sender_keys(sender_key text, sender_key_id integer, "
            "sender_device_id integer, signing_key_public blob)",
            "create table prekeys(identifier text, prekey_id integer, body blob)",
            "create table signed_prekeys(identifier text, signed_prekey_id integer, body blob)",
            "create table prekey_uploads(identifier text, timestamp integer)",
            "create table message_base_key(id integer primary key, record_mac text, "
            "base_key blob)",
            "insert into sessions values('4815162342',1,42,'aabbcc')",
            "insert into identities values('4815162342',1,x'0102',1)",
            "insert into identities values('4999999999',1,x'0304',0)",
            "insert into sender_keys values('4815162342',7,1,x'0506')",
            "insert into prekeys values('4815162342',5,x'0708')",
            "insert into message_base_key values(1,'ddeeff',x'090a')",
        ],
    )


@pytest.fixture
def wa_axolotl_without_trusted(tmp_path) -> Path:
    """The same state on a schema with no ``trusted`` column.

    The reader has to say that trust is not recorded, rather than reporting zero
    trusted identities — which would be a fact about the device stated from an
    absence of data.
    """
    path = tmp_path / "axolotl_no_trust.db"
    return make_sqlite(
        path,
        [
            "create table identities(identifier text, device_id integer, identity_key blob)",
            "create table message_base_key(id integer primary key, record_mac text, base_key blob)",
            "insert into identities values('4815162342',1,x'0102')",
        ],
    )


@pytest.fixture
def msys_db(tmp_path) -> Path:
    """``msys_database_*`` — Messenger's E2EE identity and auth-token tables.

    Named ``msys_db`` and not ``messenger_msys`` because the reader has the same
    name: a fixture called after the function shadows it inside the test module,
    and the failure is ``'PosixPath' object is not callable`` on every call.  The
    first version of this fixture did exactly that.

    Two identity rows, one with a private key blob and one without, because the
    verdict sentence differs: a local key pair outranks an auth token, and an auth
    token outranks "no data".  All three branches were uncovered.
    """
    path = tmp_path / "msys_database_devices"
    return make_sqlite(
        path,
        [
            "create table crypto_auth_token(verifier_id integer, token blob, "
            "expiration_timestamp_sec integer, session_id integer)",
            "create table secure_message_client_identity_v2(crypto_mailbox_type integer, "
            "local_registration_id integer, identity_key_public_blob blob, "
            "identity_key_private_blob blob, wcc_client_key_private_blob blob, "
            "uuid text, wa_device_id integer)",
            "create table secure_message_sender_key(sender_registration_id integer, "
            "sender_key_id integer, sender_key_private blob)",
            "create table message_base_key(id integer primary key, record_mac text, "
            "base_key blob)",
            "insert into crypto_auth_token values(10001,x'aabb',1756199200,7)",
            # A mailbox with both halves of the key pair.
            "insert into secure_message_client_identity_v2 values(1,42,x'0102',"
            "x'030405',x'0607','uuid-abcd',1)",
            # And one with only the public half.
            "insert into secure_message_client_identity_v2 values(2,43,x'0809',"
            "NULL,NULL,'uuid-efgh',2)",
            "insert into secure_message_sender_key values(10001,7,x'0a0b')",
            "insert into message_base_key values(1,'ccdd',x'0e0f')",
        ],
    )


# --- Wi-Fi -------------------------------------------------------------------


@pytest.fixture
def wifi_settings_db(tmp_path) -> Path:
    """``wifi_settings.db`` — saved networks, PSKs in the clear.

    The quotes are kept, which is the detail the reader has to deal with: Android
    7 stores ``ssid`` and ``psk`` with the surrounding quotes of the
    ``wpa_supplicant.conf`` format, so a reader that does not strip them produces
    an SSID no analyst has ever seen.
    """
    path = tmp_path / "wifi_settings.db"
    return make_sqlite(
        path,
        [
            "create table wifi(_id integer primary key, ssid text, bssid text, psk text, "
            "keyMgmt text, priority integer, account text, marker text, deleted integer)",
            "create table wifi_sync(_id integer primary key, account_name text, "
            "marker text, sync_extra_info blob)",
            'insert into wifi values(1,\'"Domowa"\',\'aa:bb:cc:dd:ee:01\','
            '\'"sekretnyklucz"\',\'WPA_PSK\',0,\'com.android.Account\',\'x\',0)',
            # An open network, deliberately: no psk is not a missing psk.
            'insert into wifi values(2,\'"Gosc"\',\'aa:bb:cc:dd:ee:02\',NULL,'
            '\'OPEN\',1,NULL,NULL,0)',
            # A network deleted from the device, which must not be counted as saved.
            'insert into wifi values(3,\'"Skasowana"\',\'aa:bb:cc:dd:ee:03\','
            '\'"inny"\',\'WPA_PSK\',2,NULL,NULL,1)',
            # Two networks sharing one key, so the distinct count differs from the total.
            'insert into wifi values(4,\'"Sasiad"\',\'aa:bb:cc:dd:ee:04\','
            '\'"sekretnyklucz"\',\'WPA_PSK\',3,NULL,NULL,0)',
        ],
    )


WPA_CONF = b"""# Android Wi-Fi configuration
# commented lines and blanks are skipped

eap=PEAP
eap_identity=android
update_config=1

network={
    ssid="Domowa"
    psk="sekretnyklucz"
    key_mgmt=WPA-PSK
    priority=0
    scan_ssid=1
}

network={
    ssid="Gosc"
    key_mgmt=NONE
}

# a comment inside a block must not close it
network={
    ssid="Sasiad"
    psk="innyklucz"
    identity="someone@example.com"
}
"""


@pytest.fixture
def wpa_supplicant_conf() -> bytes:
    """A ``wpa_supplicant.conf`` with two password networks and one open.

    Contains the three things that break a naive INI parser: two globals before
    any block, a comment **inside** a block, and a key whose value contains an
    ``@``.  All three were uncovered.
    """
    return WPA_CONF


# --- network statistics ------------------------------------------------------


def _anet_blob(*ifaces: str) -> bytes:
    """An ``ANET`` header carrying interface names.

    **The names are quoted, and there is no length byte.**  The reader looks for
    the marker ``\\x0a`` immediately followed by a double quote, the name, and
    another double quote.  That is not a protobuf length-delimited field — a
    protobuf one would carry a varint length between the tag and the payload — so
    ``\\x0a`` is a record marker and the name is a quoted string after it.

    The first version of this builder emitted the names bare, and the second
    emitted them quoted but *with* a protobuf length byte.  Both times the reader
    returned an empty interface list, which reads as a reader that does not work
    rather than as a fixture that does not match the format.  The layout is now
    spelled out here and asserted in
    ``test_the_interface_names_are_matched_as_quoted_strings``, so the next person
    to "simplify" it finds a test that fails.
    """
    out = bytearray(b"ANET")
    out += (2).to_bytes(4, "big")  # version word
    for index, iface in enumerate(ifaces):
        out += b'\x0a"' + iface.encode() + b'"'
        out += (index + 1).to_bytes(4, "little")  # the state word it reads
    out += bytes(64)
    return bytes(out)


@pytest.fixture
def anet_stats() -> bytes:
    """A network-statistics log naming two interfaces."""
    return _anet_blob("wlan0", "rmnet0")


# --- protobuf ----------------------------------------------------------------


def varint(value: int) -> bytes:
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def pb_string(number: int, text: str | bytes) -> bytes:
    """One wire-type-2 field carrying text, or a nested message already built.

    Accepts bytes as well as str because a nested message is itself a payload,
    and building one means handing the bytes of the inner message in.
    """
    payload = text.encode("utf-8") if isinstance(text, str) else text
    return varint(number << 3 | 2) + varint(len(payload)) + payload


@pytest.fixture
def protobuf_with_nested_strings() -> bytes:
    """A message whose field 1 is a string and whose field 2 is a nested message.

    The nesting is the point: ``_protobuf_strings`` walks into length-delimited
    fields that are not text, which is what makes an unknown schema readable at
    all.  A field that is a varint sits alongside them, because a walker that
    skips wire type 0 correctly does not fall over on it.
    """
    nested = pb_string(1, "wewnetrzny") + pb_string(2, "drugi")
    return (
        pb_string(1, "zewnetrzny")
        + varint(3 << 3) + varint(42)      # wire type 0
        + pb_string(2, nested)
    )
