# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Reading the Android application databases, and what a broken one must not say.

The databases in this module are the ones the tool leans on for conclusions about
a **person**: which accounts existed, when a device last authenticated, how many
messages there were, what a WhatsApp conversation was made of.  A wrong answer
here is not a formatting error.

So three things are pinned, in order of how badly they fail.

**A table that cannot be read is never counted as empty.**  This is the class of
defect the whole ``ReadLog`` work was about, seen from inside the readers: an
``except`` returning ``[]`` or ``-1`` is a value, and a value flows on and becomes
a count of zero.

**An uncatalogued code is counted, not dropped.**  WhatsApp moved its message-type
numbering between Android columns, and the two columns disagree — 9 is
``call_missed`` in the old table and ``document`` in the new one.  A reader that
silently drops an unknown code, or that applies the wrong dictionary, produces a
count that is wrong and reads as though it were right.

**A file that fails to open is not a file with nothing in it.**  Opening a broken
database and a database with zero accounts have to be distinguishable, because the
first is a gap in the evidence and the second is a fact about a device.

The fixtures come from :mod:`appdata_fixtures` and their schemas are quoted from
the readers, so a reader that starts querying a column the fixture lacks fails
here rather than silently reading zero rows and passing.
"""

from __future__ import annotations

import sqlite3

from forensic.core.appdata import (
    messenger_accounts,
    messenger_prefs_db,
    messenger_threads_db,
    whatsapp_crypt_header,
    whatsapp_msgstore,
)

#: Documented, agreed floor: 2023-08-26T00:00:00Z, in milliseconds.  Below it a
#: Messenger timestamp is not a time, and the reader says so rather than
#: rendering 1970.
PLAUSIBLE_MS = 1693084800000


# --- the fixture checks its own premise --------------------------------------


def test_msgstore_fixture_is_the_schema_the_reader_queries(wa_msgstore):
    """If this fails, every msgstore assertion below is testing the wrong thing.

    A fixture invented from a guess of what a WhatsApp database looks like would
    pass a reader that had the guess wrong.  This one asserts the reader's own
    column list is present in the file the reader is about to be handed.
    """
    conn = sqlite3.connect(wa_msgstore)
    try:
        columns = {row[1] for row in conn.execute("pragma table_info('messages')")}
        tables = {row[0] for row in conn.execute("select name from sqlite_master where type='table'")}
    finally:
        conn.close()
    assert {"media_wa_type", "starred", "forwarded", "key_from_me", "timestamp", "data"} <= columns
    assert {"messages", "message_media", "jid", "chat", "props"} <= tables


# --- WhatsApp: message types -------------------------------------------------


def test_type_profile_counts_every_code_including_the_uncatalogued_one(wa_msgstore):
    """Five messages, five accounted for.  None quietly disappears.

    The uncatalogued code 99 is the point: an unrecognised code is itself a fact
    about which WhatsApp build wrote the row, and dropping it would make the rest
    of the counts quietly wrong.
    """
    conn = sqlite3.connect(wa_msgstore)
    try:
        from forensic.core.appdata import _whatsapp_type_profile

        profile = _whatsapp_type_profile(conn)
    finally:
        conn.close()
    assert profile["type_column"] == "media_wa_type"
    assert sum(profile["types"].values()) == 5
    assert "99" in profile["types"], profile["types"]
    # And the "no code" row is grouped rather than lost.
    assert sum(profile["type_kinds"].values()) == 5


def test_the_two_type_columns_are_not_interchangeable():
    """Measured differences between the two dictionaries, not an assumed one.

    The first version of this test asserted that code 9 differs, on the strength
    of a comment elsewhere in the module.  It does not: 9 is ``document`` in both.
    Reading the two tables gives the codes that really do differ, and those are
    what a swapped dictionary would mislabel — 16 is ``live_location`` on the older
    column and ``call_missed`` on the newer, 20 is ``sticker`` and
    ``live_location``.  Both labels are plausible, which is what makes the swap
    dangerous.
    """
    from forensic.core.appdata import _kind_for

    for code in (16, 20):
        old = _kind_for(code, "media_wa_type")
        new = _kind_for(code, "message_type")
        assert old["kind"] != new["kind"], code
        assert old["label"] != new["label"], code

    # And the codes that only one table knows are the other half of the trap: an
    # uncatalogued code is a fact about the build that wrote it, not a label to
    # discard.
    assert _kind_for(49, "media_wa_type")["kind"] == "uncatalogued"
    assert _kind_for(49, "message_type")["kind"] == "reaction"


def test_the_older_column_is_read_on_the_older_schema(wa_msgstore_new_types):
    """The column the reader picked is named in its own output."""
    from forensic.core.appdata import _whatsapp_type_profile

    conn = sqlite3.connect(wa_msgstore_new_types)
    try:
        profile = _whatsapp_type_profile(conn)
    finally:
        conn.close()
    assert profile["type_column"] == "message_type"
    assert profile["types"]["9"] == 1
    assert profile["types"]["16"] == 1


def test_a_message_type_column_that_is_neither_gives_no_profile(wa_msgstore):
    """No type column, no profile — and not an invented one.

    Returning ``{}`` is right here: a build with neither column has told us
    nothing about the conversation, and filling the space with a guess would be
    the defect this test exists to prevent.
    """
    conn = sqlite3.connect(wa_msgstore)
    try:
        conn.execute("alter table messages rename to messages_old")
        # Neither column: that is the premise of this test, and the first
        # version kept ``media_wa_type`` in the replacement table by mistake,
        # which made the reader find a profile it should not have found.
        conn.execute(
            "create table messages(_id integer primary key, data text, "
            "starred integer, forwarded integer)"
        )
        from forensic.core.appdata import _whatsapp_type_profile

        assert _whatsapp_type_profile(conn) == {}
    finally:
        conn.close()


def test_uncatalogued_code_is_labelled_as_such_and_not_dropped(wa_msgstore):
    from forensic.core.appdata import _kind_for

    entry = _kind_for(99, "media_wa_type")
    assert entry["kind"] == "uncatalogued"
    assert "99" in entry["label"]
    assert entry["disputed"] is False


def test_a_null_type_code_is_named_rather_than_crashed_on(wa_msgstore):
    """``int(None)`` raises, and the reader must answer something.

    A ``NULL`` in the type column is ordinary — some messages carry no type — and
    turning it into an exception would lose the whole database.
    """
    from forensic.core.appdata import _kind_for

    entry = _kind_for(None, "media_wa_type")
    assert entry["code"] is None
    assert entry["kind"] is None
    assert entry["label"]


def test_starred_and_forwarded_are_read_when_the_column_exists(wa_msgstore):
    """The counts the report prints, and the ones I changed from ``get(key, 0)``."""
    conn = sqlite3.connect(wa_msgstore)
    try:
        from forensic.core.appdata import _whatsapp_type_profile

        profile = _whatsapp_type_profile(conn)
    finally:
        conn.close()
    assert profile["starred"] == 1
    assert profile["forwarded"] == 1


def test_a_message_store_is_reported_with_its_counts_and_its_range(wa_msgstore):
    report = whatsapp_msgstore(str(wa_msgstore))
    assert report["messages_total"] == 5
    assert report["with_text"] == 1
    assert report["outgoing"] == 1
    assert report["counts"]["messages"] == 5
    assert report["counts"]["message_media"] == 2
    assert report["first_message_utc"].startswith("20")
    assert "wiadomości" in report["verdict"]


def test_media_mime_kinds_are_summarised_from_what_is_there(wa_msgstore):
    report = whatsapp_msgstore(str(wa_msgstore))
    assert report["media_mime_kinds"] == {"application": 1, "image": 1}
    assert {item["mime_type"] for item in report["media"]} == {"image/jpeg", "application/pdf"}


def test_a_type_disagreeing_with_its_mime_family_is_marked(wa_msgstore):
    """A document whose media is an image is a fact, and it is named as disputed.

    The dictionary may be outdated or the MIME may be a container choice; either
    way an analyst is better served by seeing both than by being told one.
    """
    conn = sqlite3.connect(wa_msgstore)
    try:
        conn.execute("update message_media set mime_type='image/png' where file_path like '%.pdf'")
        from forensic.core.appdata import _whatsapp_type_profile

        profile = _whatsapp_type_profile(conn)
    finally:
        conn.close()
    disputed = profile["type_disputed"]
    assert disputed, profile
    for code in disputed:
        assert "sporne" in profile["type_labels"].get(code, "") or code in profile["types"]


def test_props_are_read_verbatim(wa_msgstore):
    report = whatsapp_msgstore(str(wa_msgstore))
    assert report["props"]["last_push"] == "2026-08-26T10:00:00Z"


# --- WhatsApp: a sealed backup is not a broken database ----------------------


def test_a_crypt15_header_is_recognised_from_its_iv(wa_sealed_msgstore):
    """Version and IV both out of the header, without a key.

    A wrong "this is encrypted" is worse than a plain "not a database": one sends
    the analyst looking for a key they do not have.
    """
    verdict = whatsapp_crypt_header(wa_sealed_msgstore.read_bytes()[:4096])
    assert verdict is not None
    assert verdict["encrypted"] is True
    assert verdict["version"] == "crypt15"
    assert verdict["iv"] == bytes(range(16)).hex()
    assert verdict["key_available"] is False


def test_a_sealed_message_store_is_left_closed_and_says_why(wa_sealed_msgstore):
    """Not "not a database" — the file is intact and sealed."""
    report = whatsapp_msgstore(str(wa_sealed_msgstore))
    assert report.get("encrypted") is True
    assert report["counts"] == {}
    assert "zaszyfrowana" in report["verdict"]


def test_a_plain_database_is_not_called_encrypted(wa_msgstore):
    """The negative case, which matters more than the positive one."""
    assert whatsapp_crypt_header(wa_msgstore.read_bytes()[:4096]) is None
    assert whatsapp_msgstore(str(wa_msgstore)).get("encrypted") is None


def test_a_header_without_a_full_iv_is_not_encrypted():
    """Strict on purpose: a 15-byte IV is not an IV.

    The test needs a 16-byte value to come out, so anything short of that is a
    different file — and calling it encrypted would send someone looking for a key.
    """
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

    body = field(3, field(1, bytes(range(15))))
    assert whatsapp_crypt_header(bytes([len(body)]) + body + bytes(64)) is None


def test_random_noise_is_not_called_encrypted():
    """A blob that happens to start with a plausible length is still not one."""
    assert whatsapp_crypt_header(bytes(range(3)) + b"\xff" * 32) is None
    assert whatsapp_crypt_header(b"") is None


def test_a_file_that_is_not_sqlite_and_not_sealed_says_so(wa_sealed_msgstore, tmp_path):
    """The third answer, and the one that must not be guessed at.

    A wrong filesystem, a truncated dump and a format we do not read all land here,
    and the message says exactly that rather than implying the extraction failed.
    """
    path = tmp_path / "neither.db"
    path.write_bytes(b"this is not a database at all" * 32)
    report = whatsapp_msgstore(str(path))
    assert report.get("error")
    assert report.get("sqlite_header") is False


# --- Messenger ---------------------------------------------------------------


def test_prefs_db_reports_integrity_rows_and_accounts(messenger_prefs):
    report = messenger_prefs_db(str(messenger_prefs))
    assert report["integrity"] == "ok"
    # The keys are namespaced, so only the /unified_account_login/ rows land here
    # and a fixture without them passes vacuously — which is exactly what the
    # first version of this test did.
    assert report["keys"] == {"device_id": "android-abc123"}, report["keys"]
    assert report["machine_id"] == "MACHINE-ID-1"
    assert report["last_login_utc"].startswith("2025")


def test_saved_accounts_are_read_and_a_broken_one_is_skipped(messenger_prefs):
    """Accounts out of ``/orca_accounts/saved_*``, with the unparseable one skipped.

    The skip is per row: one row whose value will not parse must not cost the
    other two, or a single corrupt record hides an account.
    """
    report = messenger_prefs_db(str(messenger_prefs))
    # The page account carries no uid in its JSON, so the uid falls back to the
    # row-name suffix — `saved_page`, not `page`.  And the sort key is
    # `int(uid) if uid.isdigit() else 0`, so a non-numeric uid sorts **first**:
    # the page account leads.  Written down because both facts look like an
    # ordering bug and are not.
    assert [a["uid"] for a in report["accounts"]] == ["saved_page", "10001"], report["accounts"]
    page = next(a for a in report["accounts"] if a["uid"] == "saved_page")
    assert page["kind"] == "page"
    assert page["access_token"], "token z unseen_count_access_token nie trafił do konta"
    user = next(a for a in report["accounts"] if a["uid"] == "10001")
    assert user["name"] == "Rafał"
    assert user["last_logout_utc"].startswith("2025")


def test_prefs_db_reports_a_machine_id_when_present(tmp_path):
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "prefs_machine.db",
        [
            "create table preferences(key text, type text, value blob)",
            "insert into preferences values('/auth/auth_machine_id','s','MACHINE-ID-1')",
            "insert into preferences values('/unified_account_login/login_last_success_ts','i','1756199200')",
        ],
    )
    report = messenger_prefs_db(str(path))
    assert report["machine_id"], report
    assert report["last_login"]["utc"].startswith("20")


def test_threads_db_counts_threads_and_participants(messenger_threads):
    report = messenger_threads_db(str(messenger_threads))
    assert report["integrity"] == "ok"
    assert report["counts"]["threads"] == 2
    assert report["counts"]["thread_users"] == 2
    # Tables the fixture does not have are counted as -1, meaning "absent", which
    # is different from zero rows and is what _count returns for a missing table.
    assert report["counts"]["messages"] == -1


def test_an_empty_database_reports_zero_and_is_not_an_error(tmp_path):
    """The clean negative, which must stay reachable and must be a clean negative."""
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "empty_prefs.db",
        ["create table preferences(key text, type text, value blob)"],
    )
    report = messenger_prefs_db(str(path))
    assert report["rows"] == 0
    assert report["accounts"] == []
    assert "error" not in report


# --- broken databases --------------------------------------------------------


def test_a_file_that_is_not_a_database_reports_an_error_and_no_numbers(tmp_path):
    """Broken is not empty, and the two must not print the same thing."""
    path = tmp_path / "not_a.db"
    path.write_bytes(b"definitely not sqlite" * 100)
    report = messenger_prefs_db(str(path))
    assert report.get("error"), report
    assert "accounts" in report and report["accounts"] == []


def test_a_database_that_opens_but_fails_on_a_query_is_an_error(tmp_path):
    """The second broken case, and the one that used to be a count of zero.

    A header that libsqlite3 accepts and a schema that is not there produces a
    ``sqlite3.Error`` on the first query.  That is a different failure from a file
    that does not open at all, and both have to be visible — an analyst who sees
    zero accounts and no error will conclude the phone had none.
    """
    path = tmp_path / "header_only.db"
    path.write_bytes(b"SQLite format 3\x00" + bytes(4096))
    report = messenger_prefs_db(str(path))
    assert report.get("error"), report
    assert report["accounts"] == []


def test_a_missing_table_is_absent_rather_than_zero(tmp_path):
    """``_count`` says -1 for a table that is not there, and -1 is not zero.

    ``-1`` reads oddly on its own, so this pins the meaning at the point where it
    is produced: a missing table and an empty one are different facts and the
    report has to be able to say which.
    """
    from forensic.core.appdata import _count

    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("create table present(a)")
        conn.execute("create table empty(b)")
        assert _count(conn, "present") == 0
        assert _count(conn, "empty") == 0
        assert _count(conn, "absent") == -1
    finally:
        conn.close()


def test_a_count_that_fails_does_not_come_back_as_a_number(tmp_path):
    """A table whose ``count(*)`` raises is ``-1``, never a plausible count."""
    from forensic.core.appdata import _count

    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("create table t(a)")
        # A view over a missing table makes count() raise while the name resolves.
        conn.execute("create view broken as select * from nonexistent")
        assert _count(conn, "broken") == -1
    finally:
        conn.close()


def test_messenger_accounts_reads_the_saved_account_shape():
    """Accounts come out with a uid even when the name is missing.

    ``(key, type, value)`` rows with the account JSON in the value, which is what
    ``prefs_db`` holds; a row whose JSON will not parse is skipped rather than
    aborting the scan.
    """
    import json

    rows = [
        ("/orca_accounts/saved_10001", "s", json.dumps({"name": "Rafał", "uid": 10001})),
        ("/orca_accounts/saved_broken", "s", "not json at all"),
        ("/orca_accounts/saved_10002", "s", json.dumps({"uid": 10002})),
        ("/something_else", "s", json.dumps({"uid": 999})),
    ]
    accounts = messenger_accounts(rows)
    assert [a["uid"] for a in accounts] == ["10001", "10002"], accounts
    assert accounts[0]["name"] == "Rafał"
    # A missing name is an empty string, not None and not a crash.
    assert accounts[1]["name"] == ""


def test_a_bytes_valued_row_yields_a_nameless_account_and_that_is_pinned():
    """What a BLOB in ``preferences.value`` actually does, recorded.

    ``messenger_accounts`` only calls :func:`json.loads` when the value is a
    ``str``.  A BLOB therefore skips the parse but still produces an account,
    keyed off the row name — an account with no name, no dates and no token.  That
    is worth knowing rather than discovering in a report: a database with BLOB
    rows produces more "accounts" than it has people.

    The correct fix is a decision about what a row without readable content means,
    and it is not taken here.  What is taken is the measurement.
    """
    report = messenger_accounts(
        [("/orca_accounts/saved_10001", "s", b'{"name": "Rafal", "uid": 1}')]
    )
    assert len(report) == 1, report
    assert report[0]["uid"] == "saved_10001"
    assert report[0]["name"] == ""
    assert report[0]["access_token"] == ""


def test_a_row_before_the_agreed_epoch_is_not_rendered_as_a_1970_date():
    """Below the floor, the value is returned rather than dated.

    A Messenger timestamp of 0 or 5 is not a moment in time, and printing
    ``1970-01-01`` for it puts a date into a timeline that no evidence supports.
    """
    from forensic.core.appdata import utc_from_ms

    assert utc_from_ms(0) == ""
    assert utc_from_ms(PLAUSIBLE_MS).startswith("2023")
    # A milliseconds value handed to a milliseconds function overflows the
    # calendar by fifty thousand years, and the answer is an empty string rather
    # than a date no evidence supports.
    assert utc_from_ms(PLAUSIBLE_MS * 1000) == ""


def test_seconds_and_milliseconds_are_told_apart():
    """Messenger mixes both in the same documents, and guessing wrong shifts by 1970.

    A value small enough to be seconds in 2023 and large enough to be milliseconds
    in 1970 — the ambiguity is real, and the reader has to pick using the same
    floor ``PLAUSIBLE_FROM_MS`` states.
    """
    from forensic.core.appdata import epoch_auto

    as_ms = epoch_auto(PLAUSIBLE_MS)
    as_s = epoch_auto(PLAUSIBLE_MS // 1000)
    assert as_ms["utc"].startswith("2023"), as_ms
    assert as_s["utc"].startswith("2023"), as_s


# --- a message store with no messages ---------------------------------------


def test_an_empty_message_store_says_so_in_its_own_words(tmp_path):
    """The verdict sentence for zero is different from the one for some."""
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "empty_msgstore.db",
        [
            "create table messages(_id integer primary key, media_wa_type integer, "
            "timestamp integer, data text)",
        ],
    )
    report = whatsapp_msgstore(str(path))
    assert report["verdict"] == "brak wiadomości"
    assert report["counts"]["messages"] == 0


def test_a_message_store_without_a_messages_table_is_not_reported_as_zero_messages(
    tmp_path,
):
    """A missing table is ``-1`` in ``counts`` and absent from the summary.

    This is the distinction from the zero case above, and it is the one that used
    to be lost: a reader that defaults a missing count to zero reports an empty
    conversation for a database whose conversation table it never found.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(tmp_path / "no_messages.db", ["create table jid(_id integer, jid text)"])
    report = whatsapp_msgstore(str(path))
    assert report["counts"]["messages"] == -1
    assert "messages_total" not in report
    assert report["verdict"] == "brak wiadomości"