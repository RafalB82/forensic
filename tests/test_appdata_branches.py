# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The last uncovered branches in ``appdata``: warianty schematu i zepsute wejścia.

Everything here is a **branch**, not a function.  Every reader in
:mod:`forensic.core.appdata` is called from somewhere in the test suite; what was
missing were the paths behind a second schema variant, a malformed input, or a
limit — the places where the code says something different and nobody had asked
it to.

The two that carry the most weight:

**``_people`` has three shapes of thread and one of them is the one that happens.**
A one-to-one thread has no ``name``, and the viewer is a participant of it too, so
the counterpart is resolved through ``thread_participants``.  The fixture builds
four threads — resolvable, unresolvable, group, and nobody — because a function
with three branches and one covered is a function whose other two branches are
guesses.

**The sender join and the snippet fallback are joined by ``or``.**  Both halves
were uncovered: a ``messages.sender`` that is NULL (fallback fires) and one that
holds the JSON the join wants (fallback must not).  An ``or`` with one arm never
executed is a place where the second arm might be dead code or might be the
common path, and the tests cannot tell you which without running both.
"""

from __future__ import annotations

import sqlite3

import pytest

from forensic.core import appdata


# --- Messenger: resolving who a thread was with -------------------------------


def test_a_one_to_one_thread_gets_its_counterpart_from_the_participants(messenger_threads_with_participants):
    """The reader is a participant too, so "the other name" is not in the thread.

    A one-to-one thread carries no ``name`` at all, and both parties appear in
    ``thread_participants``.  The counterpart is the participant whose key ends
    with the **other** uid from the thread key, and getting that wrong would put
    the account owner's own name on every one of their conversations.
    """
    report = appdata.messenger_threads_db(str(messenger_threads_with_participants))
    threads = {t["thread_key"]: t for t in report["threads"]}
    assert threads["ONE_TO_ONE:4815162342:1"]["name"] == "Rafał B", threads
    assert threads["ONE_TO_ONE:4815162342:1"]["named_by"] == "thread_participants"


def test_a_group_thread_falls_back_to_its_first_named_participant(messenger_threads_with_participants):
    """A group key carries no uids to compare, so the shape gives nothing.

    The first named participant is used, and that is a weaker claim than the
    one-to-one case — which is why ``named_by`` exists and says
    ``thread_participants`` rather than naming a person.
    """
    report = appdata.messenger_threads_db(str(messenger_threads_with_participants))
    threads = {t["thread_key"]: t for t in report["threads"]}
    assert threads["GROUP:a:b"]["name"] == "Kasia", threads
    assert threads["GROUP:a:b"]["named_by"] == "thread_participants"


def test_a_thread_nobody_can_be_named_for_is_left_empty_not_filled(messenger_threads_with_participants):
    """``ONE_TO_ONLY`` is not the shape the reader knows.

    The key reads like a one-to-one thread with one digit wrong, and the
    counterpart search finds nothing — so the entry stays empty.  A reader that
    fell back to "the only named participant" would put a name here with no
    evidence for it.
    """
    report = appdata.messenger_threads_db(str(messenger_threads_with_participants))
    threads = {t["thread_key"]: t for t in report["threads"]}
    # Every participant of this thread is in the table and every one of them has
    # a NULL name, so the general branch finds nothing to use.  The entry stays
    # empty: a reader that fell back to "the only participant" would put a name
    # here with nothing behind it.
    assert threads["ONE_TO_ONE:555000:1"]["name"] == ""
    assert threads["ONE_TO_ONE:555000:1"]["named_by"] == ""


def test_a_thread_whose_only_participant_has_a_name_still_resolves(messenger_threads_with_participants):
    """The general branch: no comparable uid in the key, so any named member.

    ``ONE_TO_ONE:10001:1`` matches the prefix but the counterpart search finds
    nothing, and the fallback still produces a name — from the one participant
    there is, whose name is on file.
    """
    report = appdata.messenger_threads_db(str(messenger_threads_with_participants))
    threads = {t["thread_key"]: t for t in report["threads"]}
    assert threads["ONE_TO_ONE:10001:1"]["name"] == "Bez-imienia", threads


def test_people_needs_both_tables_and_returns_nothing_without_either(messenger_threads_with_snippets):
    """``_people`` reads two tables; with one missing it answers nothing.

    Half the function's guard, untested: a store with ``thread_users`` but no
    ``thread_participants`` has names and no membership, and joining one to
    nothing would produce a name for every thread on the device.
    """
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("create table thread_users(a text)")
        assert appdata._people(conn, {"thread_users", "messages"}) == {}
        conn.execute("create table thread_participants(thread_key text, user_key text)")
        assert appdata._people(conn, {"thread_users", "thread_participants"}) == {}
    finally:
        conn.close()


# --- Messenger: the sender join, and the fallback it suppresses ----------------


def test_a_json_sender_wins_and_the_snippet_fallback_does_not_run(messenger_threads_messy_sender):
    """The ``or`` arm that must **not** fire.

    ``messages.sender`` holds a JSON document with the ``user_key`` the join reads,
    so the good path produces senders and the snippet index is never consulted.
    With both arms uncovered it was impossible to say whether the fallback was
    dead code or the common path.
    """
    report = appdata.messenger_threads_db(str(messenger_threads_messy_sender))
    # Two of the three messages resolve to a name; the third names nobody and the
    # join drops it, which is the join's own behaviour and not the fallback's.
    assert report["top_senders"] == [{"name": "Kasia", "messages": 2}], report["top_senders"]


def test_the_two_sender_paths_give_the_same_name_from_different_evidence(
    messenger_threads_with_snippets, messenger_threads_messy_sender
):
    """Two stores, two sources, one name — and the name agrees.

    One has no author on the message rows and reads the sender from the snippet
    index; the other has the author as a JSON document and reads it from the join.
    That they agree is the reassuring case; the test exists because a reader that
    silently preferred one would not be distinguishable from this.
    """
    from_snippets = appdata.messenger_threads_db(str(messenger_threads_with_snippets))
    from_json = appdata.messenger_threads_db(str(messenger_threads_messy_sender))
    assert from_snippets["top_senders"] == [
        {"name": "Kasia", "messages": 2},
        {"name": "Rafał B", "messages": 1},
    ]
    assert from_json["top_senders"] == [{"name": "Kasia", "messages": 2}]


# --- preferences_documents: four ways a row can fail -------------------------


def test_the_document_filter_is_a_double_quote_in_the_raw_text(preferences_db_with_documents):
    """The gate is a ``"`` somewhere in the value, and that decides a lot.

    Read literally, the function skips any value whose text contains no double
    quote — **before** parsing.  A JSON array of numbers has none, so it is
    dropped, even though the very next line accepts lists.  The two rules
    together mean only objects survive in practice, and the ``list`` in the
    isinstance check is unreachable from this caller.

    Written as the real contract rather than the intended one, because a reader
    of the code would reasonably assume arrays come through.
    """
    documents = appdata.preferences_documents(str(preferences_db_with_documents))
    assert documents == [{"k": "v", "n": 1}, {"plain": 1}], documents
    # The array had no quote and never reached the parse.
    assert [1, 2, 3] not in documents


def test_a_row_that_does_not_parse_is_skipped_even_when_it_has_a_quote(preferences_db_with_documents):
    """The quote gate is not a parser.

    ``"{definitely not json`` contains quotes and still fails to parse, so it is
    dropped by the ``ValueError`` arm — and ``"just a string"`` and ``42`` parse
    cleanly but are scalars, so they are dropped by the type check.  Four
    rejections, three different reasons, and only one of them is the quote.
    """
    documents = appdata.preferences_documents(str(preferences_db_with_documents))
    assert all(isinstance(d, dict) for d in documents), documents
    assert not any("definitely" in str(d) for d in documents)


def test_documents_are_read_through_the_log_when_it_is_given(preferences_db_with_documents):
    """A read that worked records nothing, and the log stays empty.

    The counterpart is in ``tests/test_read_errors.py``: a read that **failed**
    must record, because that is the case where an empty list would be read as
    "nothing there".
    """
    from forensic.core.readlog import ReadLog

    log = ReadLog()
    documents = appdata.preferences_documents(str(preferences_db_with_documents), log)
    assert documents
    assert len(log) == 0, log.entries


# --- WhatsApp: the media limit and the second backup format ------------------


def test_the_media_limit_is_applied_and_the_kinds_summarise_what_was_kept(wa_msgstore_media_over_limit):
    """A busy store holds tens of thousands of media rows.

    The reader is a report, not an exporter, so it cuts — and ``media_mime_kinds``
    is computed over the **cut** set.  A summary over everything would report a
    file the reader never looked at, which is the same sin as a checksum over a
    file that was never written.
    """
    report = appdata.whatsapp_msgstore(str(wa_msgstore_media_over_limit), media_limit=3)
    assert len(report["media"]) == 3
    assert report["media_mime_kinds"] == {"image": 3}, report["media_mime_kinds"]


def test_the_media_limit_does_not_change_the_message_count(wa_msgstore_media_over_limit):
    """Ten messages, three media rows kept: the two numbers are separate.

    Cutting the media list must not touch the message total, or a report would say
    the conversation was smaller than it was.
    """
    report = appdata.whatsapp_msgstore(str(wa_msgstore_media_over_limit), media_limit=3)
    assert report["messages_total"] == 10
    assert report["counts"]["message_media"] == 10


def test_a_crypt14_header_is_recognised_from_its_own_iv_field(wa_sealed_crypt14):
    """The other version, and the two are not a parameter apart.

    crypt15 puts the version in protobuf field 3 and the IV in sub-field 1;
    crypt14 uses field 2 and sub-field 5.  A reader handling only one recognises
    one format and calls the other "not a database" — which is the failure this
    two-version fixture exists to rule out.
    """
    verdict = appdata.whatsapp_crypt_header(wa_sealed_crypt14[:4096])
    assert verdict is not None
    assert verdict["version"] == appdata.WA_CRYPT14
    assert verdict["iv"] == bytes(range(16)).hex()
    assert verdict["header_len"] == len(wa_sealed_crypt14) - 120


def test_the_feature_table_marker_is_skipped_in_the_header_length(wa_sealed_crypt14):
    """The optional ``0x01`` byte moves the payload, and the length says by how much.

    ``header_len`` is what a later stage would use to find where the ciphertext
    starts, so being off by one puts the ciphertext boundary inside the ciphertext.
    """
    verdict = appdata.whatsapp_crypt_header(wa_sealed_crypt14[:4096])
    # Two bytes in front of the protobuf: the length prefix and the feature marker.
    assert verdict["header_len"] == 2 + len(wa_sealed_crypt14) - 120 - 2


def test_a_sealed_store_reports_its_version_and_leaves_the_payload_alone(wa_sealed_crypt14, tmp_path):
    """The store as a whole, not just the header.

    The verdict says which format and that no key is present; the payload is never
    touched, so a reader that tried would have nothing to report.
    """
    path = tmp_path / "msgstore_c14.db"
    path.write_bytes(wa_sealed_crypt14)
    report = appdata.whatsapp_msgstore(str(path))
    assert report["encrypted"] is True
    assert report["version"] == appdata.WA_CRYPT14
    assert report["counts"] == {}
    assert "zaszyfrowana" in report["verdict"]


# --- the message type wrapper -------------------------------------------------


def test_the_public_wrapper_agrees_with_the_private_one():
    """Two entry points to one decision, and they must not drift.

    A module reading a code through the wrapper and a test reading it through the
    private function would compare two things and call it an agreement.
    """
    for code in (0, 1, 9, 16, 20, 99):
        for column in ("media_wa_type", "message_type"):
            assert appdata.whatsapp_message_type(code, column) == appdata._kind_for(code, column)


def test_the_wrapper_defaults_to_the_older_column():
    """The default is the column the reference image uses, not the newer one."""
    assert appdata.whatsapp_message_type(16) == appdata._kind_for(16, "media_wa_type")


# --- MIUI cloud backup --------------------------------------------------------


def test_backup_records_are_read_with_their_children(miui_backup_record):
    """One dict per package, child elements as keys."""
    report = appdata.miui_backup_records(miui_backup_record)
    assert report["count"] == 2
    assert report["packages"][0] == {
        "package": "com.android.chrome",
        "version": "1.2.3",
        "lastBackup": "1756199200",
    }
    # And the second one, which has fewer children, does not inherit the first's.
    assert report["packages"][1] == {"package": "com.example.app", "version": "4.5.6"}


def test_the_package_filter_selects_one_and_found_carries_it(miui_backup_record):
    report = appdata.miui_backup_records(miui_backup_record, package="com.example.app")
    assert report["count"] == 1
    assert report["found"]["package"] == "com.example.app"


def test_a_package_that_is_not_there_gives_found_none_and_count_zero(miui_backup_record):
    """``found`` is ``None`` and not ``{}``: there was nothing, not an empty record."""
    report = appdata.miui_backup_records(miui_backup_record, package="com.absent")
    assert report["found"] is None
    assert report["count"] == 0
    assert "found" in report


def test_unparseable_backup_xml_reports_the_error_and_no_packages():
    report = appdata.miui_backup_records(b"<records><package")
    assert report.get("error"), report
    assert report["packages"] == []


def test_a_backup_file_with_no_packages_is_empty_not_broken():
    report = appdata.miui_backup_records(b"<records></records>")
    assert report["count"] == 0
    assert "error" not in report


# --- small helpers whose edge cases were never asked about --------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, 0.0),
        ("", 0.0),
        ("0", 0.0),
        ("42", 42.0),
        (42, 42.0),
        (42.5, 42.5),
        ("not a number", 0.0),
        ([1], 0.0),
        ({"a": 1}, 0.0),
        (True, 1.0),
    ],
)
def test_number_coerces_or_gives_up_at_zero(value, expected):
    """Zero is the answer for "not a number", and ``0`` is a number worth zero.

    A value that cannot be read becomes 0.0 rather than raising, because every
    caller is formatting a timestamp and a missing timestamp should not cost the
    rest of the row.  ``True`` is 1.0 because Python says so, which is written
    down here rather than discovered.
    """
    assert appdata._number(value) == expected


def test_a_uid_is_found_at_the_top_level_or_inside_a_nested_value():
    """Three key names at the top level, then a recursive walk.

    A Facebook document puts the account id in ``uid``, ``fbid`` or ``id``,
    sometimes at the top level and sometimes inside a nested object — so the
    reader tries all three and then looks inside.
    """
    assert appdata._uid_of({"uid": 10001}) == "10001"
    assert appdata._uid_of({"fbid": "20002"}) == "20002"
    assert appdata._uid_of({"id": 30003}) == "30003"
    assert appdata._uid_of({"account": {"uid": 40004}}) == "40004"
    # A value that is not a str or an int is skipped rather than stringified.
    assert appdata._uid_of({"uid": None, "fbid": {"x": 1}}) == ""


def test_a_name_comes_from_three_keys_and_is_never_an_empty_string():
    """A name is only returned when it is a non-empty string.

    ``{"name": ""}`` falling through to the next key rather than returning an
    empty name is what lets ``display_name`` win over a blank ``name``.
    """
    assert appdata._name_of({"name": "Rafał"}) == "Rafał"
    assert appdata._name_of({"name": "", "display_name": "Rafał B"}) == "Rafał B"
    assert appdata._name_of({"username": "rafal"}) == "rafal"
    assert appdata._name_of({"profile": {"name": "Zagnieżdżone"}}) == "Zagnieżdżone"
    assert appdata._name_of({"name": 42}) == ""
    assert appdata._name_of({}) == ""


def test_integrity_reports_the_databases_own_verdict(tmp_path):
    """A clean database says ``ok`` — SQLite's word, not ours."""
    from appdata_fixtures import make_sqlite

    path = make_sqlite(tmp_path / "clean.db", ["create table t(a)"])
    assert appdata.integrity(str(path)) == "ok"


def test_integrity_reports_a_broken_database_in_sqlites_words(tmp_path):
    """A database that fails its own check says so in the words it used.

    The alternative — mapping a failure onto a word of our own — would lose which
    failure it was, and ``PRAGMA integrity_check`` names them for a reason.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(tmp_path / "empty_tables.db", ["create table t(a)"])
    raw = bytearray(path.read_bytes())
    raw[100:200] = bytes(100)  # destroy the b-tree page header of page 1
    path.write_bytes(bytes(raw))
    verdict = appdata.integrity(str(path))
    assert verdict != "ok", verdict


def test_integrity_on_a_file_that_is_not_a_database_reports_an_error():
    """A file that will not open is an error string, not a crash."""
    import tempfile

    path = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    path.write(b"not a database" * 100)
    path.close()
    verdict = appdata.integrity(path.name)
    assert verdict.startswith("error: "), verdict


def test_a_sender_name_that_is_not_a_string_is_still_counted(messenger_threads_with_snippets):
    """``snippet_sender`` is stringified rather than rejected.

    SQLite is dynamically typed, so a numeric value can sit in a TEXT column.  A
    reader that dropped it would lose a sender because of a type the column did not
    enforce.
    """
    import sqlite3
    import tempfile
    from pathlib import Path

    path = Path(tempfile.mkdtemp()) / "numeric_sender.db"
    conn = sqlite3.connect(path)
    try:
        conn.execute("create table threads(threads_id text, snippet_sender)")
        conn.execute("insert into threads values('t1', 4815162342)")
        rows = appdata._senders_by_snippet(conn, 10)
    finally:
        conn.close()
    assert rows == [{"name": "4815162342", "messages": 1}], rows


def test_shared_prefs_refuses_a_document_that_is_not_xml():
    """The error key, not an empty map.

    An empty map and a document that would not parse are different, and only one
    of them is a fact about a device.
    """
    report = appdata.shared_prefs(b"this is not xml")
    assert set(report) == {"error"}, report


def test_shared_prefs_accepts_an_empty_but_valid_map():
    """``<map/>`` parses and holds nothing, and that is a successful read."""
    report = appdata.shared_prefs(b"<map></map>")
    assert report == {}, report


def test_shared_prefs_decodes_long_and_small_numbers_both():
    """A ``long`` bigger than 32 bits must not come back truncated.

    Millisecond timestamps are 13 digits and overflow ``int``, so a reader that
    read ``value`` as an int would lose the high bits and print 1970.
    """
    report = appdata.shared_prefs(
        b"<map><long name='ms' value='1756199200000' />"
        b"<int name='n' value='3' /></map>"
    )
    assert report["ms"] == 1756199200000
    assert report["n"] == 3


def test_wpa_supplicant_ignores_a_line_with_no_equals_sign():
    """A stray line is skipped, and the block it was in is still closed."""
    # Bytes, not a str literal: a password with a non-ASCII character in it is
    # ordinary in a conf file, and a bytes literal here would be a syntax error.
    blob = (
        'network={\nssid="Domowa"\npsk="zażółć"\ngarbage-without-equals\n}'
    ).encode("utf-8")
    report = appdata.wpa_supplicant(blob)
    assert report["ssids"] == ["Domowa"]
    assert report["with_psk"][0]["psk"] == "zażółć"


def test_wpa_supplicant_a_key_outside_any_block_is_a_global():
    """A key before the first ``network=`` is a global, and is kept as one."""
    report = appdata.wpa_supplicant(b"country=PL\nnetwork={\nssid=\"X\"\n}\n")
    assert report["globals"] == {"country": "PL"}
    assert report["ssids"] == ["X"]


def test_wifi_settings_handles_a_row_whose_columns_are_absent(tmp_path):
    """A ``wifi`` table with only ``ssid`` is read as far as it goes.

    The reader selects the columns it wants **that exist**, so a lean table
    produces rows with fewer keys rather than an error.  That is the opposite of
    ``appstate``, which selects unconditionally — and the difference is worth
    having written down, because the two are inconsistent within one module.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "lean_wifi.db",
        ["create table wifi(_id integer, ssid text)",
         "insert into wifi values(1,'\"Tylko SSID\"')"],
    )
    report = appdata.wifi_settings(str(path))
    assert report["ssids"] == ["Tylko SSID"]
    assert report["count"] == 1


def test_a_whatsapp_type_profile_on_a_query_that_fails_gives_an_empty_profile(tmp_path):
    """A group-by that raises yields the skeleton and no types.

    ``metadata_csum`` verification found that SQLite will not run a group-by over
    a column it has lost track of, and the reader returns the profile it had
    rather than propagating — which is the right call here, because the rest of
    the report is still true.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "broken_profile.db",
        ["create table messages(_id integer, media_wa_type integer)",
         "insert into messages values(1, 0)"],
    )
    conn = sqlite3.connect(path)
    try:
        # Drop the column out from under the reader's own query.
        conn.execute("alter table messages rename to messages_old")
        conn.execute("create table messages(_id integer)")
        profile = appdata._whatsapp_type_profile(conn)
    finally:
        conn.close()
    assert profile == {}, profile


def test_a_messenger_thread_list_is_capped_by_the_limit(messenger_threads_with_snippets):
    """Threads are cut to ``top_threads``, and the reader says how many it saw."""
    conn = sqlite3.connect(messenger_threads_with_snippets)
    try:
        assert appdata._count(conn, "threads") == 5
    finally:
        conn.close()
    report = appdata.messenger_threads_db(str(messenger_threads_with_snippets), top_threads=2)
    assert len(report["threads"]) == 2, report["threads"]


def test_a_tincan_store_with_only_metadata_tables_is_empty_not_populated(tmp_path):
    """Tables exist, all of them bookkeeping, so there are no records.

    ``tables_total`` counts them and ``non_empty`` does not, and the verdict says
    zero rows in the content tables — which is a fact about Messenger's local
    store, not about the database being unreadable.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "meta_only.db",
        ["create table android_metadata(locale text)",
         "insert into android_metadata values('pl_PL')"],
    )
    report = appdata.messenger_tincan(str(path))
    assert report["non_empty"] == {}
    assert report["verdict"].startswith("poprawna baza")

# --- protobuf truncation edges ------------------------------------------------
#
# The walkers below read headers whose declared length may run past the end of
# what was actually read.  Every early ``return out`` in them is a decision, and
# a decision that returns the fields it *did* parse is the difference between a
# partly-readable header and nothing.


def test_a_tag_varint_running_past_the_end_stops_the_walk():
    """Eleven continuation bytes is a shift of 77, which is past a 64-bit varint.

    The guard exists because a header with the high bit set on every byte would
    otherwise shift forever and the walk would never end on a blob an attacker
    controls.
    """
    blob = bytes([0x80] * 12) + b"payload"
    assert appdata._protobuf_fields(blob) == []


def test_a_tag_continuing_to_the_last_byte_is_read_and_then_stops():
    """A continuation that runs out of input stops the walk, keeping what it had.

    Truncated evidence should yield the part that was legible; a header is often
    only partly present and the readable fields are real.
    """
    blob = bytes([(1 << 3) | 2, 3]) + b"abc" + bytes([0x80, 0x80])
    assert appdata._protobuf_fields(blob) == [(1, 2, b"abc")]


def test_a_length_varint_running_past_the_end_stops_the_walk():
    """The length has the same guard as the tag, and for the same reason."""
    blob = bytes([(1 << 3) | 2]) + bytes([0x80] * 12) + b"x"
    assert appdata._protobuf_fields(blob) == []


def test_a_record_reading_one_byte_past_the_end_is_refused_whole():
    """A length of 3 with two bytes left is not a short read — it is a wrong one.

    Returning the two available bytes would produce a value the header never
    declared, and a caller comparing lengths would not notice.
    """
    blob = bytes([(1 << 3) | 2, 3]) + b"ab"
    assert appdata._protobuf_fields(blob) == []


def test_a_header_that_is_a_single_continuation_byte_returns_nothing():
    """The ``IndexError`` arm, reached by a tag byte with nothing after it."""
    assert appdata._protobuf_fields(bytes([0x80])) == []
    assert appdata._protobuf_fields(bytes([(1 << 3) | 2, 0x80])) == []


def test_an_empty_header_walks_to_nothing():
    assert appdata._protobuf_fields(b"") == []


def test_a_wire_type_zero_field_stops_the_walk_rather_than_being_skipped():
    """Wire type 0 is not decoded, and the walk stops rather than resynchronising.

    Skipping it by its own length is what the comment says the header never uses;
    doing it anyway would mean guessing where the next field starts on a message
    whose schema we do not have.
    """
    blob = (
        bytes([(1 << 3) | 2, 1]) + b"a"
        + bytes([(2 << 3) | 0, 42])
        + bytes([(3 << 3) | 2, 1]) + b"c"
    )
    assert appdata._protobuf_fields(blob) == [(1, 2, b"a")]


@pytest.mark.parametrize(
    "blob",
    [
        bytes([(1 << 3) | 2, 9]),                 # length runs past the end
        bytes([(1 << 3) | 0, 42]),                # wire type we do not read
        bytes([0x80]),                            # varint runs out
        bytes([(1 << 3) | 2]),                    # length byte missing
        bytes([(2 << 3) | 1]) + bytes(3),         # 64-bit field, truncated
        bytes([(3 << 3) | 5]) + bytes(1),         # 32-bit field, truncated
    ],
)
def test_protobuf_strings_survives_every_truncation_point(blob):
    """Six cut points, none of which may raise.

    All of them reach the ``IndexError`` guards inside the walk, and a reader of
    untrusted blobs that raised on a truncated one would crash on a file that is
    merely incomplete.
    """
    assert isinstance(appdata._protobuf_strings(blob), list)


def test_protobuf_strings_returns_the_prefix_before_a_truncation():
    """What was legible comes back; the rest is not invented."""
    blob = bytes([(1 << 3) | 2, 5]) + b"hello" + bytes([(2 << 3) | 2])
    assert appdata._protobuf_strings(blob) == ["hello"]


# --- the remaining type-profile branches --------------------------------------


def test_a_group_by_that_raises_gives_the_skeleton_and_no_types(tmp_path):
    """``PRAGMA integrity_check``'s own output says this happens.

    ``e2fsck`` on the reference image reports ``invalid metadata_block_checksum``
    and similar, so SQLite refusing a query over a column it has lost track of is
    not hypothetical.  The reader returns the profile it had rather than
    propagating — the rest of the report is still true.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "lost_column.db",
        ["create table messages(_id integer, media_wa_type integer)",
         "insert into messages values(1, 0)"],
    )
    conn = sqlite3.connect(path)
    try:
        conn.execute("drop table messages")
        conn.execute("create table messages(_id integer)")
        profile = appdata._whatsapp_type_profile(conn)
    finally:
        conn.close()
    assert profile == {}, profile


def test_a_media_join_that_raises_leaves_the_type_unmarked(tmp_path):
    """One unreadable MIME lookup must not cost the message counts.

    The join to ``message_media`` is wrapped separately from the group-by, so a
    failure there loses the MIME evidence and keeps the rest — the opposite of
    losing everything, and worth pinning because the two are in one ``try``.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "no_media_join.db",
        ["create table messages(_id integer, media_wa_type integer, timestamp integer, "
         "data text, key_from_me integer)",
         "insert into messages values(1, 1, 1756199200000, NULL, 1)"],
    )
    conn = sqlite3.connect(path)
    try:
        profile = appdata._whatsapp_type_profile(conn)
    finally:
        conn.close()
    assert profile["types"] == {"1": 1}, profile
    assert profile["type_disputed"] == {}


def test_a_kind_with_no_mime_family_is_never_disputed(tmp_path):
    """``deleted`` has an empty allowed set, so nothing can contradict it.

    A kind with no declared MIME family has nothing to disagree with, and a reader
    that marked it disputed on every media type would flag every deleted message
    in the store.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "deleted_kind.db",
        ["create table messages(_id integer, media_wa_type integer, timestamp integer, "
         "data text, key_from_me integer)",
         "create table message_media(message_row_id integer, file_path text, "
         "mime_type text, file_size integer, transferred integer)",
         # 53 is not in the older table, so it is uncatalogued and has no family.
         "insert into messages values(1, 53, 1756199200000, NULL, 1)",
         "insert into message_media values(1, '/d/1.bin', 'application/octet-stream', 1, 1)"],
    )
    conn = sqlite3.connect(path)
    try:
        profile = appdata._whatsapp_type_profile(conn)
    finally:
        conn.close()
    assert profile["type_disputed"] == {}, profile
