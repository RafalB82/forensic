# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Who was in the conversation: snippet senders and the device's own identity.

These two are the last readers in :mod:`forensic.core.appdata` that answer a
question about a **person** rather than about a file, and both had no coverage.
A report that names the wrong sender or prints a composed identifier as a read
one is not a formatting problem.

**The snippet path is a fallback, and it fires exactly when the good path cannot.**
:meth:`forensic.core.appdata.messenger_threads_db` prefers a join of
``messages.sender`` — a JSON document — against ``thread_users``.  The fixture has
every table that join needs and the join still returns nothing, because ``sender``
is NULL: the message rows kept their bodies and lost their authors.  That is the
situation the fallback exists for, and it is what the fixture builds.

**A composed identifier is not a read one.**  ``com.whatsapp.files/me`` stores a
country code, an e164 number and a national number — and *not* the Jabber ID.  So
``48515162342@s.whatsapp.net`` is assembled from the digits, and the reader says
which it did with ``jabber_id_derived``.  Both paths are tested, and the difference
between them is the point: one came out of the file and the other came out of a
rule about Polish numbers.
"""

from __future__ import annotations

import pytest

from forensic.core import appdata


# --- sender names out of the snippet index -----------------------------------


def test_snippet_senders_are_counted_when_the_json_join_yields_nothing(messenger_threads_with_snippets):
    """The fallback fires, and it names senders with their counts.

    ``messages.sender`` is NULL throughout, so the JSON join that would have given
    better names produces an empty list and the snippet index is read instead.
    The verdict the reader attaches is about the *text*, not the sender, so the
    sender evidence has to survive on its own in ``top_senders``.
    """
    report = appdata.messenger_threads_db(str(messenger_threads_with_snippets))
    assert report["integrity"] == "ok"
    assert report["top_senders"] == [
        {"name": "Kasia", "messages": 2},
        {"name": "Rafał B", "messages": 1},
    ], report["top_senders"]


def test_a_thread_with_no_snippet_sender_is_excluded_not_counted_as_blank(messenger_threads_with_snippets):
    """NULL and ``''`` are both "we do not know who", and neither becomes a name.

    A sender called ``""`` in a report is a thing an analyst would try to read as
    a person, and a NULL grouped by SQLite would produce exactly that row.
    """
    senders = {s["name"] for s in appdata.messenger_threads_db(
        str(messenger_threads_with_snippets))["top_senders"]}
    assert "" not in senders
    assert None not in senders
    assert senders == {"Kasia", "Rafał B"}


def test_senders_are_ordered_by_message_count(messenger_threads_with_snippets):
    """Most talkative first, which is the order a report is read in."""
    senders = appdata.messenger_threads_db(str(messenger_threads_with_snippets))["top_senders"]
    counts = [s["messages"] for s in senders]
    assert counts == sorted(counts, reverse=True), senders


def test_the_sender_limit_is_applied(messenger_threads_with_snippets):
    """The limit reaches the fallback, not just the join."""
    import sqlite3

    conn = sqlite3.connect(messenger_threads_with_snippets)
    try:
        assert len(appdata._senders_by_snippet(conn, 1)) == 1
    finally:
        conn.close()


def test_a_sender_name_is_truncated_so_one_row_cannot_fill_the_report():
    """A name is sliced to 120 characters.

    A contact name is attacker-controlled in the sense that a device can hold
    any bytes, and one thread with a name a megabyte long would otherwise push
    every other row out of the table.
    """
    import sqlite3

    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("create table threads(threads_id text, snippet_sender text)")
        conn.execute("insert into threads values('t1', ?)", ("N" * 400,))
        rows = appdata._senders_by_snippet(conn, 10)
    finally:
        conn.close()
    assert len(rows[0]["name"]) == 120
    assert rows[0]["name"] == "N" * 120


def test_a_database_without_a_threads_table_has_no_snippet_senders():
    """The fallback needs the index it reads; without it the answer is none."""
    import sqlite3

    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("create table messages(a integer)")
        assert appdata._senders_by_snippet(conn, 10) == []
    finally:
        conn.close()


def test_the_verdict_is_about_the_text_and_does_not_claim_a_sender(messenger_threads_with_snippets):
    """A store whose bodies survived still reads as "no text" if the text is empty.

    The verdict sentence is about recoverability of **content**, and reading a
    sender out of a snippet must not turn it into a claim that messages were
    readable.
    """
    report = appdata.messenger_threads_db(str(messenger_threads_with_snippets))
    assert report["with_text"] == 1
    assert "odzysk możliwy" in report["verdict"], report["verdict"]
    assert report["top_senders"], "wysyłający zgubieni mimo czytelnego tekstu"


def test_a_thread_name_comes_from_the_threads_column_not_from_the_snippets(messenger_threads_with_snippets):
    """``named_by`` says which of the two sources supplied the name.

    One thread carries ``threads.name`` and one does not, so the two sources are
    distinguishable in the output rather than both appearing as "a name".  A
    report that merges them would let an analyst treat a name Messenger stored as
    one this tool resolved.
    """
    threads = {t["thread_key"]: t for t in
               appdata.messenger_threads_db(str(messenger_threads_with_snippets))["threads"]}
    assert threads["t3"]["name"] == "Nazwa wątku"
    assert threads["t3"]["named_by"] == "threads.name"
    assert threads["t1"]["named_by"] == ""
    assert threads["t1"]["messages"] == 2


# --- the device's own identity ------------------------------------------------


def test_a_composed_identifier_is_marked_as_derived(java_me_blob):
    """The number was read; the identifier was composed from it.

    The file does not contain a Jabber ID, so printing one without saying it was
    derived would claim the identifier came out of the evidence when it came out
    of a rule about which country a number starts with.
    """
    report = appdata.whatsapp_identity(java_me_blob)
    assert report["is_java_stream"] is True
    assert report["e164"] == "48515162342"
    assert report["number"] == "481516234"
    assert report["jabber_id"] == "48515162342@s.whatsapp.net"
    assert report["jabber_id_derived"] is True
    assert report["country_code"] == "48"


def test_a_jabber_id_in_the_stream_is_reported_as_read_not_derived(java_me_blob_with_jid):
    """The other path, and the difference between the two is one boolean."""
    report = appdata.whatsapp_identity(java_me_blob_with_jid)
    assert report["jabber_id"] == "48615162342@s.whatsapp.net"
    assert report["jabber_id_derived"] is False
    # The number read out of the JID wins over the one the digit scan would pick,
    # because a JID is a specific claim and a digit run is a guess.
    assert report["e164"] == "48615162342"


def test_the_type_name_and_descriptor_are_recovered(java_me_blob):
    """Which class was written, which is the forensic value in a Java stream.

    A Java object stream is not parsed field by field here, and deliberately so:
    what matters is that it is a ``com.whatsapp.Me`` and not something else.
    """
    report = appdata.whatsapp_identity(java_me_blob)
    assert "com.whatsapp.Me" in report["types"]
    assert any("com/whatsapp" in d for d in report["type_descriptors"]), report


def test_the_digit_scan_is_longest_first_and_excludes_short_runs(java_me_blob):
    """Six to fifteen digits, sorted by length descending.

    The two-digit country code is **not** in ``digit_fields``: the pattern's floor
    is six digits, so ``48`` never appears there, and the country code in the
    output is derived from the e164 prefix instead.  That is why the numbers in
    the fixture are separated by non-digit bytes — ``48`` written next to the
    e164 value would be one run of thirteen and the prefix would be lost.
    """
    report = appdata.whatsapp_identity(java_me_blob)
    assert report["digit_fields"] == ["48515162342", "481516234"]
    assert "48" not in report["digit_fields"]


def test_a_stream_with_no_numbers_composes_nothing(java_blob_without_numbers):
    """Nothing to compose from, and nothing is invented.

    A reader that fell back to a default country code would print an identifier
    for a number it has never seen.
    """
    report = appdata.whatsapp_identity(java_blob_without_numbers)
    assert report["digit_fields"] == []
    assert report["number"] == ""
    assert "jabber_id" not in report
    assert "country_code" not in report


@pytest.mark.parametrize("number", ["447911123456", "15551234567", "4915112345678"])
def test_a_number_outside_poland_yields_no_composed_identifier(number):
    """A limitation, measured and asserted rather than left to be discovered.

    The e164 candidate is selected with a **hardcoded** ``startswith("48")`` — the
    Polish country code, matching the reference device.  On any other country's
    number the selection finds nothing, and with it go ``country_code`` and the
    composed ``jabber_id``: the reader reports the digits and stops.

    That is arguably the right trade.  Deriving a country code from a number is an
    inference about a person's phone number, and doing it silently is worse than
    not doing it.  But the consequence must be written down, because the output
    looks identical to "the file held no numbers": ``e164`` is missing in both
    cases, and a reader of the report cannot tell them apart.

    ``digit_fields`` still carries the number, which is the part that is evidence.
    """
    blob = b"\xac\xed\x00\x05" + number.encode() + b"\x00"
    report = appdata.whatsapp_identity(blob)
    assert report["digit_fields"] == [number], report["digit_fields"]
    assert "e164" not in report, f"{number}: e164 znalezione mimo obcego kodu kraju"
    assert "country_code" not in report, report
    assert "jabber_id" not in report, report


def test_a_blob_that_is_not_a_java_stream_still_reports_what_it_is():
    """The format answer is separate from the contents.

    A reader that required the Java header would refuse to answer on a file whose
    header is missing, when the digits in it are just as readable.
    """
    report = appdata.whatsapp_identity(b"48515162342@s.whatsapp.net i 481516234")
    assert report["is_java_stream"] is False
    assert report["jabber_id"] == "48515162342@s.whatsapp.net"
    assert report["jabber_id_derived"] is False


def test_the_size_and_the_format_verdict_are_carried_through(java_me_blob):
    """``whatsapp_identity`` reports on the container as well as the contents.

    The caller gets a format answer it can print without a second call, and the
    two format sources stay separate — ours and libmagic's — because they are two
    independent implementations and a disagreement between them is a finding.
    """
    report = appdata.whatsapp_identity(java_me_blob)
    assert report["size"] == len(java_me_blob)
    assert report["format_ours"] == "java-serialized"
    # The key is ``format_note``, not ``note``: it is the note from the format
    # verdict, and this output has no note of its own to put it in.
    assert "format_note" in report
    assert report["format_note"]


def test_an_empty_blob_answers_nothing_and_does_not_raise():
    report = appdata.whatsapp_identity(b"")
    assert report["is_java_stream"] is False
    assert report["digit_fields"] == []
    assert report["size"] == 0


@pytest.mark.parametrize(
    "blob,expected_types",
    [
        (b"\xac\xed\x00\x05\x74\x00\x0fcom.whatsapp.Me\x00", ["com.whatsapp.Me"]),
        (b"\xac\xed\x00\x05\x74\x00\x0bjava.lang.L\x00", []),
    ],
)
def test_a_string_that_looks_like_a_class_name_becomes_a_type(blob, expected_types):
    """``java_serialized`` calls a dotted string a type name.

    That is a guess, and the test states it as one: the string has a dot and no
    spaces, which is the rule.  A stream whose literal merely happens to contain a
    dot would be reported as a type, which is why the rule is written down here
    rather than left to be discovered in a report.
    """
    report = appdata.java_serialized(blob)
    assert [t for t in report["types"] if t in expected_types] == expected_types


def test_a_prose_string_is_not_mistaken_for_a_type_name():
    """A space disqualifies it — that is the whole rule."""
    report = appdata.java_serialized(b"\xac\xed\x00\x05not a type name at all here")
    assert report["types"] == []


def test_type_descriptors_are_matched_by_their_shape():
    """``[Lcom/…;`` and ``[B`` are descriptors; ``[something]`` is not.

    Anchored on the bracket and terminated by a semicolon or a primitive code, so
    an ordinary bracketed word in a string does not become a descriptor.
    """
    report = appdata.java_serialized(
        b"\xac\xed\x00\x05[Lcom/whatsapp/Profile;Ljava/lang/String;[B[not a descriptor"
    )
    assert "[Lcom/whatsapp/Profile;" in report["type_descriptors"]
    assert "[B" in report["type_descriptors"]
    assert "[not a descriptor" not in report["type_descriptors"]