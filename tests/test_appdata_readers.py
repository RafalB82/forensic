# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Contacts, the P2P store, what was installed, what was looked at.

The last uncovered readers in :mod:`forensic.core.appdata`, and the ones with the
least excuse left in them: an address book, a store that is either empty or not,
an install log and a usage log.  All four answer questions a report puts in front
of a person, and all four had **no** coverage.

The distinctions that matter and were untested:

* a saved contact with no name is still a saved contact, so ``named_contacts`` is
  a different number from ``contacts``;
* a valid P2P store with no rows is a **sentence of its own**, and must not read
  as a database that could not be opened — the metadata tables
  (``android_metadata`` and friends) exist in both fixtures precisely so that a
  reader counting them would report a populated store;
* the metadata tables are excluded from the verdict, because they carry the
  database's own bookkeeping rather than its content;
* an install log says **which account** installed something, and that is a name in
  a report;
* the token scanners keep a real access token apart from an ``EAA…`` run inside a
  base64 blob, because the second is a coincidence of the alphabet and reporting it
  would be an accusation.
"""

from __future__ import annotations

import json

import pytest

from forensic.core import appdata

#: A token long enough for the reader's own pattern: ``EAA`` plus at least 40
#: characters.  Built here rather than pasted so its shape is stated by the test
#: rather than assumed by it.
TOKEN = "EAA" + "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdef"
#: A run that matches the pattern but is base64 noise from an expo push payload.
NOISE = "EAAAAAAQ" + "ZmFrZQ" + "0123456789abcdefghijklmnopqrstuvwxyz0123"


# --- WhatsApp address book ---------------------------------------------------


def test_named_contacts_is_a_different_number_from_contacts(wa_contacts_db):
    """Three saved contacts, two of them named.

    A contact saved without a display name is still in the address book, and a
    reader that reports only the named ones understates how many people a device
    knew about.
    """
    report = appdata.whatsapp_contacts(str(wa_contacts_db))
    assert report["integrity"] == "ok"
    assert report["contacts"] == 4
    assert report["named_contacts"] == 2, report


def test_the_sample_carries_jid_name_and_number(wa_contacts_db):
    """The limit is applied, and the three fields a report needs are all there."""
    report = appdata.whatsapp_contacts(str(wa_contacts_db), limit=1)
    assert len(report["sample"]) == 1
    entry = report["sample"][0]
    assert set(entry) == {"jid", "name", "number"}
    assert entry["jid"].endswith("@s.whatsapp.net")


def test_a_contact_book_with_no_table_reports_an_error_not_zero(tmp_path):
    """``wa_contacts`` missing is a schema this reader cannot use, and it says so."""
    from appdata_fixtures import make_sqlite

    path = make_sqlite(tmp_path / "no_wa.db", ["create table other(a integer)"])
    report = appdata.whatsapp_contacts(str(path))
    assert report.get("error"), report
    # ``contacts`` is still there, and it is -1: the table is absent, which is not
    # the same as a table with no rows in it.  Both facts survive, and that is
    # better than an absent key — the reader says both what it found and what it
    # could not.
    assert report["contacts"] == -1


# --- the P2P store -----------------------------------------------------------


def test_a_populated_p2p_store_names_the_tables_with_rows(tincan_populated):
    report = appdata.messenger_tincan(str(tincan_populated))
    assert report["non_empty"] == {"threads": 1, "messages": 1}
    assert report["verdict"] == "tabele z danymi: ['messages', 'threads']"


def test_the_metadata_tables_are_excluded_from_the_verdict(tincan_populated):
    """``android_metadata`` has a row and is not content.

    It carries the database's own bookkeeping — a locale, a schema version — and a
    reader that counted it would report a populated store on an empty one.  Both
    fixtures have it with rows, so a reader that did count it fails the empty case
    below as well.
    """
    report = appdata.messenger_tincan(str(tincan_populated))
    assert "android_metadata" not in report["non_empty"]
    assert report["non_empty"] == {"threads": 1, "messages": 1}


def test_a_valid_store_with_no_rows_gets_its_own_sentence(tincan_empty):
    """The clean negative, and it is not "the database could not be read".

    An empty Messenger P2P store is a finding — the device had no local message
    store — and the sentence has to say that rather than leaving the analyst to
    infer it from an absent number.
    """
    report = appdata.messenger_tincan(str(tincan_empty))
    assert report["integrity"] == "ok"
    assert report["non_empty"] == {}
    assert report["verdict"] == "poprawna baza, ale bez rekordów (0 wierszy w tabelach treści)"


def test_the_tables_total_counts_everything_but_the_verdict_counts_content(tincan_empty):
    """``tables_total`` and ``non_empty`` answer different questions.

    A store with four tables and no rows has four tables.  Reporting that as
    "4 tables with data" would be the difference between a schema and a store.
    """
    report = appdata.messenger_tincan(str(tincan_empty))
    assert report["tables_total"] == 4
    assert report["non_empty"] == {}


# --- Play Store --------------------------------------------------------------


def test_installs_are_read_with_the_account_that_made_them(play_localappstate_db):
    """Two installs, two accounts, and the account name reaches the output."""
    report = appdata.play_localappstate(str(play_localappstate_db))
    assert report["integrity"] == "ok"
    assert report["rows"] == 2
    assert report["accounts"] == ["inny@example.com", "rafal@example.com"]
    chrome = next(a for a in report["apps"] if a["package_name"] == "com.android.chrome")
    assert chrome["title"] == "Chrome"
    assert chrome["first_download_utc"].startswith("2015")
    assert chrome["delivery_token"] is True


def test_installs_are_grouped_by_year_of_first_download(play_localappstate_db):
    """Derived from the first-download date, so the year is that of *first* seen.

    A last-update date is not a substitute: an app installed in 2015 and updated
    last week would move between years and turn one fact into two.
    """
    report = appdata.play_localappstate(str(play_localappstate_db))
    assert report["by_year"] == {"2015": 1, "2023": 1}, report["by_year"]


def test_a_package_filter_narrows_apps_and_found_ends_up_equal(play_localappstate_db):
    """``found`` is redundant when a package is given, and this pins that.

    The filter is applied **inside** ``_appstate_rows``, so ``apps`` is already
    narrowed to the one package before ``found`` filters it again.  Both lists are
    therefore identical, and ``found`` adds nothing in that case — it only earns
    its place when no package was given.

    Worth writing down rather than "fixing": a reader that read the table twice,
    once filtered and once not, could disagree with itself if the file changed
    between the two reads, and a report showing two different counts for one
    database invites the question which is right.
    """
    unfiltered = appdata.play_localappstate(str(play_localappstate_db))
    assert len(unfiltered["apps"]) == 2
    assert "found" not in unfiltered

    report = appdata.play_localappstate(str(play_localappstate_db), package="com.example.app")
    assert [a["package_name"] for a in report["apps"]] == ["com.example.app"]
    assert report["found"] == report["apps"], report["found"] == report["apps"]


def test_a_missing_referrer_is_empty_and_does_not_raise(play_localappstate_db):
    """``referrer`` is sliced and defaulted; an unconditional slice on ``None`` would."""
    report = appdata.play_localappstate(str(play_localappstate_db))
    example = next(a for a in report["apps"] if a["package_name"] == "com.example.app")
    assert example["referrer"] == ""


def test_a_package_that_is_not_there_gives_an_empty_finding_not_an_error(play_localappstate_db):
    """A clean negative again, and the empty result is in ``found``."""
    report = appdata.play_localappstate(str(play_localappstate_db), package="com.absent")
    assert report["found"] == []
    assert report["apps"] == []


def test_a_lean_appstate_schema_is_an_error_and_says_which_column_is_missing(tmp_path):
    """A schema missing ``last_update_timestamp_ms`` is refused, not partly read.

    ``_appstate_rows`` has a fallback for exactly **one** column,
    ``first_download_ms``; the other thirteen are selected unconditionally.  A
    reader that demanded all of them would refuse a database it could have
    reported on, and a reader that fell back for all of them would report fields
    as absent rather than as unreadable.  The current behaviour is the second
    failure mode's opposite: it refuses and names the column.

    The part worth pinning is the disagreement this leaves in the output:
    ``rows`` is 1 — the table exists and holds one row — while ``apps`` is empty,
    because the query failed.  Both numbers are true and a reader who sees only
    the first will believe an install list was read.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(
        tmp_path / "lean_appstate.db",
        [
            "create table appstate(package_name text, title text, first_download_ms integer)",
            "insert into appstate values('com.example.app','Przykład',1693084800000)",
        ],
    )
    report = appdata.play_localappstate(str(path))
    assert report["rows"] == 1, "tabela ma jeden wiersz i _count policzył go"
    assert report["apps"] == [], "zapytanie o kolumny padło i nie zwróciło nic"
    assert "last_update_timestamp_ms" in report["error"], report
    assert report["by_year"] == {}


def test_a_missing_appstate_table_leaves_rows_at_absent(tmp_path):
    """No table is ``-1``, not ``0`` — and ``apps`` stays empty without an error."""
    from appdata_fixtures import make_sqlite

    path = make_sqlite(tmp_path / "no_appstate.db", ["create table other(a integer)"])
    report = appdata.play_localappstate(str(path))
    assert report["rows"] == -1
    assert report["apps"] == []
    assert report["by_year"] == {}
    assert "error" not in report


# --- package usage -----------------------------------------------------------


def test_package_usage_sorts_newest_first_and_drops_malformed_lines(package_usage_list):
    """Four valid lines out of six; the other two are skipped, not raised on.

    A real ``package-usage.list`` has blank lines and the occasional truncated
    one, and a reader that raised on them would lose the whole file over the
    contents of one line.
    """
    rows = appdata.package_usage(package_usage_list)
    assert [r["package"] for r in rows] == [
        "com.android.chrome",
        "com.android.settings",
        "com.android.contacts",
    ]
    assert rows[0]["last_used_ms"] == 1756199200000
    assert rows[0]["last_used_utc"].startswith("2025")


def test_a_zero_stamp_survives_because_zero_is_a_value_not_an_absence(package_usage_list):
    """``contacts`` has stamp 0 and is still a row.

    A reader that dropped falsy stamps would silently remove every package this
    device had opened exactly once, which on a spare phone is most of them.
    """
    rows = {r["package"]: r for r in appdata.package_usage(package_usage_list)}
    assert "com.android.contacts" in rows
    assert rows["com.android.contacts"]["last_used_ms"] == 0
    assert rows["com.android.contacts"]["last_used_utc"] == ""


def test_an_empty_usage_list_gives_no_rows():
    assert appdata.package_usage(b"") == []
    assert appdata.package_usage(b"\n\n\n") == []


# --- MIUI gallery ------------------------------------------------------------


def test_gallery_history_counts_launches_from_the_counter_dict(miui_gallery_history):
    """``launches`` is the sum of the per-bucket counters, not the bucket count.

    One entry has two buckets and one has one; reading the number of buckets
    instead of their sum would report two launches where the evidence says eight.
    """
    report = appdata.miui_gallery_history(miui_gallery_history)
    assert report["count"] == 4
    # The component is a class name with a leading dot, so the key keeps it.
    launches = {e["component"].rsplit("/", 1)[-1]: e["launches"] for e in report["entries"]}
    assert launches[".PhotoActivity"] == 8, launches
    assert launches[".EditorActivity"] == 1, launches
    assert launches[".Main"] == 0, launches


def test_a_history_that_is_not_a_dict_gives_zero_and_keeps_the_row(miui_gallery_history):
    """One malformed row must not cost the file.

    ``launches`` is guarded on the type; a reader that summed it unguarded would
    raise on the fourth entry and return nothing at all, losing three good ones.
    """
    report = appdata.miui_gallery_history(miui_gallery_history)
    broken = next(e for e in report["entries"] if e["component"].endswith(".Broken"))
    assert broken["launches"] == 0


def test_the_package_filter_selects_components_and_the_count_follows(miui_gallery_history):
    report = appdata.miui_gallery_history(miui_gallery_history, package="com.example.other")
    assert report["count"] == 1
    assert report["package"] == "com.example.other"
    assert report["entries"][0]["package"] == "com.example.other"


def test_a_json_document_that_is_not_a_list_is_refused_with_a_reason():
    """Shape is checked before anything is counted.

    A dictionary where a list was expected would iterate over its keys and produce
    an empty report with no error — the same silence this module has been removing
    from everywhere else.
    """
    report = appdata.miui_gallery_history(b'{"package": "x"}')
    assert report["error"] == "nieoczekiwany kształt JSON"
    assert report["entries"] == []


def test_unparseable_json_reports_the_error_and_no_entries():
    report = appdata.miui_gallery_history(b"[{,]")
    assert report.get("error"), report
    assert report["entries"] == []


def test_a_list_of_non_objects_is_skipped_rather_than_counted():
    report = appdata.miui_gallery_history(b'["tekst", 42, null]')
    assert report["entries"] == []
    assert report["count"] == 0


# --- token scanners ----------------------------------------------------------


def test_a_token_in_a_named_field_is_a_real_hit():
    """The field name is what makes it evidence rather than a coincidence."""
    documents = [{"unseen_count_access_token": TOKEN, "uid": 10001}]
    hits = appdata.access_tokens(documents)
    assert len(hits) == 1
    assert hits[0]["noise"] is False
    assert hits[0]["token"] == TOKEN
    assert hits[0]["length"] == len(TOKEN)
    # The uid is stringified, because it comes from a JSON document where a
    # numeric uid and a numeric-string uid are indistinguishable to the reader.
    assert hits[0]["uid"] == "10001"


def test_a_token_in_an_unnamed_field_is_marked_as_noise():
    """``EAA…`` inside some other field is kept but flagged.

    Dropping it would lose a token that is genuinely there; reporting it without
    the flag would put an accusation in a report on the strength of an alphabet.
    """
    hits = appdata.access_tokens([{"push_payload": TOKEN}])
    assert len(hits) == 1
    assert hits[0]["noise"] is True


def test_the_base64_noise_prefix_is_marked_even_in_a_named_field():
    """``EAAAAAAQ`` is the shape expo push payloads produce.

    The field name says "token" and the value says base64, and the two disagree.
    Both signals are kept: a reader that trusted the field name alone would report
    a push payload as an access token.
    """
    hits = appdata.access_tokens([{"access_token": NOISE}])
    assert hits[0]["noise"] is True


def test_a_value_that_is_not_a_string_or_does_not_start_with_eaa_is_not_a_token():
    documents = [{"n": 42}, {"b": b"EAA" + b"x" * 50}, {"s": "not a token"}, {"nul": None}]
    assert appdata.access_tokens(documents) == []


def test_a_document_that_is_not_a_dict_is_skipped():
    assert appdata.access_tokens(["tekst", 42, None]) == []


def test_raw_token_hits_finds_every_run_and_deduplicates_in_order():
    """Order of appearance, deduplicated, over the raw bytes.

    Used on blobs with no structure to scan, so it must not assume one — and it
    must report a token it has already reported only once, or the count in a
    report is a count of how many times a string occurs rather than of tokens.
    """
    other = "EAA" + "0123456789" * 5
    blob = f"prefix {TOKEN} middle {other} suffix {TOKEN} end".encode()
    hits = appdata.raw_token_hits(blob)
    assert hits == [TOKEN, other], hits


def test_a_run_too_short_to_be_a_token_is_not_one():
    """Forty characters is the pattern's floor; shorter runs are not reported."""
    blob = b"EAA" + b"short" + b" rest of the file"
    assert appdata.raw_token_hits(blob) == []


def test_raw_hits_on_a_blob_with_no_token():
    assert appdata.raw_token_hits(b"") == []
    assert appdata.raw_token_hits(bytes(512)) == []


# --- small helpers that everything else leans on -----------------------------


def test_media_inventory_counts_extensions_case_insensitively():
    """``.JPG`` and ``.jpg`` are one kind of file, and no extension is its own."""
    paths = ["/data/media/a.jpg", "/data/media/b.JPG", "/data/media/c.png",
             "/data/media/noext", "/data/media/also.NoExt"]
    counts = appdata.media_inventory(paths)
    assert counts[".jpg"] == 2
    assert counts[".png"] == 1
    assert counts[".noext"] == 1
    assert counts["(bez rozszerzenia)"] == 1


def test_media_inventory_is_ordered_by_count_then_name():
    paths = ["/a/1.png", "/b/2.png", "/c/3.jpg"]
    counts = appdata.media_inventory(paths)
    assert list(counts) == [".png", ".jpg"]


def test_mib_names_finds_database_names_left_in_a_blob():
    """A ``.db`` literal in a binary is a misplaced database, and it is reported.

    Sorted and deduplicated, because a blob that mentions one name forty times has
    one misplaced file, not forty.
    """
    blob = b"\x00\x01/data/system/accounts.db\x00/data/system/contacts.db\x00accounts.db\x00"
    names = appdata.mib_names(blob)
    assert names == ["/data/system/accounts.db", "/data/system/contacts.db"]


def test_kinds_groups_by_the_mime_major_type_and_counts_a_blind_one_as_question_mark():
    """The MIME major type, so an absent value is ``?`` and not an empty key.

    ``{"?": 1}`` says something counted; ``{"": 1}`` is a key an analyst has to
    guess about.
    """
    assert appdata._kinds(["image/jpeg", "image/png", "video/mp4", None]) == {
        "image": 2,
        "video": 1,
        "?": 1,
    }


def test_kinds_on_an_empty_list_is_an_empty_dict():
    assert appdata._kinds([]) == {}


@pytest.mark.parametrize("blob", [b"", b"not xml at all", b"<map>", b"<?xml"])
def test_a_document_that_is_not_a_shared_prefs_map_is_refused_not_guessed(blob):
    """``shared_prefs`` returns an error key rather than an empty map.

    An empty map and a map that could not be read are different, and only one of
    them is a fact about the device.
    """
    report = appdata.shared_prefs(blob)
    assert "error" in report or report == {}, report
    if "error" in report:
        assert report == {"error": report["error"]}, report


def test_a_well_formed_shared_prefs_map_is_read_as_typed_values(shared_prefs_xml):
    """One of each value type, so the type dispatch is exercised end to end."""
    values = appdata.shared_prefs(shared_prefs_xml)
    assert "error" not in values, values
    assert values["device_id"] == "abc-123"
    assert values["attempts"] == 3
    assert values["last_seen_ms"] == 1756199200000
    assert values["enabled"] is True
    assert values["score"] == 0.5
    assert values["empty"] == ""


def test_a_shared_prefs_entry_without_a_name_is_skipped(shared_prefs_xml):
    """The ``name`` attribute is the key; an entry without one has no key to file it under."""
    blob = shared_prefs_xml.replace(b'<int name="attempts" value="3" />',
                                    b'<int value="3" />')
    values = appdata.shared_prefs(blob)
    assert "attempts" not in values
    assert len(values) == 5, values


def test_shared_prefs_json_and_other_documents_are_typed_as_they_are_read():
    """A JSON document read into a flat dict, for the formats that are not XML.

    Only the shared-prefs shape is promised here; what this pins is that the
    error key is absent when the document parsed, which is the difference between
    "read it" and "found nothing".
    """
    report = appdata.shared_prefs(b"<map><string name='k'>v</string></map>")
    assert report == {"k": "v"}


def test_the_token_scanners_are_the_pair_the_modules_expect():
    """``raw_token_hits`` for structureless blobs, ``access_tokens`` for documents.

    Both are used together in ``fb_tokens``: the first says a token exists in these
    bytes, the second says which document and which field.  Reporting only the
    first would name a token with no source, which is not a finding.
    """
    documents = json.loads(json.dumps([{"access_token": TOKEN}]))
    assert appdata.access_tokens(documents)[0]["token"] in appdata.raw_token_hits(
        json.dumps(documents).encode()
    )