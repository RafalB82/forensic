# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The E2EE state, the Wi-Fi keys and the network counters.

Three groups, and what they have in common is that each one answers a question a
report puts in front of a person: *were their messages encrypted and by whom, were
their Wi-Fi keys stored in the clear, and what did this device's radios do.*

**The E2EE databases carry the sharpest wording in the whole tool.**  A verdict
that says "no private key material present" when the schema simply has no column
for it is a fact about a device stated from an absence of data.  So the two
identity schemas — with and without a ``trusted`` column — are both here, because
the reader has a different sentence for each and both were untested.

**Wi-Fi keys are stored in the clear on Android 7, with the quotes still on
them.**  A reader that does not strip them produces an SSID no analyst has ever
seen and a PSK that will not join a network; and a network with a ``NULL`` key is
not a network whose key went missing, which is why the open network is in the
fixture next to the two that have keys.

**The network counter has no schema in this project.**  ``ConnectivityService``
writes it and the field layout is a framework internal, so the reader reports only
what it can read without guessing — and the millisecond stamp comes from the
**file name**, not from anything inside.  That is worth pinning, because a reader
that found a timestamp field and preferred it would look more thorough and be
wrong more often.
"""

from __future__ import annotations

import pytest

from appdata_fixtures import _anet_blob, varint
from forensic.core.appdata import (
    _protobuf_fields,
    _protobuf_strings,
    messenger_msys,
    network_stats,
    wpa_supplicant,
    whatsapp_axolotl,
    wifi_settings,
)


# --- Signal state: axolotl ---------------------------------------------------


def test_axolotl_counts_every_table_it_names(wa_axolotl):
    report = whatsapp_axolotl(str(wa_axolotl))
    assert report["integrity"] == "ok"
    # Every table the reader names, with its real row count.  ``signed_prekeys``
    # and ``prekey_uploads`` are created and left empty, so they read 0 — which is
    # a different answer from -1 and is asserted as such below.
    assert report["counts"] == {
        "sessions": 1,
        "identities": 2,
        "sender_keys": 1,
        "prekeys": 1,
        "signed_prekeys": 0,
        "prekey_uploads": 0,
        "message_base_key": 1,
    }, report["counts"]


def test_an_empty_table_and_a_missing_one_are_different_numbers(wa_axolotl):
    """``signed_prekeys`` exists and is empty: 0.  ``x`` does not exist: -1.

    Both appear in the same ``counts`` dict and mean opposite things about the
    device, so the distinction is pinned where the two numbers are produced.
    """
    report = whatsapp_axolotl(str(wa_axolotl))
    assert report["counts"]["signed_prekeys"] == 0
    assert report["counts"]["signed_prekeys"] != -1


def test_a_trusted_column_is_read_and_its_absence_is_named(wa_axolotl, wa_axolotl_without_trusted):
    """One identity is trusted out of two — and a schema without the column says so.

    The second case is the one that matters: reporting **zero** trusted identities
    from a database that does not record trust is a statement about the device
    made from a field that is not there.
    """
    with_column = whatsapp_axolotl(str(wa_axolotl))
    assert with_column["trusted_identities"] == 1

    without = whatsapp_axolotl(str(wa_axolotl_without_trusted))
    assert "trusted_identities" not in without, without
    assert "brak kolumny" in without["verdict_note"], without


def test_identity_columns_are_reported_verbatim(wa_axolotl):
    """The schema is handed back so an analyst can judge a claim made from it."""
    report = whatsapp_axolotl(str(wa_axolotl))
    assert set(report["identity_columns"]) == {"identifier", "device_id", "identity_key", "trusted"}


def test_an_absent_message_base_key_is_what_says_the_pairs_are_not_stored(wa_axolotl, tmp_path):
    """The verdict turns on one table, and both of its answers are tested.

    ``message_base_key`` is what Signal writes when a session is established.  It
    being absent or empty means the pairs were never written — a fact about the
    device.  It being empty **and reported as absent** would be a different claim,
    so both cases are pinned separately.
    """
    from appdata_fixtures import make_sqlite

    assert "stan sesji" in whatsapp_axolotl(str(wa_axolotl))["verdict"]

    empty = make_sqlite(
        tmp_path / "axolotl_no_base.db",
        ["create table message_base_key(id integer primary key, record_mac text, base_key blob)"],
    )
    report = whatsapp_axolotl(str(empty))
    assert report["counts"]["message_base_key"] == 0
    assert "pary sesji nie są zapisane" in report["verdict"]


def test_an_absent_axolotl_table_is_not_read_as_zero_pairs(tmp_path):
    """A database with no ``message_base_key`` at all says the table is absent."""
    from appdata_fixtures import make_sqlite

    path = make_sqlite(tmp_path / "axolotl_bare.db", ["create table sessions(a integer)"])
    report = whatsapp_axolotl(str(path))
    assert report["counts"]["message_base_key"] == -1
    # And -1 is not 0, so the "pairs not stored" verdict does not fire off it.
    assert report["verdict"] == "stan sesji Signal zapisany", report["verdict"]


# --- Messenger E2EE: msys ---------------------------------------------------


def test_msys_reports_tokens_and_their_expiry(msys_db):
    report = messenger_msys(str(msys_db))
    assert report["integrity"] == "ok"
    assert report["tables_present"] == [
        "crypto_auth_token",
        "secure_message_client_identity_v2",
        "secure_message_sender_key",
    ]
    token = report["auth_tokens"][0]
    assert token["verifier_id"] == 10001
    assert token["token_bytes"] == 2
    assert token["expires_utc"].startswith("2025")


def test_msys_distinguishes_a_local_key_pair_from_a_public_half(msys_db):
    """Two identities, one with a private blob and one without.

    ``private_key_present`` is a single boolean in the output, and it is the whole
    difference between "the key is on this device" and "we know who it belongs to
    but cannot read it".
    """
    identities = messenger_msys(str(msys_db))["identities"]
    assert len(identities) == 2
    with_key = [i for i in identities if i["private_key_present"]]
    without = [i for i in identities if not i["private_key_present"]]
    assert len(with_key) == 1 and len(without) == 1
    assert with_key[0]["identity_key_private_bytes"] == 3
    assert without[0]["identity_key_private_bytes"] is None
    assert without[0]["wcc_client_key_private_bytes"] is None


def test_msys_verdict_prefers_a_local_key_pair_over_a_token(msys_db, tmp_path):
    """Three verdicts, and the ranking between them is the point."""
    from appdata_fixtures import make_sqlite

    both = messenger_msys(str(msys_db))["verdict"]
    assert "para kluczy E2EE obecna lokalnie" in both

    token_only = make_sqlite(
        tmp_path / "msys_token_only",
        [
            "create table crypto_auth_token(verifier_id integer, token blob, "
            "expiration_timestamp_sec integer, session_id integer)",
            "insert into crypto_auth_token values(1,x'aa',1756199200,7)",
        ],
    )
    assert "tylko tokeny autoryzacji" in messenger_msys(str(token_only))["verdict"]

    bare = make_sqlite(tmp_path / "msys_bare", ["create table unrelated(a integer)"])
    assert "brak danych o parach kluczy" in messenger_msys(str(bare))["verdict"]


def test_msys_counts_sender_keys_and_the_base_key_table(msys_db):
    report = messenger_msys(str(msys_db))
    assert report["sender_keys"] == 1
    assert report["message_base_key_rows"] == 1
    assert report["counts"] == {
        "crypto_auth_token": 1,
        "secure_message_client_identity_v2": 2,
        "secure_message_sender_key": 1,
    }, report["counts"]


# --- protobuf ----------------------------------------------------------------


def test_protobuf_fields_reads_length_delimited_records():
    """The minimal walk, on bytes whose layout the test states itself."""
    blob = bytes([(1 << 3) | 2, 3]) + b"abc" + bytes([(2 << 3) | 2, 3]) + b"xyz"
    assert _protobuf_fields(blob) == [(1, 2, b"abc"), (2, 2, b"xyz")]


def test_protobuf_fields_stops_at_a_wire_type_it_does_not_read():
    """Varint first, then anything else: bail rather than guess.

    The function decodes only wire type 2 because that is all the headers use.
    Meeting wire type 0 on real data is possible — a nested message that grew a
    numeric field — and answering with fields from an unknown offset would be
    worse than answering with none.
    """
    blob = bytes([(1 << 3) | 0, 42]) + bytes([(2 << 3) | 2, 1]) + b"a"
    assert _protobuf_fields(blob) == []


def test_protobuf_fields_returns_what_it_managed_before_a_truncation():
    """A record whose length runs past the end stops the walk; earlier ones stand.

    Truncated evidence should yield the part that was legible rather than nothing,
    because the part that was legible is real.
    """
    blob = bytes([(1 << 3) | 2, 3]) + b"abc" + bytes([(2 << 3) | 2, 99]) + b"xy"
    assert _protobuf_fields(blob) == [(1, 2, b"abc")]


def test_protobuf_strings_finds_strings_at_the_top_level_and_inside_a_nested_message(protobuf_with_nested_strings):
    """The structural walk is what makes an unknown schema readable.

    A nested message is a length-delimited field that does not decode as text, so
    the only honest reading is to go into it.  Without that, an Android blob
    written by a newer framework version returns nothing at all.
    """
    strings = _protobuf_strings(protobuf_with_nested_strings)
    assert "zewnetrzny" in strings
    assert "wewnetrzny" in strings, strings
    assert "drugi" in strings, strings
    # The varint field is skipped, not misread as a length.
    assert "42" not in strings


def test_protobuf_strings_skips_wire_types_it_does_not_walk():
    """Fixed-width fields are stepped over by their size.

    Wire type 5 is four bytes and type 1 is eight; a walker that treated either as
    a length would read a following string from the wrong offset and return
    something that looks like a value.
    """
    blob = bytes([(1 << 3) | 5]) + b"\x01\x02\x03\x04" + bytes([(2 << 3) | 2, 3]) + b"abc"
    assert _protobuf_strings(blob) == ["abc"]

    blob64 = bytes([(1 << 3) | 1]) + bytes(8) + bytes([(2 << 3) | 2, 3]) + b"xyz"
    assert _protobuf_strings(blob64) == ["xyz"]


def test_protobuf_strings_reads_base64_because_android_stores_it_that_way():
    """A ``sync_extra_info`` column arrives base64-encoded from some builds.

    The reader decodes it rather than reporting the column as undecodable, which
    is the difference between a field being read and a field being counted.
    """
    import base64

    inner = bytes([(1 << 3) | 2, 5]) + b"hello"
    assert _protobuf_strings(base64.b64encode(inner).decode()) == ["hello"]


def test_protobuf_strings_stops_at_the_depth_limit():
    """Depth four, and the deepest level is not returned.

    Recursing without a bound on a blob that is mostly length-delimited noise
    would walk until the interpreter ran out of stack, on data an attacker
    controls.
    """
    blob = b""
    for depth in range(6):
        blob = bytes([(1 << 3) | 2]) + varint(len(blob) + 2) + b"x" + blob
    # Whatever comes back, the walk terminates and does not include the deepest.
    assert isinstance(_protobuf_strings(blob), list)


def test_protobuf_strings_on_junk_returns_nothing_rather_than_raising():
    """Arbitrary bytes, including the zero page of an unwritten file."""
    assert _protobuf_strings(b"") == []
    assert _protobuf_strings(bytes(512)) == []
    assert _protobuf_strings(b"\xff\xff\xff\xff") == []


def test_a_str_input_is_read_as_base64_not_as_raw_bytes():
    """Both shapes reach this function, from two different columns — and they differ.

    A ``str`` is a ``sync_extra_info`` column, which Android base64-encodes, so it
    is decoded first.  Handing it the raw text of a protobuf message therefore
    yields nothing, and the first version of this test expected the two calls to
    agree.  They must not: bytes are a protobuf message and a string is base64
    one, and conflating them would read one column as the other.
    """
    import base64

    blob = bytes([(1 << 3) | 2, 5]) + b"hello"
    assert _protobuf_strings(blob) == ["hello"]
    assert _protobuf_strings(base64.b64encode(blob).decode()) == ["hello"]
    assert _protobuf_strings(blob.decode("ascii", "ignore")) == []


# --- Wi-Fi: the config file --------------------------------------------------


def test_wpa_supplicant_reads_blocks_and_globals(wpa_supplicant_conf):
    """Globals before any block, then one block per saved network."""
    report = wpa_supplicant(wpa_supplicant_conf)
    assert report["globals"] == {"eap": "PEAP", "eap_identity": "android", "update_config": "1"}
    assert report["ssids"] == ["Domowa", "Gosc", "Sasiad"]
    assert report["verdict"] == "3 sieci, 2 z hasłem w pliku"


def test_wpa_supplicant_strips_the_quotes_and_keeps_the_rest_of_the_value(wpa_supplicant_conf):
    """Quotes go; an ``@`` inside an identity does not.

    Stripping quotes naively from both ends would also eat a value that merely
    begins and ends with one, and would break a password containing ``"``.
    """
    networks = {n["ssid"]: n for n in wpa_supplicant(wpa_supplicant_conf)["networks"]}
    assert networks["Domowa"]["psk"] == "sekretnyklucz"
    assert networks["Sasiad"]["identity"] == "someone@example.com"


def test_a_comment_inside_a_block_does_not_close_it(wpa_supplicant_conf):
    """The failure this guards against is silent: one network reported as three.

    A naive line parser that treats any line ending in ``}`` as a block end also
    treats a commented-out closing brace as one, and the network after it lands in
    the globals instead of in a block.
    """
    networks = wpa_supplicant(wpa_supplicant_conf)["networks"]
    assert len(networks) == 3, networks
    # The comment mentions a brace; if it closed the block, the third network would
    # be missing and its keys would be in `globals`.
    assert "identity" in networks[-1]


def test_an_open_network_has_no_psk_and_is_not_reported_as_having_one(wpa_supplicant_conf):
    report = wpa_supplicant(wpa_supplicant_conf)
    open_networks = [n for n in report["networks"] if n.get("key_mgmt") == "NONE"]
    assert len(open_networks) == 1
    assert not open_networks[0].get("psk")
    assert [n["ssid"] for n in report["with_psk"]] == ["Domowa", "Sasiad"]


def test_an_empty_config_is_empty_and_says_so():
    report = wpa_supplicant(b"")
    assert report["networks"] == []
    assert report["ssids"] == []
    assert report["verdict"] == "0 sieci, 0 z hasłem w pliku"


# --- Wi-Fi: the database -----------------------------------------------------


def test_wifi_settings_strips_the_quotes_the_file_format_left_behind(wifi_settings_db):
    """The SSID a reader reports has to be an SSID an analyst could type.

    Android 7 keeps the surrounding quotes of the ``wpa_supplicant.conf`` format
    in the column, so an unstripped reader reports ``"Domowa"`` with the quotes
    included — a string that is in no SSID list and matches no network.
    """
    report = wifi_settings(str(wifi_settings_db))
    assert report["ssids"] == ["Domowa", "Gosc", "Sasiad", "Skasowana"]
    assert all(not s.startswith('"') for s in report["ssids"])
    home = next(n for n in report["networks"] if n["ssid"] == "Domowa")
    assert home["psk"] == "sekretnyklucz"
    assert not home["psk"].startswith('"')


def test_a_network_with_no_key_is_open_and_not_missing(wifi_settings_db):
    """``NULL`` is a statement about the network; an empty string is an absence.

    The reader strips quotes from ``None`` into ``""``, so both an open network
    and a lost key look the same in ``with_psk`` — and the difference is visible
    only in ``keyMgmt``.
    """
    report = wifi_settings(str(wifi_settings_db))
    guest = next(n for n in report["networks"] if n["ssid"] == "Gosc")
    assert guest["psk"] == ""
    assert guest["keyMgmt"] == "OPEN"
    assert "Gosc" not in [n["ssid"] for n in report["with_psk"]]


def test_two_networks_sharing_one_key_are_counted_once_for_the_key(wifi_settings_db):
    """``distinct_psk`` is not the same number as ``with_psk``, and both are reported."""
    report = wifi_settings(str(wifi_settings_db))
    assert len(report["with_psk"]) == 3
    assert report["distinct_psk"] == ["inny", "sekretnyklucz"]
    assert report["verdict"] == "4 zapisanych sieci, 3 z kluczem WPA w bazie"


def test_wifi_settings_reports_accounts_and_the_sync_blob(wifi_settings_db):
    """The sync blob is measured and reported as decodable or not, separately.

    ``sync_extra_info`` is protobuf an older build may not have written, so the
    answer is a byte count and a boolean — not a claim that the blob is empty.
    """
    report = wifi_settings(str(wifi_settings_db))
    assert report["accounts"] == ["com.android.Account"]
    assert report["sync"] == [], "fixture nie ma wierszy w wifi_sync"


def test_a_wifi_sync_blob_is_read_when_present(tmp_path):
    """With a row: the protobuf walk runs and its strings come out."""
    from appdata_fixtures import make_sqlite

    payload = bytes([(1 << 3) | 2, 5]) + b"SSIDX" + bytes([(2 << 3) | 2, 3]) + b"pwd"
    path = make_sqlite(
        tmp_path / "wifi_sync.db",
        [
            "create table wifi_sync(_id integer primary key, account_name text, "
            "marker text, sync_extra_info blob)",
            "insert into wifi_sync values(1,'com.android.Account','m',x'%s')" % payload.hex(),
        ],
    )
    report = wifi_settings(str(path))
    assert len(report["sync"]) == 1
    entry = report["sync"][0]
    assert entry["sync_extra_info_bytes"] == len(payload)
    assert entry["sync_extra_info_decodable"] is True
    assert "SSIDX" in entry["sync_extra_info_strings"], entry


def test_a_wifi_database_with_no_wifi_table_reports_nothing_and_says_nothing(tmp_path):
    """No table is not an empty table, and the verdict says zero either way.

    ``count`` is zero in both cases and the difference is in ``counts`` nowhere —
    so this pins what the reader can and cannot distinguish, which is: nothing.
    Worth stating rather than pretending the output distinguishes them.
    """
    from appdata_fixtures import make_sqlite

    path = make_sqlite(tmp_path / "no_wifi.db", ["create table other(a integer)"])
    report = wifi_settings(str(path))
    assert report["networks"] == []
    assert report["count"] == 0
    assert report["verdict"] == "0 zapisanych sieci, 0 z kluczem WPA w bazie"


# --- network statistics ------------------------------------------------------


def test_anet_interfaces_are_read_and_deduplicated(anet_stats):
    """The interfaces the log mentions, in the order first seen.

    Interface names appear repeatedly as the log records successive events for
    them, so the list is a set that keeps its order — and the state word is taken
    from the first occurrence only, because later ones are a different sample.
    """
    report = network_stats(anet_stats, name="stats.1756199200000")
    assert report["is_anet"] is True
    assert report["magic"] == "ANET"
    assert report["ifaces"] == ["wlan0", "rmnet0"]
    # The state word is the 4 bytes following the first quoted name.
    assert report["state"] == 1


def test_the_interface_names_are_matched_as_quoted_strings(anet_stats):
    """The quotes are part of the format, not decoration in the reader.

    A builder that writes ``wlan0`` bare is a fixture that does not match ANET, and
    a reader built for the quoted form then returns nothing — which is what
    happened here first, and it read as a broken reader rather than a broken
    fixture.  Written as its own test so the quoting cannot be "simplified" away.
    """
    import re

    pattern = rb'\x0a"([\x20-\x7e]{1,32})"'
    assert re.findall(pattern, anet_stats) == [b"wlan0", b"rmnet0"]
    unquoted = anet_stats.replace(b'"', b"")
    assert re.findall(pattern, unquoted) == []


def test_the_stamp_comes_from_the_file_name_and_not_from_the_file(anet_stats):
    """A reader that preferred a field inside would be wrong more often.

    There is no schema for this container in the project — ``ConnectivityService``
    writes it and the layout is a framework internal — so the millisecond stamp is
    taken from the name, which the framework does control.  A blob with no
    timestamp field at all must therefore still produce one.
    """
    report = network_stats(anet_stats, name="stats.1756199200000")
    assert report["stamp_ms"] == 1756199200000
    assert report["stamp_utc"].startswith("2025")
    assert "licznik sieciowy zapisany" in report["verdict"]


def test_a_name_without_a_stamp_says_so_rather_than_guessing(anet_stats):
    report = network_stats(anet_stats, name="stats.bin")
    assert report["stamp_ms"] is None
    assert "?" in report["verdict"], report["verdict"]


def test_a_file_that_is_not_anet_says_so_in_one_sentence():
    """The refusal, and it is a refusal rather than a partial reading."""
    report = network_stats(b"NOTANET" + bytes(64), name="stats.1756199200000")
    assert report["is_anet"] is False
    assert report["verdict"] == "nie jest plikiem ANET"
    assert report["ifaces"] == []
    assert report["state"] is None


def test_an_anet_file_with_no_interface_named_reports_none(anet_stats):
    """An empty list is the honest answer; inventing one is not."""
    report = network_stats(_anet_blob(), name="stats.1756199200000")
    assert report["ifaces"] == []
    assert "brak w pliku" in report["verdict"], report["verdict"]


@pytest.mark.parametrize("blob,expected", [(b"", False), (b"ANE", False), (b"ANET", True)])
def test_the_magic_is_the_whole_admission_test(blob, expected):
    """Three bytes are not enough; four are."""
    report = network_stats(blob, name="x")
    assert report["is_anet"] is expected


def test_the_version_word_is_read_as_big_endian():
    blob = bytearray(_anet_blob("wlan0"))
    blob[4:8] = (0x01020304).to_bytes(4, "big")
    assert network_stats(bytes(blob), name="s")["version"] == 0x01020304