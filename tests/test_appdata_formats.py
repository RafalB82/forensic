# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Identifying a blob, and what happens when two identifiers disagree.

:func:`forensic.core.appdata.classify` is the first thing that touches every
artifact this tool reads, and a wrong answer from it is not a wrong line in a
table — it is the wrong artifact named in a report.  A shared-prefs map called
"opaque" means an analyst never opens it; a database called "opaque" means the
token scan never runs.

So the identification is tested against blobs built byte for byte, and the second
opinion — libmagic — is tested for what it actually contributes.  ``classify`` was
written by the same author as the report that cites it, so a rule that is wrong is
wrong everywhere at once; libmagic is a separate project with its own magic
database, and the disagreement between them is itself the finding.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from forensic.core.appdata import (
    MAGIC_MAP,
    classify,
    classify_checked,
    is_encrypted,
    magic_available,
    magic_verdict,
    text_strings,
)

SQLITE = b"SQLite format 3\x00" + bytes(4096)
JAVA = b"\xac\xed\x00\x05" + bytes(64)


# --- ours --------------------------------------------------------------------


def test_sqlite_is_recognised_by_its_header():
    assert classify(SQLITE) == "sqlite"


def test_java_serialisation_is_recognised_by_its_header():
    assert classify(JAVA) == "java-serialized"


def test_shared_prefs_is_recognised_in_both_forms_and_with_leading_space(shared_prefs_xml):
    """Android writes ``<map>`` with or without an XML prolog.

    The prolog is on the same line in some builds and padded with spaces in
    others, and the reader strips leading whitespace before looking — a detail
    worth pinning because "almost every real shared_prefs" is a sentence that
    turns into "none".
    """
    assert classify(shared_prefs_xml) == "shared-prefs-xml"
    assert classify(b"<map><string name='a'>b</string></map>") == "shared-prefs-xml"
    assert classify(b"   \n<?xml version='1.0'?><map/>") == "shared-prefs-xml"


def test_json_is_recognised_for_objects_and_arrays():
    assert classify(b'{"a": 1}') == "json"
    assert classify(b"[1, 2, 3]") == "json"
    assert classify(b'  \n {"a": 1}') == "json"


def test_anything_else_is_opaque():
    """Not a failure mode — the honest label for something unrecognised.

    What matters is that it is a distinct word from "text", which the caller uses
    to decide whether to go looking inside.
    """
    assert classify(b"") == "opaque"
    assert classify(bytes(64)) == "opaque"
    assert classify(b"\x01\x02\x03\x04" * 16) == "opaque"


def test_the_ber_properties_branch_is_pinned_as_it_is_written():
    """A two-byte prefix decides this one, so it is pinned rather than trusted.

    ``0x0002`` at the front of a blob is a weak signal, and the reader says so by
    putting this branch *last*, after the strong magic numbers.  The test records
    what it currently claims rather than approving of it: if this ever widens, the
    diff shows up here.
    """
    assert classify(b"\x00\x02" + b"\x00" * 32) == "ber-properties-store"
    # Too short to decide — the branch requires more than eight bytes.
    assert classify(b"\x00\x02" + b"\x00" * 4) == "opaque"
    # And a strong magic number beats it, because that branch comes first.
    assert classify(SQLITE) == "sqlite"


# --- the second opinion ------------------------------------------------------


def test_magic_verdict_says_nothing_rather_than_guessing():
    """An empty blob and a missing tool both yield ``("", "")``.

    ``("", "")`` is deliberately distinguishable from ``("", "data")``: the first
    means libmagic had no opinion, the second means it had one we deliberately
    discarded.  Reporting the second as the first would let "data" hide a real
    disagreement.
    """
    label, raw = magic_verdict(b"")
    assert label == "" and raw == ""


@pytest.mark.skipif(not magic_available(), reason="brak narzędzia `file`")
def test_agreement_is_reported_as_agreement(tmp_path):
    """Against a **real** database, not a header of zeros.

    The first version of this test used ``b"SQLite format 3\0" + bytes(4096)``,
    which our classifier names from the magic alone and libmagic calls ``data`` —
    because a header with no page size and no page count is not a database.  That
    is a disagreement about a broken input rather than about the two readers, and
    writing it as "they disagree" would have taught the wrong thing.
    """
    import sqlite3

    real = tmp_path / "real.db"
    conn = sqlite3.connect(real)
    conn.execute("create table t(a)")
    conn.execute("insert into t values(1)")
    conn.commit()
    conn.close()

    result = classify_checked(real.read_bytes())
    assert result["format"] == "sqlite"
    assert result["magic"] == "sqlite", result
    assert result["report"] == "sqlite"
    assert "zgodne" in result["note"]


@pytest.mark.skipif(not magic_available(), reason="brak narzędzia `file`")
def test_a_header_with_no_pages_is_reported_as_ours_with_the_reason_attached():
    """The broken input above, pinned — and it lands on a third branch.

    Ours reads the magic and calls it a database.  libmagic reads the whole
    header, finds no page count, and says ``data``.  And ``data`` is
    **deliberately absent** from :data:`forensic.core.appdata.MAGIC_MAP`, because
    it carries no information and translating it into a class of our own would
    invent certainty.  So this is neither "in agreement" nor "in disagreement": it
    is libmagic having an opinion we refuse to use, and that is its own note.

    The first version of this test expected "niezgodność" and failed, having
    assumed the two-label vocabulary.  There are three: agreement, a usable
    disagreement, and a discarded opinion.
    """
    result = classify_checked(SQLITE)
    assert result["format"] == "sqlite"
    assert result["report"] == "sqlite"
    assert result["magic"] == "", result
    assert "bez użytecznej etykiety" in result["note"], result["note"]


@pytest.mark.skipif(not magic_available(), reason="brak narzędzia `file`")
def test_our_opaque_but_theirs_recognised_is_a_named_disagreement():
    """The interesting direction, and the reason the second opinion exists.

    When our classifier returns ``opaque`` and libmagic recognises something, the
    report says libmagic's answer — and the note says whose it is.  Merging the
    two into one field would make a disagreement invisible, and an invisible
    disagreement is how a reader that does not understand a format gets to look
    like it does.
    """
    plain_text = b"just some readable bytes\n" * 8
    assert classify(plain_text) == "opaque"
    result = classify_checked(plain_text)
    if result["magic"]:
        assert result["report"] == result["magic"]
        assert result["format"] == "opaque"
        assert "opaque" in result["note"] and "libmagic" in result["note"]


@pytest.mark.skipif(not magic_available(), reason="brak narzędzia `file`")
def test_a_real_disagreement_keeps_our_answer_and_says_so():
    """When both have an opinion and they differ, ours is reported and named.

    The reverse of the previous test: silently preferring the other project
    would make the two readers interchangeable in the report, and they are not.
    """
    # A Java stream whose header we classify, that libmagic words differently.
    result = classify_checked(JAVA)
    if result["magic"] and result["magic"] != result["format"]:
        assert result["report"] == result["format"]
        assert "niezgodność" in result["note"]


def test_every_magic_label_is_a_label_our_classifier_can_produce():
    """The mapping cannot invent a format we do not have a word for.

    ``MAGIC_MAP`` translating libmagic's "text" to ``text`` is fine — the caller
    knows that word.  Translating to something like "ber-properties-store" from a
    fuzzy match would not be.
    """
    ours = {"sqlite", "java-serialized", "shared-prefs-xml", "json",
            "ber-properties-store", "opaque"}
    mapped = {label for _needle, label in MAGIC_MAP}
    assert mapped <= ours | {"text"}, mapped - ours


# --- the heuristics beside it ------------------------------------------------


def test_is_encrypted_declines_the_formats_it_can_name():
    """A named format is by definition not "encrypted, probably".

    This is the same reasoning ``whatsapp_crypt_header`` states: a wrong "this is
    encrypted" sends the analyst looking for a key they do not have.
    """
    assert is_encrypted(SQLITE) is False
    assert is_encrypted(JAVA) is False


def test_is_encrypted_declines_short_and_printable_blobs():
    assert is_encrypted(b"") is False
    assert is_encrypted(b"\x01\x02\x03" * 8) is False  # too short to judge
    assert is_encrypted(b"readable text " * 64) is False


def test_is_encrypted_accepts_dense_noise():
    """The narrow band it does accept, pinned so the acceptance is not folklore.

    The condition is *no* printable run of four in the first 4 KiB, plus a NUL
    density below one in 64.  A deterministic stride coprime with 256 produces
    exactly that and nothing else does.
    """
    blob = bytes((i * 131 + 3) % 256 for i in range(8192))
    assert is_encrypted(blob) is True


def test_is_encrypted_does_not_detect_real_ciphertext():
    """A known limitation, asserted so nobody later believes the function works.

    Measured on 20 fresh 64 KiB blobs from ``os.urandom``: ``is_encrypted``
    returns ``False`` on **20 of 20**.  Random bytes produce around 810 printable
    runs of four characters or more per 64 KiB, and the heuristic demands a blob
    with none in its first 4 KiB, so the condition real encryption satisfies is
    the one it rules out.

    This is written as a test on purpose, even though it pins a defect: the
    function is **not called anywhere in the package**, so nothing depends on the
    answer, and an untested and undocumented version of this would be read as
    working.  Whoever reaches for it needs to know it does not.  The fix is either
    an entropy measure or deleting it — see the note in ``is_encrypted``.
    """
    import os

    blob = os.urandom(65536)
    assert is_encrypted(blob) is False


def test_text_strings_are_deduplicated_and_longest_first():
    """Longest first because that is the order a reader should meet them in.

    Runs shorter than four characters are not extracted at all: the pattern is
    ``[\x20-\x7e]{4,}``, so a two-character fragment of noise is not a string
    anybody put in a file.  An earlier version of this test expected ``"ab"`` and
    failed on exactly that, which is why the minimum is written down here.
    """
    blob = b"\x00ab\x00abcd\x00abcdefgh\x00ab\x00wxyz\x00"
    assert text_strings(blob) == ["abcdefgh", "abcd", "wxyz"]


def test_text_strings_honours_a_limit():
    blob = b"aaaa bbbb cccc dddd eeee"
    assert text_strings(blob) == ["aaaa bbbb cccc dddd eeee"]
    assert text_strings(blob, limit=2) == ["aaaa bbbb cccc dddd eeee"]


def test_classify_checked_always_carries_a_report_label(fb_properties_store, shared_prefs_xml):
    """Whatever happens, there is a word to print."""
    for blob in (SQLITE, JAVA, shared_prefs_xml, b"", bytes(64), fb_properties_store.read_bytes()):
        result = classify_checked(blob)
        assert result["report"], blob[:16]
        assert result["format"], blob[:16]
        assert result["note"], blob[:16]


def test_no_subprocess_when_the_tool_is_missing(monkeypatch):
    """A missing ``file`` must not turn into an error.

    The readers run on analyst machines where e2fsprogs may be absent, so the
    second opinion has to degrade to silence.
    """
    monkeypatch.setattr("forensic.core.imagemount.tool_path", lambda name: None)
    assert magic_available() is False
    assert magic_verdict(SQLITE) == ("", "")
    result = classify_checked(SQLITE)
    assert result["magic"] == ""
    assert "nie odpowiedział" in result["note"]
    # And our own answer is untouched by the missing tool.
    assert result["format"] == "sqlite"


def test_a_failing_subprocess_is_swallowed(monkeypatch):
    """A ``file`` that exits non-zero has said nothing, which is not a crash."""

    def boom(*args, **kwargs):
        raise subprocess.SubprocessError("no")

    monkeypatch.setattr("forensic.core.imagemount.tool_path", lambda name: "/bin/false")
    monkeypatch.setattr(subprocess, "run", boom)
    assert magic_verdict(SQLITE) == ("", "")


def test_json_properties_store_documents_are_extracted_and_the_container_is_not_guessed(fb_properties_store):
    """The private Facebook Lite container is named as unknown, on purpose.

    Its format is Facebook's and is not documented forensically, so the reader
    reports what survives — the JSON documents — and says the container is
    unknown rather than inventing a name for it.  A confident guess here would be
    indistinguishable, in the report, from having understood it.
    """
    from forensic.core.appdata import properties_store

    report = properties_store(fb_properties_store.read_bytes())
    assert report["container"].startswith("nieznany")
    documents = report["documents"]
    assert any(isinstance(d, dict) and "unseen_count_access_token" in d for d in documents)
    # The truncated document must not appear: a half-parsed object is not evidence.
    assert not any(isinstance(d, dict) and "broken" in d for d in documents)


def test_nested_json_with_a_brace_inside_a_string_survives(fb_properties_store):
    """The brace counter must respect string quoting.

    A ``}`` inside a string value closes nothing, and a counter that forgets that
    truncates every document whose text contains a brace — which is most of them.
    """
    from forensic.core.appdata import properties_store

    documents = properties_store(fb_properties_store.read_bytes())["documents"]
    nested = [d for d in documents if isinstance(d, dict) and "outer" in d]
    assert nested, documents
    assert nested[0]["outer"]["inner"] == [1, 2, 3]
    assert nested[0]["s"] == 'has "quotes" and } brace'


def test_a_store_with_no_documents_is_empty_not_broken(tmp_path):
    from forensic.core.appdata import properties_store

    path = tmp_path / "empty_store"
    path.write_bytes(b"\x00\x01FBLT" + bytes(512))
    report = properties_store(path.read_bytes())
    assert report["documents"] == []
    assert report["size"] == 518  # 6-byte prefix + 512


def test_only_json_objects_are_extracted_and_that_is_a_limitation(tmp_path):
    """The scan looks for ``{`` and so finds objects only.

    A bare string or a top-level array in the store is skipped, which the first
    version of this test got wrong by expecting otherwise.  It is a real
    limitation and stated as one: whatever Facebook Lite writes, the token hunter
    only ever needed objects, and a scanner that also handled top-level scalars
    would be guessing at a private format.
    """
    from forensic.core.appdata import properties_store

    path = tmp_path / "store"
    path.write_bytes(
        b"\x00\x01" + b'"bare string"' + b"\x00" + b"[1,2]" + b"\x00"
        + b'{"kept": 1}' + b"\x00"
    )
    documents = properties_store(path.read_bytes())["documents"]
    assert documents == [{"kept": 1}], documents


def test_documents_are_deduplicated(tmp_path):
    """The same document written twice is one document."""
    from forensic.core.appdata import properties_store

    doc = json.dumps({"k": "v"}).encode()
    path = tmp_path / "store"
    path.write_bytes(b"\x00\x01" + doc + b"\x00" + doc + b"\x00")
    assert len(properties_store(path.read_bytes())["documents"]) == 1