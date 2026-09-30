# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Android ``shared_prefs/*.xml`` — the parser and its size guard.

Every value type the format uses is pinned here, because the failure mode is
silent: a tag the parser does not recognise falls through to "keep the raw
string", so a preference that should be an ``int`` reads back as ``"5"`` and
nothing anywhere reports a problem.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from forensic.core.appdata import miui_backup_records, shared_prefs
from forensic.core.xmlsafe import MAX_XML, safe_fromstring

PREFS_TEXT = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="device_id">android-abc123</string>
    <string name="pusty"></string>
    <int name=" Attempts" value="0" />
    <int name="version" value="42" />
    <long name="last_seen" value="1646132854" />
    <boolean name="enabled" value="true" />
    <boolean name="disabled" value="false" />
    <float name="ratio" value="0.75" />
    <set name="languages"><string>pl</string><string>en</string></set>
    <string name="has spaces and &amp; entities">a &lt;b&gt; c</string>
    <string name="unicode">zażółć gęślą jaźń</string>
</map>
"""
PREFS = PREFS_TEXT.encode("utf-8")


def test_every_value_type_round_trips():
    out = shared_prefs(PREFS)
    assert out["device_id"] == "android-abc123"
    assert out["pusty"] == ""
    assert out["version"] == 42
    assert isinstance(out["version"], int)
    assert out["last_seen"] == 1646132854
    assert out["enabled"] is True
    assert out["disabled"] is False
    assert out["ratio"] == pytest.approx(0.75)
    assert out["languages"] == ["pl", "en"]
    assert out["has spaces and & entities"] == "a <b> c"
    assert out["unicode"] == "zażółć gęślą jaźń"


def test_a_name_that_is_only_whitespace_is_kept():
    """``strip()`` is applied to the *element text*, never to the key."""
    out = shared_prefs(PREFS)
    assert " Attempts" in out


def test_malformed_xml_is_reported_not_raised():
    out = shared_prefs(b"<map><string name='a'>b</map>")
    assert "error" in out
    assert out["error"]


def test_binary_junk_is_reported_not_raised():
    out = shared_prefs(b"\x00\x01\x02 not xml at all")
    assert "error" in out


def test_empty_input():
    assert shared_prefs(b"") == {"error": shared_prefs(b"")["error"]}
    assert "error" in shared_prefs(b"")


def test_unparseable_value_keeps_the_string():
    """A tag claiming to be an int but holding text reads back as text."""
    blob = b"<map><int name='x' value='abc' /></map>"
    assert shared_prefs(blob)["x"] == "abc"


def test_size_limit_refuses_an_oversized_document():
    huge = "<map><string name='a'>" + "x" * (MAX_XML + 1) + "</string></map>"
    with pytest.raises(ET.ParseError, match="XML"):
        safe_fromstring(huge)


def test_size_limit_allows_a_document_at_the_boundary():
    """The limit is on the text handed in, and nothing is lost at the edge."""
    filler = "x" * (MAX_XML - len("<map><string name='a'></string></map>"))
    text = f"<map><string name='a'>{filler}</string></map>"
    assert len(text) == MAX_XML
    assert shared_prefs(text.encode())["a"] == filler


def test_miui_backup_records():
    blob = b"""<?xml version='1.0' ?>
    <records>
        <package name="com.example.app"><version>12</version><time>1646132854000</time></package>
        <package name="com.other.app"><version>3</version></package>
    </records>
    """
    out = miui_backup_records(blob, package="com.example.app")
    assert [p["package"] for p in out["packages"]] == ["com.example.app"]
    assert out["packages"][0]["version"] == "12"
    assert out["packages"][0]["time"] == "1646132854000"
    assert miui_backup_records(blob)["packages"].__len__() == 2
