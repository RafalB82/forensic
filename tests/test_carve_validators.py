# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The carver's validators, one real file each.

A carving validator that returns ``None`` is indistinguishable from a format
that is not present, so a broken validator reports "nothing here" about a file
that is there.  Three of them were broken that way and none of the existing
fixtures noticed, because the fixtures planted a PNG and a gzip and nothing
else.  Each test below builds a genuine file with the standard library, runs the
validator over it, and requires the exact byte length back.

ZIP earns its own test twice over: its header fields are little-endian while
every other format in the table is big-endian, and reading them the other way
round produced a plausible-looking ``None``.
"""

from __future__ import annotations

import gzip
import io
import zipfile

import pytest

from forensic.core import carve

PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06"
    b"\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05"
    b"\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
)


def space_for(blob: bytes) -> carve._Space:
    return carve._Space([0], lambda _b: blob, len(blob), 0)


def _zip_bytes(method: int) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", method) as archive:
        archive.writestr("a.txt", "hello forensic world")
        archive.writestr("b/c.txt", "second entry " * 40)
    return buffer.getvalue()


@pytest.mark.parametrize("method", [zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED])
def test_zip_is_validated_to_its_exact_length(method):
    blob = _zip_bytes(method)
    result = carve._zip(space_for(blob))
    assert result is not None, "archiwum ZIP nie zostało rozpoznane"
    length, grade, truncated, note, detail = result
    assert grade == carve.VALIDATED
    assert truncated is False
    assert length == len(blob), f"{length} != {len(blob)}"
    assert detail["entries"] == 2


def test_zip_header_fields_are_read_little_endian():
    """The failure was silent: a wrong size sent the walk past the run's end."""
    blob = _zip_bytes(zipfile.ZIP_STORED)
    space = space_for(blob)
    assert space.le32(18) == len(b"hello forensic world")
    assert space.le16(26) == len("a.txt")
    # Big-endian on the same bytes is what the validator used to do.
    assert space.u32(18) != len(b"hello forensic world")


def test_zip_without_a_central_directory_is_reported_as_truncated():
    """The end record is what says the archive ended; without it, it is a fragment."""
    blob = _zip_bytes(zipfile.ZIP_STORED)
    without_eocd = blob[: -22]
    result = carve._zip(space_for(without_eocd))
    assert result is not None
    _length, grade, truncated, note, _detail = result
    assert truncated is True
    assert "katalogu centralnego" in note
    assert grade == carve.VALIDATED


def test_zip_claiming_more_data_than_the_run_holds_is_not_a_candidate():
    """An entry whose declared size runs past the window is refused, not carved.

    Reporting it would claim bytes that belong to whatever follows the run —
    possibly a live file — so the answer "no candidate" is the conservative one.
    """
    blob = _zip_bytes(zipfile.ZIP_STORED)
    result = carve._zip(space_for(blob[: len(blob) // 2]))
    assert result is None


def test_zip_rejects_bytes_that_only_start_like_one():
    assert carve._zip(space_for(b"PK\x03\x04" + b"\x00" * 8)) is None


def test_gzip_is_validated_by_decompressing_it():
    blob = gzip.compress(b"forensic" * 500)
    result = carve._gzip(space_for(blob))
    assert result is not None
    length, grade, truncated, _note, _detail = result
    assert grade == carve.VALIDATED
    assert not truncated
    assert length == len(blob)


def test_png_is_validated_by_its_crc():
    result = carve._png(space_for(PNG))
    assert result is not None
    length, grade, truncated, _note, _detail = result
    assert grade == carve.VALIDATED
    assert not truncated
    assert length == len(PNG)


def test_a_truncated_png_is_reported_not_dropped():
    """A signature that is really there must never come back as nothing.

    Cut after the IHDR, so at least one chunk is complete and CRC-checked.
    """
    head = PNG[: 8 + 8 + 13 + 4]  # signature + IHDR length/type/payload/crc
    result = carve._png(space_for(head))
    assert result is not None, "urwany PNG zgłoszony jako nieobecny"
    _length, grade, truncated, note, _detail = result
    assert truncated is True
    assert grade == carve.VALIDATED
    assert "IEND" in note


def test_a_png_cut_inside_its_first_chunk_is_not_a_candidate():
    """Eight signature bytes and noise are a hint, not a file.

    The validator needs one complete, CRC-verified chunk before it will call
    something a truncated PNG rather than a coincidence.
    """
    assert carve._png(space_for(PNG[:20])) is None


def test_pdf_finds_its_own_eof():
    blob = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n%%EOF\n"
    result = carve._pdf(space_for(blob))
    assert result is not None
    assert result[1] == carve.VALIDATED
    assert result[0] <= len(blob)


def test_signature_scan_finds_a_planted_object():
    """The scan step, not the validator: an archive among noise is located."""
    blob = b"\x00" * 64 + _zip_bytes(zipfile.ZIP_STORED) + b"\xff" * 32
    found = carve._find_signatures(blob)
    assert any(kind == "zip" for kind, _start in found), found
