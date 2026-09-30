# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""``metadata_csum``: verified, and the fact that it was is the point.

Two directions matter and they fail differently.  A checksum implementation that
is one byte off will reject clean images, or it will accept damaged ones and call
the metadata verified.  Neither is loud, so the tests below check both: that a
clean image verifies, and that **a single flipped byte is caught**.

The algorithm is transcribed from e2fsprogs' ``lib/ext2fs/csum.c`` and was pinned
against e2fsprogs before any of this was written.  Two properties were wrong in
the first attempt and both produced a plausible wrong number rather than an
error:

* the superblock checksum takes **no seed** and covers only the bytes *before*
  ``s_checksum`` — every other structure in the format is seeded, which makes the
  superblock the exception rather than the rule;
* ``i_extra_isize`` counts bytes past the 128-byte old inode, so the test for
  ``i_checksum_hi`` is ``>= 4``, not ``>= 0x84``.

Group-descriptor checksums need the ``gdt_csum`` bit, which is a **separate** bit
from ``metadata_csum`` and which this e2fsprogs build will not set through
``mke2fs -O`` or ``tune2fs -O``.  So that branch is implemented from the source
and exercised for shape only; the test says so rather than passing silently.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from forensic.core.crc32c import crc32c
from forensic.core.ext4 import Ext4

requires_e2fsprogs = pytest.mark.skipif(
    not (shutil.which("mke2fs") or Path("/sbin/mke2fs").exists()),
    reason="brak narzędzi e2fsprogs",
)


def _tool(name: str) -> str | None:
    for directory in ("", "/sbin", "/usr/sbin"):
        found = shutil.which(name, path=directory or None)
        if found:
            return found
    return None


# --- the primitive -----------------------------------------------------------


def test_crc32c_standard_check_value():
    """The published value, and the reason for the explicit complement.

    ``crc32c`` here follows e2fsprogs: the seed goes straight through, because
    every caller in the ext4 scheme threads one running value across several
    buffers.  A complement in the middle would change every byte after it.
    """
    assert crc32c(b"123456789") ^ 0xFFFFFFFF == 0xE3069283


def test_crc32c_is_order_dependent():
    assert crc32c(b"ab", 0x12345678) != crc32c(b"ba", 0x12345678)
    assert crc32c(b"", 0x12345678) == 0x12345678


# --- against e2fsprogs -------------------------------------------------------


def _make(image: Path, *, blocks: int = 8192, block_size: int = 1024) -> None:
    with image.open("wb") as handle:
        handle.truncate(blocks * block_size)
    subprocess.run(
        [_tool("mke2fs"), "-q", "-t", "ext4", "-F", "-b", str(block_size),
         "-I", "256", str(image)],
        check=True, capture_output=True, timeout=180,
    )


@requires_e2fsprogs
@pytest.mark.parametrize("block_size", [1024, 2048, 4096])
def test_superblock_checksum_matches_dumpe2fs(tmp_path, block_size):
    """Compared with e2fsprogs' own reading, across the three block sizes.

    Not against a value this tool computed earlier — that would only prove the
    implementation agrees with itself.
    """
    image = tmp_path / f"sb{block_size}.img"
    _make(image, block_size=block_size)
    dumpe2fs = _tool("dumpe2fs")
    if not dumpe2fs:
        pytest.skip("brak dumpe2fs")
    out = subprocess.run([dumpe2fs, "-h", str(image)], capture_output=True,
                         timeout=120).stdout.decode()
    reported = None
    for line in out.splitlines():
        if line.startswith("Checksum:"):
            reported = int(line.split()[-1], 16)
    if reported is None:
        pytest.skip("ten obraz nie ma sumy superblocka")

    with Ext4(str(image)) as fs:
        result = fs.checksums(inodes=0)
    assert result["metadata_csum"] is True, result
    assert result["superblock"]["stored"] == reported, (
        f"nasz odczyt {result['superblock']['stored']:#010x} vs dumpe2fs {reported:#010x}"
    )
    assert result["superblock"]["ok"] is True


@requires_e2fsprogs
def test_clean_image_verifies(tmp_path):
    image = tmp_path / "clean.img"
    _make(image)
    with Ext4(str(image)) as fs:
        result = fs.checksums(inodes=100)
    assert result["status"] == "ok", result
    assert result["superblock"]["ok"] is True
    assert result["bitmaps"]["bad"] == 0
    assert result["inodes"]["bad"] == 0
    assert result["bad"] == []


# --- the half that matters: it detects damage -------------------------------


def _flip(image: Path, offset: int, value: int = 0xFF) -> None:
    with open(image, "r+b") as handle:
        handle.seek(offset)
        current = handle.read(1)[0]
        handle.seek(offset)
        handle.write(bytes([current ^ value]))


@requires_e2fsprogs
def test_one_flipped_byte_in_the_superblock_is_caught(tmp_path):
    """A single byte, inside the region the checksum covers.

    The failure mode this guards against is the quiet one: a checksum that
    verifies everything is worse than no checksum, because a report then says the
    metadata was checked.
    """
    image = tmp_path / "sb_hit.img"
    _make(image)
    with Ext4(str(image)) as fs:
        assert fs.checksums(inodes=0)["status"] == "ok"
    _flip(image, 1024 + 0x2C)  # s_mtime, well inside the covered range
    with Ext4(str(image)) as fs:
        result = fs.checksums(inodes=0)
    assert result["status"] == "failed"
    assert result["superblock"]["ok"] is False
    assert result["bad"], "uszkodzony superblock nie został wymieniony"
    assert "superblock" in result["bad"][0]["what"]


@requires_e2fsprogs
def test_one_flipped_byte_in_a_bitmap_is_caught(tmp_path):
    """The bitmaps are what the free-space accounting reads.

    A wrong bitmap is not a cosmetic problem here: ``free_block_count`` and every
    "is this block free" answer that decides whether a carved file is believed
    come straight out of these bytes.
    """
    image = tmp_path / "bm_hit.img"
    _make(image)
    with Ext4(str(image)) as fs:
        before = fs.checksums(inodes=0)
        assert before["bitmaps"]["bad"] == 0
        bitmap_block = fs._groups[0]["block_bitmap"]
        block_size = fs.block_size
    _flip(image, bitmap_block * block_size + 40)
    with Ext4(str(image)) as fs:
        result = fs.checksums(inodes=0)
    assert result["status"] == "failed"
    assert result["bitmaps"]["bad"] >= 1
    assert any("block_bitmap" in item["what"] for item in result["bad"])


@requires_e2fsprogs
def test_one_flipped_byte_in_an_inode_is_caught(tmp_path):
    image = tmp_path / "in_hit.img"
    _make(image)
    with Ext4(str(image)) as fs:
        node = fs.inode(2)
        per_block = fs.block_size // fs.inode_size
        group, index = divmod(2 - 1, fs.superblock["inodes_per_group"])
        table = fs._groups[group]["inode_table"]
        at = (table + index // per_block) * fs.block_size + (index % per_block) * fs.inode_size
        assert node.is_dir and node.size > 0, node.size
    _flip(image, at + 0x04)  # i_size
    with Ext4(str(image)) as fs:
        result = fs.checksums(inodes=4)
    assert result["status"] == "failed"
    assert result["inodes"]["bad"] >= 1
    assert any(item["what"].startswith("inode") for item in result["bad"])


# --- the third state ---------------------------------------------------------


@requires_e2fsprogs
def test_image_without_metadata_csum_says_not_present_not_ok(tmp_path):
    """No feature means no checksum was computed, and that is not a pass.

    Reporting this as ``ok`` would claim a verification that never happened, and
    a report line reading "metadata verified" on a volume that carries no
    checksums is exactly the sentence this tool must not produce.  The 2016
    reference image lands here — that is where the old docstring's "parsed but
    never verified" came from.
    """
    image = tmp_path / "nocsum.img"
    with image.open("wb") as handle:
        handle.truncate(8192 * 1024)
    subprocess.run(
        [_tool("mke2fs"), "-q", "-t", "ext2", "-F", "-b", "1024", "-I", "256", str(image)],
        check=True, capture_output=True, timeout=180,
    )
    with Ext4(str(image)) as fs:
        result = fs.checksums(inodes=50)
    assert result["metadata_csum"] is False
    assert result["status"] == "not_present"
    assert result["status"] != "ok"
    assert result["bad"] == []
    assert result["ok_count"] == 0


@requires_e2fsprogs
def test_group_descriptor_checksums_are_marked_absent_when_the_bit_is_off(tmp_path):
    """``gdt_csum`` is a separate bit and this e2fsprogs will not set it.

    So the branch is exercised for shape only.  Asserted as such rather than
    left looking like coverage: a reader that silently claimed to have verified
    group descriptors would be the exact failure this suite exists to catch.
    """
    image = tmp_path / "gdt.img"
    _make(image)
    with Ext4(str(image)) as fs:
        result = fs.checksums(inodes=0)
    assert result["gdt_csum"] is False
    assert result["group_descriptors"]["not_present"] is True
    assert result["group_descriptors"]["checked"] == 0


@requires_e2fsprogs
def test_all_zero_inode_is_not_reported_as_corrupt(tmp_path):
    """e2fsprogs accepts an unused inode whose checksum does not match, and so does this.

    An inode nobody wrote has a zero checksum by construction; calling that
    corruption would put a permanent critical finding on every healthy volume.
    Counted separately so the number of *verified* inodes is not inflated by them.
    """
    image = tmp_path / "zero.img"
    _make(image)
    with Ext4(str(image)) as fs:
        result = fs.checksums(inodes=300)
    assert result["inodes"]["all_zero"] > 0, result["inodes"]
    assert result["status"] == "ok", result


@requires_e2fsprogs
def test_inode_cap_is_reported_not_implied(tmp_path):
    """A capped check that does not say it was capped reads as a complete one."""
    image = tmp_path / "cap.img"
    _make(image)
    with Ext4(str(image)) as fs:
        result = fs.checksums(inodes=5)
    assert result["inodes"]["cap"] == 5
    assert result["inodes"]["capped"] is True
    assert result["inodes"]["checked"] <= 5


@requires_e2fsprogs
def test_superblock_checksum_stops_before_its_own_field(tmp_path):
    """The property that was wrong first time, pinned.

    ``s_checksum`` sits *outside* the covered region, so it is neither zeroed nor
    appended.  Zeroing it or appending it both produce a plausible wrong number.
    """
    image = tmp_path / "sb_prop.img"
    _make(image)
    raw = image.read_bytes()[1024:2048]
    stored = struct.unpack_from("<I", raw, 0x3FC)[0]
    assert crc32c(raw[:0x3FC]) == stored
    assert crc32c(raw[:0x3FC], struct.unpack_from("<I", raw, 0x270)[0]) != stored
    assert crc32c(raw) != stored
