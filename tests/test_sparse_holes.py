# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Sparse files: a hole inside a file is not a hole in the evidence.

The distinction this file exists to protect, because the two look identical in
code and demand opposite handling.

* A **physical** block that is not in the image is missing evidence.  The reader
  raises :class:`~forensic.core.evidence.TruncatedEvidenceError`.
* A **logical** block inside ``i_size`` that no extent maps is a **sparse hole**.
  The format says it reads as zeros, and filling it is correct — reporting it as
  unreadable would refuse a perfectly good file.

``read_at`` implemented the second by accident and got the first for free, which
is the worst of both.  It clipped the result to the inode's declared size and
concatenated only the extents that existed, so a 16 KiB file with 8 KiB of holes
came back as 8 KiB of real bytes and **no error at all**: the declared length, the
real length and the truth were three different numbers and nothing said so.

That is not a theoretical defect.  A SQLite database whose interior pages were
never written — the normal shape of a database created with a 4 KiB page size and
little data in it — lost half its length on the way to the parser, and the parser
answered ``database disk image is malformed``.  A confident false diagnosis of
undamaged evidence, which is the one thing a forensic reader must not produce.

The fixtures here write holes explicitly rather than borrowing whatever sparsity
some other tool happens to produce, so the test states its own premise.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from forensic.core.evidence import TruncatedEvidenceError
from forensic.core.ext4 import Ext4

BLOCK_SIZE = 1024
BLOCKS = 4096
FILE_PATH = "/evidence/sparse.bin"


def _tool(name: str) -> str | None:
    for directory in ("", "/sbin", "/usr/sbin"):
        found = shutil.which(name, path=directory or None)
        if found:
            return found
    return None


requires_e2fsprogs = pytest.mark.skipif(
    not (_tool("mke2fs") and _tool("debugfs")),
    reason="brak narzędzi e2fsprogs (mke2fs, debugfs)",
)


def _run(*args: str) -> None:
    result = subprocess.run(list(args), capture_output=True, timeout=120)
    if result.returncode != 0:
        raise AssertionError(
            f"{' '.join(args)} -> {result.returncode}: "
            f"{result.stderr.decode('utf-8', 'replace')[:200]}"
        )


def _sparse_source(path: Path) -> tuple[bytes, int]:
    """A file with holes at blocks 1-3, 5 and 9; returns its bytes and hole count.

    Written by seeking, so the sparsity is a property of the fixture rather than
    of whatever the filesystem or a library decided to do.  Block 0 and block 4
    carry data; 1, 2, 3, 5 and 9 are never written, so they read as zeros and
    occupy no blocks.
    """
    content = bytearray(BLOCK_SIZE * 10)
    for index, block in enumerate((0, 4, 6, 7, 8)):
        marker = bytes([index + 1]) * BLOCK_SIZE
        content[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE] = marker
    path.write_bytes(bytes(content))
    holes = sum(
        1
        for block in range(10)
        if bytes(content[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE])
        == bytes(BLOCK_SIZE)
    )
    return bytes(content), holes


@pytest.fixture(scope="module")
def sparse_image(tmp_path_factory):
    src_dir = tmp_path_factory.mktemp("sparse-src")
    source = src_dir / "s.bin"
    _, holes = _sparse_source(source)
    base = tmp_path_factory.mktemp("sparse-img")
    image = base / "sparse.img"
    _run(
        _tool("mke2fs"), "-q", "-t", "ext4", "-F",
        "-b", str(BLOCK_SIZE), "-I", "256", str(image), str(BLOCKS),
    )
    _run(_tool("debugfs"), "-w", "-R", "mkdir /evidence", str(image))
    _run(_tool("debugfs"), "-w", "-R", f"write {source} {FILE_PATH}", str(image))
    return image, source.read_bytes(), holes


@requires_e2fsprogs
def test_fixture_is_actually_sparse(sparse_image):
    """Guard the premise.  If the holes got allocated, the tests below prove nothing.

    Checks the inode rather than the file on the host: what matters is that the
    *image* carries unmapped blocks, which is the condition ``read_at`` has to
    survive.
    """
    image, whole, holes = sparse_image
    assert holes > 0, "fixture nie ma dziur"
    assert len(whole) == BLOCK_SIZE * 10
    with Ext4(str(image)) as fs:
        node = fs.resolve(FILE_PATH)
        mapped_blocks = sum(e.count for e in node.extents)
        assert node.size == BLOCK_SIZE * 10
        assert mapped_blocks < 10, (
            f"extent map pokrywa {mapped_blocks} z 10 bloków — fixture nie jest "
            f"rzeczywiście dziurawy"
        )
        assert fs.hole_bytes(node) == holes * BLOCK_SIZE


@requires_e2fsprogs
def test_sparse_file_reads_back_byte_identical(sparse_image):
    """The whole length, with the holes as zeros, and nothing else different.

    This is the assertion that failed before: the read came back 8192 bytes for a
    10240-byte file and still raised nothing.
    """
    image, whole, _ = sparse_image
    with Ext4(str(image)) as fs:
        node = fs.resolve(FILE_PATH)
        assert node.size == len(whole)
        blob = fs.read(FILE_PATH)
        assert len(blob) == len(whole), (
            f"przeczytano {len(blob)} z {len(whole)} B — brakujące bajty "
            f"dziur zostały zgłoszone jako treść"
        )
        assert blob == whole
        assert hashlib.sha256(blob).hexdigest() == hashlib.sha256(whole).hexdigest()


@requires_e2fsprogs
def test_partial_read_keeps_the_right_offsets(sparse_image):
    """A range that spans a hole must still be positioned correctly.

    Slicing the result of a full read would hide an off-by-one in the positional
    writes: reading blocks 0..9 into a buffer and handing back the first 5 KiB
    skips the hole, so the bytes after it shift.
    """
    image, whole, _ = sparse_image
    with Ext4(str(image)) as fs:
        chunk = fs.read_at(FILE_PATH, 0, BLOCK_SIZE * 10)
        assert chunk == whole
        # A window in the middle, entirely inside the first hole.
        assert fs.read_at(FILE_PATH, BLOCK_SIZE, BLOCK_SIZE * 2) == whole[
            BLOCK_SIZE : BLOCK_SIZE * 3
        ]
        # A window straddling the second hole.
        start = BLOCK_SIZE * 4
        assert fs.read_at(FILE_PATH, start, BLOCK_SIZE * 2) == whole[
            start : start + BLOCK_SIZE * 2
        ]


@requires_e2fsprogs
def test_hole_bytes_is_reported_not_hidden(sparse_image):
    """How much of the file was never written is evidence, so it gets a number.

    A hole means the file was extended without being written — a database cut
    short by a crashed process, a log resized in place.  An analyst deciding
    whether trailing zeros were ever written needs to know.
    """
    image, whole, holes = sparse_image
    with Ext4(str(image)) as fs:
        reported = fs.hole_bytes(FILE_PATH)
        assert reported == holes * BLOCK_SIZE, (reported, holes * BLOCK_SIZE)
        assert 0 < reported < len(whole)


@requires_e2fsprogs
def test_hole_is_not_mistaken_for_truncation(sparse_image, tmp_path):
    """The two gaps must not have collapsed into one.

    Cutting the image so the file's last data block falls off the end is
    truncation and raises.  The same file with a hole in the middle is neither,
    and must keep reading.  A reader that raised for holes would refuse half the
    sparse files on a real ``/data``; one that padded for truncation is the bug
    this whole turn started from.
    """
    image, whole, _ = sparse_image
    with Ext4(str(image)) as fs:
        # Whole image: the hole reads, and nothing raises.
        assert fs.read(FILE_PATH) == whole

        first = fs.resolve(FILE_PATH).extents[0].physical
        cut = tmp_path / "cut.img"
        with open(image, "rb") as src, open(cut, "wb") as dst:
            dst.write(src.read(first * BLOCK_SIZE))
        with Ext4(str(cut)) as cut_fs:
            assert cut_fs.truncated is True
            with pytest.raises(TruncatedEvidenceError):
                cut_fs.read(FILE_PATH)


@requires_e2fsprogs
def test_dense_file_has_no_holes(sparse_image):
    """The control: a fully written file reports none, so the number means something.

    Without it, ``hole_bytes`` could be a constant and every assertion above would
    still pass.
    """
    image, _, _ = sparse_image
    source = image.parent / "dense.bin"
    content = bytes((i * 31 + 7) % 256 for i in range(BLOCK_SIZE * 4))
    source.write_bytes(content)
    _run(_tool("debugfs"), "-w", "-R", f"write {source} /evidence/dense.bin", str(image))
    with Ext4(str(image)) as fs:
        assert fs.hole_bytes("/evidence/dense.bin") == 0
        assert fs.read("/evidence/dense.bin") == content
