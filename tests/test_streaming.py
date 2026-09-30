# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Extraction streams: RAM stays flat whatever the artifact weighs, and a partial
write never looks like a finished one.

The path being replaced was ``blob = fs.read(path)`` then ``write_bytes(blob)``
then ``sha256(blob)`` — the whole artifact in memory, written out, and hashed
again from the buffer.  For a 10 GB database that is three passes over ten
gigabytes and a resident set proportional to the evidence, on a machine that was
handed a phone dump and asked to look at it.

The two guarantees tested here are the ones a streaming loop can quietly lose:

**Memory stays flat.**  Asserted by counting the bytes the reader is *asked* for,
which is the part that is actually under this function's control, and by pinning
the chunk size.  Measuring RSS would work too and would prove less — it is
possible to hold ten gigabytes and not show it if the allocator is cooperating.

**A failure leaves nothing behind.**  Bytes go to ``<name>.part`` and the finished
file is renamed.  ``extract_file`` writes the output path into its manifest
*before* the bytes are read, so a partial file left at the final name would be
listed there as a successful extraction and found by the next run, which returns
early on an existing file and would then parse the fragment as though it were the
whole database.
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

import pytest

from forensic.core.evidence import CHUNK_BYTES, TruncatedEvidenceError, copy_stream

requires_e2fsprogs = pytest.mark.skipif(
    not (shutil.which("mke2fs") or Path("/sbin/mke2fs").exists())
    and not (shutil.which("debugfs") or Path("/sbin/debugfs").exists()),
    reason="brak narzędzi e2fsprogs (mke2fs, debugfs)",
)


def _tool(name: str) -> str | None:
    for directory in ("", "/sbin", "/usr/sbin"):
        found = shutil.which(name, path=directory or None)
        if found:
            return found
    return None


def _run(*args: str) -> None:
    result = subprocess.run(list(args), capture_output=True, timeout=120)
    if result.returncode != 0:
        raise AssertionError(
            f"{' '.join(args)} -> {result.returncode}: "
            f"{result.stderr.decode('utf-8', 'replace')[:200]}"
        )


# --- the shape of the reads --------------------------------------------------


class _Reader:
    """Counts what it is asked for, so the memory claim can be checked."""

    def __init__(self, payload: bytes, *, fail_after: int | None = None) -> None:
        self.payload = payload
        self.requests: list[tuple[int, int]] = []
        self.fail_after = fail_after
        self.served = 0

    def __call__(self, offset: int, length: int) -> bytes:
        self.requests.append((offset, length))
        if self.fail_after is not None and self.served >= self.fail_after:
            raise TruncatedEvidenceError(
                f"blok {offset // 4096} nieczytelny w całości — obraz kończy się wcześniej"
            )
        block = self.payload[offset : offset + length]
        self.served += len(block)
        return block


def test_output_is_byte_identical_and_hash_matches(tmp_path):
    payload = bytes((i * 37 + 11) % 256 for i in range(300_000))
    reader = _Reader(payload)
    out = tmp_path / "artifact.bin"
    result = copy_stream(reader, out, size=len(payload))

    assert out.read_bytes() == payload
    assert result["sha256"] == hashlib.sha256(payload).hexdigest()
    assert result["bytes"] == len(payload)
    assert result["complete"] is True


def test_memory_is_bounded_by_the_chunk_not_the_file(tmp_path):
    """The claim the whole change rests on, stated as an assertion.

    A 300 000-byte file with the default 8 MiB chunk must be asked for once.  The
    old code asked for the whole thing and then held it.
    """
    payload = bytes(300_000)
    reader = _Reader(payload)
    copy_stream(reader, tmp_path / "a.bin", size=len(payload))
    assert reader.requests == [(0, len(payload))]

    big = bytes(5 * CHUNK_BYTES + 1234)
    reader = _Reader(big)
    copy_stream(reader, tmp_path / "b.bin", size=len(big))
    assert len(reader.requests) == 6, reader.requests
    assert sum(length for _offset, length in reader.requests) == len(big)
    assert max(length for _offset, length in reader.requests) <= CHUNK_BYTES


def test_offsets_are_contiguous_so_nothing_is_skipped(tmp_path):
    """A hole in the offsets would write a file with a silent gap in it.

    That is what the sparse-read bug looked like from this side: the reader asked
    for the right bytes and the writer put them in the wrong places.
    """
    payload = bytes((i * 7) % 256 for i in range(3 * CHUNK_BYTES + 99))
    reader = _Reader(payload)
    out = tmp_path / "c.bin"
    copy_stream(reader, out, size=len(payload), chunk=1024 * 1024)

    assert out.read_bytes() == payload
    offset = 0
    for asked, length in reader.requests:
        assert asked == offset, (asked, offset)
        offset += length
    assert offset == len(payload)


# --- failures leave nothing behind -------------------------------------------


def test_a_failing_read_removes_the_partial_and_raises(tmp_path):
    payload = bytes(200_000)
    reader = _Reader(payload, fail_after=120_000)
    out = tmp_path / "d.bin"
    with pytest.raises(TruncatedEvidenceError):
        copy_stream(reader, out, size=len(payload), chunk=8192)

    assert not out.exists(), "plik częściowy został pod nazwą końcową"
    assert not out.with_name(out.name + ".part").exists(), "został plik .part"


def test_an_existing_output_survives_a_failed_rewrite(tmp_path):
    """The next run must not find a fragment and call it the file.

    ``materialise`` returns early when the output exists, so a half-written file
    left at the final name would be parsed as a complete database on every later
    run — the failure would outlive the process that caused it.
    """
    out = tmp_path / "e.bin"
    out.write_bytes(b"the previous good extraction")
    reader = _Reader(bytes(100_000), fail_after=1000)
    with pytest.raises(TruncatedEvidenceError):
        copy_stream(reader, out, size=100_000, chunk=4096)
    assert out.read_bytes() == b"the previous good extraction"


def test_interrupt_also_cleans_up(tmp_path):
    reader = _Reader(bytes(100_000))

    def interrupted(offset: int, length: int) -> bytes:
        if offset >= 4096:
            raise KeyboardInterrupt
        return reader(offset, length)

    out = tmp_path / "f.bin"
    with pytest.raises(KeyboardInterrupt):
        copy_stream(interrupted, out, size=100_000, chunk=4096)
    assert not out.exists()
    assert not out.with_name(out.name + ".part").exists()


# --- a lying i_size ----------------------------------------------------------


def test_a_size_past_the_limit_is_reported_not_silently_cut(tmp_path):
    """``i_size`` is a field in the image and can be wrong by gigabytes.

    Handing back a prefix as if it were the file is the sparse-read bug wearing a
    different hat, so the result says ``complete: False`` and stops.
    """
    payload = bytes(10_000)
    reader = _Reader(payload)
    out = tmp_path / "g.bin"
    result = copy_stream(reader, out, size=4 * 1024 * 1024 * 1024, limit=4096)

    assert result["complete"] is False
    assert result["declared_size"] == 4 * 1024 * 1024 * 1024
    assert result["bytes"] == 4096
    assert out.read_bytes() == payload[:4096]


def test_a_reader_returning_nothing_stops_the_loop(tmp_path):
    """A short reader must not spin, and must not claim completeness."""
    out = tmp_path / "h.bin"
    result = copy_stream(lambda offset, length: b"", out, size=1000)
    assert result["bytes"] == 0
    assert result["complete"] is False
    assert out.read_bytes() == b""


# --- through the modules -----------------------------------------------------


@requires_e2fsprogs
def test_extracted_sparse_file_is_still_byte_identical(tmp_path):
    """Streaming must not have reintroduced the short-read defect.

    ``read_at`` returns the holes as zeros, and the writer has to place them at
    the right offsets.  A concatenation bug here would look exactly like the
    sparse-read bug the previous turn closed.
    """
    from forensic.core.config import Config
    from forensic.core.session import Ctx

    image = tmp_path / "img.img"
    _run(_tool("mke2fs"), "-q", "-t", "ext4", "-F", "-b", "1024", "-I", "256",
         str(image), "4096")
    payload = bytearray(10 * 1024)
    for index, block in enumerate((0, 4, 6, 7, 8)):
        payload[block * 1024 : (block + 1) * 1024] = bytes([index + 1]) * 1024
    source = tmp_path / "sparse.bin"
    source.write_bytes(bytes(payload))
    _run(_tool("debugfs"), "-w", "-R", "mkdir /d", str(image))
    _run(_tool("debugfs"), "-w", "-R", f"write {source} /d/s.bin", str(image))

    ctx = Ctx(
        config=Config(image=str(image), workdir=str(tmp_path / "w"), case="st"),
        color=False,
    )
    local = ctx.materialise("/d/s.bin")
    assert local.read_bytes() == bytes(payload)


@requires_e2fsprogs
def test_extract_file_manifest_hash_matches_the_file_on_disk(tmp_path):
    """The end the last turn was about: the hash must be of the bytes written.

    Both halves have to come from the same pass, or the manifest certifies one
    file while the disk holds another — which is what happened when the reader
    returned a short buffer that was then hashed and written unchallenged.
    """
    from forensic.core.config import Config
    from forensic.core.session import Ctx
    from forensic.modules.offline import extract_file

    image = tmp_path / "img.img"
    _run(_tool("mke2fs"), "-q", "-t", "ext4", "-F", "-b", "1024", "-I", "256",
         str(image), "4096")
    payload = bytes((i * 13 + 5) % 256 for i in range(120_000))
    source = tmp_path / "payload.bin"
    source.write_bytes(payload)
    _run(_tool("debugfs"), "-w", "-R", "mkdir /d", str(image))
    _run(_tool("debugfs"), "-w", "-R", f"write {source} /d/p.bin", str(image))

    ctx = Ctx(
        config=Config(image=str(image), workdir=str(tmp_path / "w"), case="st"),
        color=False,
    )
    result = extract_file.run(ctx, {"path": "/d/p.bin", "sidecars": False})
    entry = result.data["items"][0]
    assert entry["status"] == extract_file.STATUS_PRESENT
    assert entry["size"] == len(payload)
    assert Path(entry["output"]).read_bytes() == payload
    assert entry["sha256"] == hashlib.sha256(payload).hexdigest()
    assert entry["declared_size"] == len(payload)
