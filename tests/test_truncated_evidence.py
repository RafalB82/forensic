# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""What the reader does when the evidence stops being evidence.

A truncated image is not a hypothetical input.  It is what a half-finished EDL
dump is, what a ``dd`` that ran out of space is, and what an analyst gets when
they are handed a partition rather than the whole disk.  It is also the one input
this reader used to answer most confidently and most wrongly: a short ``pread`` at
the end of the file was completed with NUL bytes, and because ``read_at`` clips
its result to the size the inode declares, a file whose data blocks sat past the
cut came back as a buffer of **exactly the declared length**, full of zeros, with
no error anywhere.  ``extract_file`` then hashed it and wrote the hash into a
manifest.

So the assertions below are not "it does not crash" — that was already true. They
are the three things that have to hold instead:

* a read that crosses the truncation raises :class:`TruncatedEvidenceError`,
* it never returns bytes that were not in the file,
* and a file past the cut is never reported as a file that does not exist.

The last one is the subtle half.  Truncating low enough that the directory blocks
go missing used to raise ``KeyError``, which every module renders as *"Brak
ścieżki"* — a clean negative.  It is not a clean negative; the file was there and
we cannot read it.  ``extract_file`` now distinguishes the two, and
:func:`test_absent_and_truncated_are_different_findings` pins that.

Needs ``e2fsprogs``; skips without it, like the rest of the filesystem tests.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from forensic.core.evidence import TruncatedEvidenceError
from forensic.core.ext4 import Ext4, Ext4Error
from forensic.modules.offline import extract_file

BLOCK_SIZE = 1024
BLOCKS = 4096
#: 4096 B of known content, written into the image by ``debugfs`` without
#: mounting, so the tests know the exact bytes the file is supposed to hold.
PAYLOAD = bytes((i * 37 + 11) % 256 for i in range(4096))
PAYLOAD_PATH = "/evidence/payload.bin"


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
    import subprocess

    result = subprocess.run(list(args), capture_output=True, timeout=120)
    if result.returncode != 0:
        raise AssertionError(
            f"{' '.join(args)} -> {result.returncode}: "
            f"{result.stderr.decode('utf-8', 'replace')[:200]}"
        )


@pytest.fixture(scope="module")
def whole_image(tmp_path_factory) -> tuple[Path, bytes]:
    """A whole, valid ext4 image with one known file in it, plus its true bytes."""
    base = tmp_path_factory.mktemp("truncated")
    image = base / "whole.img"
    _run(
        _tool("mke2fs"),
        "-q",
        "-t",
        "ext4",
        "-F",
        "-b",
        str(BLOCK_SIZE),
        "-I",
        "256",
        str(image),
        str(BLOCKS),
    )
    payload = base / "payload.bin"
    payload.write_bytes(PAYLOAD)
    _run(_tool("debugfs"), "-w", "-R", "mkdir /evidence", str(image))
    _run(
        _tool("debugfs"),
        "-w",
        "-R",
        f"write {payload} {PAYLOAD_PATH}",
        str(image),
    )
    return image, PAYLOAD


def _copy_truncated(whole: Path, tmp_path: Path, blocks: int, name: str = "cut.img") -> Path:
    """A copy of ``whole`` holding only its first ``blocks`` blocks."""
    out = tmp_path / name
    with open(whole, "rb") as src, open(out, "wb") as dst:
        remaining = blocks * BLOCK_SIZE
        while remaining > 0:
            chunk = src.read(min(BLOCK_SIZE, remaining))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)
    return out


def _private_image(whole: Path, tmp_path: Path, name: str = "own.img") -> Path:
    """A writable copy of the fixture, for tests that add files to it.

    ``whole_image`` is module-scoped so the read-only tests only pay for one
    ``mke2fs``, but ``debugfs -w`` mutates whatever it is given.  A test that
    writes into the shared image changes what every later test in the file sees,
    which is how the collision test came to read the wrong file's bytes.
    """
    return _copy_truncated(whole, tmp_path, BLOCKS, name=name)


def _file_extent_block(whole: Path) -> int:
    """The first physical block the planted file occupies."""
    import subprocess

    result = subprocess.run(
        [_tool("debugfs"), "-R", f"stat {PAYLOAD_PATH}", str(whole)],
        capture_output=True,
        timeout=60,
    )
    text = result.stdout.decode("utf-8", "replace")
    for line in text.splitlines():
        if line.startswith("(") and "-" in line:
            # e.g. ``(0-3):1651-1654``
            return int(line.split(":")[-1].split("-")[0])
    raise AssertionError(f"nie znaleziono extentu w debugfs:\n{text}")


# --- the whole image, as the control -----------------------------------------
# Without a control the truncated cases prove nothing: a test that expects an
# exception passes just as well against a reader that is broken in every case.


@requires_e2fsprogs
def test_whole_image_is_not_truncated(whole_image):
    whole, payload = whole_image
    with Ext4(str(whole)) as fs:
        assert fs.truncated is False
        assert fs.truncated_bytes == 0
        assert fs.read(PAYLOAD_PATH) == payload


# --- the geometry is larger than the file ------------------------------------


@requires_e2fsprogs
@pytest.mark.parametrize("blocks", [BLOCKS - 1, BLOCKS - 2, BLOCKS // 2])
def test_shortfall_is_reported_in_bytes(whole_image, tmp_path, blocks):
    """The superblock is the filesystem's own size statement; hold it to it.

    Reported as data rather than raised, because a truncated image is still the
    best evidence available — refusing to open it would throw that away over a
    number ``stat`` already knows.
    """
    whole, _ = whole_image
    cut = _copy_truncated(whole, tmp_path, blocks)
    with Ext4(str(cut)) as fs:
        assert fs.truncated is True
        assert fs.truncated_bytes == (BLOCKS - blocks) * BLOCK_SIZE


@requires_e2fsprogs
def test_one_byte_short_is_still_detected(whole_image, tmp_path):
    """The smallest possible truncation — one byte — must not slip through."""
    whole, _ = whole_image
    cut = _copy_truncated(whole, tmp_path, BLOCKS)
    with open(cut, "r+b") as handle:
        handle.truncate(BLOCKS * BLOCK_SIZE - 1)
    with Ext4(str(cut)) as fs:
        assert fs.truncated is True
        assert fs.truncated_bytes == 1


# --- reads past the cut fail closed ------------------------------------------


@requires_e2fsprogs
def test_reading_past_the_cut_raises_instead_of_returning_zeros(whole_image, tmp_path):
    """The regression this whole file exists for.

    Cutting the image immediately below the file's first data block used to
    produce 4096 bytes of NULs — the declared length, so indistinguishable from
    content — and a SHA-256 of them in the extraction manifest.
    """
    whole, payload = whole_image
    first = _file_extent_block(whole)
    cut = _copy_truncated(whole, tmp_path, first)
    with Ext4(str(cut)) as fs:
        assert fs.truncated is True
        with pytest.raises(TruncatedEvidenceError):
            fs.read(PAYLOAD_PATH)
        # Belt and braces: whatever it raises, it must not hand back the
        # fabricated buffer.  Comparing against zeros is the assertion that
        # would have failed before the fix.
        try:
            blob = fs.read(PAYLOAD_PATH)
        except TruncatedEvidenceError:
            return
        assert blob != bytes(len(payload)), "reader zwrócił same zera"
        assert blob != payload


@requires_e2fsprogs
def test_partially_cut_file_is_not_a_partial_success(whole_image, tmp_path):
    """Three of four data blocks present still means the file is unreadable.

    Returning the readable prefix would be worse than refusing: the caller would
    record a short file as the file, and the four missing bytes would be nobody's
    problem.
    """
    whole, _ = whole_image
    first = _file_extent_block(whole)
    cut = _copy_truncated(whole, tmp_path, first + 3)
    with Ext4(str(cut)) as fs:
        with pytest.raises(TruncatedEvidenceError):
            fs.read(PAYLOAD_PATH)


@requires_e2fsprogs
def test_truncated_metadata_is_not_a_valid_filesystem(whole_image, tmp_path):
    """Cut inside the first kilobyte: nothing claims to be a filesystem yet.

    This is the one short read that is *not* truncation — there is no superblock
    to contradict — so it stays an ``Ext4Error`` and keeps its own wording.
    """
    whole, _ = whole_image
    cut = _copy_truncated(whole, tmp_path, 1)
    with pytest.raises(Ext4Error) as caught:
        Ext4(str(cut))
    assert "superklock" in str(caught.value).lower() or "superblock" in str(caught.value).lower()


@requires_e2fsprogs
def test_empty_file_is_not_a_filesystem(whole_image, tmp_path):
    whole, _ = whole_image
    cut = _copy_truncated(whole, tmp_path, 0)
    with pytest.raises(Ext4Error):
        Ext4(str(cut))


@requires_e2fsprogs
def test_truncation_error_is_not_caught_as_a_format_error(whole_image, tmp_path):
    """``except Ext4Error`` must not be able to swallow missing evidence.

    Modules catch ``Ext4Error`` to say "this is not an ext4 I can read". If
    truncation were a subclass, one ``except`` arm would report a broken format
    for a filesystem whose first half is perfectly legible.
    """
    assert not issubclass(TruncatedEvidenceError, Ext4Error)
    whole, _ = whole_image
    cut = _copy_truncated(whole, tmp_path, _file_extent_block(whole))
    with Ext4(str(cut)) as fs:
        with pytest.raises(TruncatedEvidenceError):
            fs.read(PAYLOAD_PATH)


# --- absent and truncated are different findings ------------------------------


@requires_e2fsprogs
def test_absent_and_truncated_are_different_findings(whole_image, tmp_path):
    """The distinction a report depends on, checked through the real module.

    A path past the cut and a path the device never had used to produce the same
    finding — *"Brak ścieżki"* — which reads as a clean negative. The manifest
    now carries ``status`` per item and the two must not collapse.
    """
    from forensic.core.config import Config
    from forensic.core.session import Ctx

    whole, payload = whole_image
    cut = _copy_truncated(whole, tmp_path, _file_extent_block(whole))
    ctx = Ctx(
        config=Config(image=str(cut), workdir=str(tmp_path / "work"), case="trunc"),
        color=False,
    )
    result = extract_file.run(
        ctx, {"path": f"{PAYLOAD_PATH},/evidence/not-there.bin", "sidecars": False}
    )
    items = {item["source_path"]: item for item in result.data["items"]}

    missing = items["/evidence/not-there.bin"]
    assert missing["status"] == extract_file.STATUS_ABSENT, missing

    unreadable = items[PAYLOAD_PATH]
    assert unreadable["status"] == extract_file.STATUS_TRUNCATED, unreadable
    # The one thing that must never happen: a truncated file recorded as
    # extracted, with a hash of zeros in the manifest.
    assert "sha256" not in unreadable, unreadable
    assert "output" not in unreadable, unreadable

    assert result.data["present"] == 0
    assert result.data["truncated"] == 1
    assert result.data["image_truncated_bytes"] > 0


@requires_e2fsprogs
def test_materialise_uses_the_same_names(whole_image, tmp_path):
    """``Ctx.materialise`` had its own copy of the flattening, and it collided.

    Same defect, second call site: it wrote ``work/<case>/extracted/<flattened>``
    with the substitution written inline, so the two sources above would have
    landed in one file there too.  Both call sites now share
    :mod:`forensic.core.naming`, and this is the assertion that keeps them
    sharing it.
    """
    from forensic.core.config import Config
    from forensic.core.naming import safe_name
    from forensic.core.session import Ctx

    whole, _ = whole_image
    image = _private_image(whole, tmp_path)
    ctx = Ctx(
        config=Config(image=str(image), workdir=str(tmp_path / "work"), case="mat"),
        color=False,
    )
    _run(_tool("debugfs"), "-w", "-R", "mkdir /a", str(image))
    nested = tmp_path / "nested.bin"
    nested.write_bytes(b"NESTED" * 64)
    _run(_tool("debugfs"), "-w", "-R", f"write {nested} /a/b", str(image))
    other = tmp_path / "other.bin"
    other.write_bytes(b"OTHER" * 64)
    _run(_tool("debugfs"), "-w", "-R", f"write {other} /a_b", str(image))

    first = ctx.materialise("/a/b")
    second = ctx.materialise("/a_b")
    assert first != second
    assert first.name == safe_name("/a/b")
    assert second.name == safe_name("/a_b")
    assert first.read_bytes() == b"NESTED" * 64
    assert second.read_bytes() == b"OTHER" * 64


@requires_e2fsprogs
def test_extraction_names_survive_a_batch_with_a_flattening_collision(
    whole_image, tmp_path
):
    """Two sources, two files on disk, two hashes that match their own bytes."""
    from forensic.core.config import Config
    from forensic.core.session import Ctx

    whole, _ = whole_image
    image = _private_image(whole, tmp_path, name="batch.img")
    ctx = Ctx(
        config=Config(image=str(image), workdir=str(tmp_path / "work"), case="batch"),
        color=False,
    )
    # The pair that flattens to one name: a file at /a/b and a file at /a_b.
    # Both exist, and both must come out as two files.
    _run(_tool("debugfs"), "-w", "-R", "mkdir /a", str(image))
    nested = tmp_path / "nested.bin"
    nested.write_bytes(b"NESTED-FILE-CONTENT" * 8)
    _run(_tool("debugfs"), "-w", "-R", f"write {nested} /a/b", str(image))
    second = tmp_path / "second.bin"
    second.write_bytes(b"SECOND-FILE-CONTENT" * 8)
    _run(
        _tool("debugfs"),
        "-w",
        "-R",
        f"write {second} /a_b",
        str(image),
    )
    result = extract_file.run(ctx, {"path": "/a/b,/a_b", "sidecars": False})

    outputs = [item["output"] for item in result.data["items"] if item["status"] == "PRESENT"]
    assert len(outputs) == 2, result.data["items"]
    assert len(set(outputs)) == 2, f"dwa źródła w jednym pliku: {outputs}"
    # Each manifest entry must describe the file it names.
    import hashlib

    on_disk = set()
    for item in result.data["items"]:
        if item["status"] != "PRESENT":
            continue
        blob = Path(item["output"]).read_bytes()
        assert hashlib.sha256(blob).hexdigest() == item["sha256"], item
        on_disk.add(blob)
    assert on_disk == {b"NESTED-FILE-CONTENT" * 8, b"SECOND-FILE-CONTENT" * 8}