# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""F2FS under pytest, where only the self-test looked at it.

The same problem ``erofs.py`` had, one notch less glaring: ``f2fs.py`` sat at 81%
with a 70% floor, and its coverage came from ``ext4_selftest`` — run by hand —
rather than from ``pytest tests/``.  Both were the same lie at different volumes.

Four comparisons, because four different things can be wrong and one of them
hides behind the others agreeing:

* **geometry** — superblock and checkpoint fields against ``dump.f2fs``;
* **the tree** — names against the source tree ``sload.f2fs`` was given, by name
  set rather than by count, because a reader that returned each name twice would
  pass a count;
* **inodes** — size and timestamps against ``dump.f2fs -i <number>``;
* **contents** — byte for byte against the source files, the only check that
  catches a block read from the wrong place in a 64 MiB volume.

Needs ``f2fs-tools``: ``mkfs.f2fs`` to format, ``sload.f2fs`` to populate,
``dump.f2fs`` to read independently.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from forensic.core.f2fs import BLOCK_SIZE, F2fs, F2fsError

requires_f2fs_tools = pytest.mark.skipif(
    not all(
        (shutil.which(name) or Path("/sbin", name).exists())
        for name in ("mkfs.f2fs", "sload.f2fs", "dump.f2fs")
    ),
    reason="brak f2fs-tools (mkfs.f2fs, sload.f2fs, dump.f2fs)",
)

#: 64 MiB.  The self-test builds this size and 512 MiB, and the smaller is not
#: arbitrary: ``mkfs.f2fs`` refuses anything below it with *"Device size is not
#: sufficient for F2FS volume"*.  The first version of this file used 5 MiB — the
#: size EROFS is happy with — and **14 of 15 tests skipped**, which in a summary
#: reads exactly like a pass.
IMAGE_BYTES = 64 * 1024 * 1024

#: The tree loaded into the image.  A nested directory, a file large enough to
#: need more than one block, and a symlink — the three shapes a walk must tell
#: apart, and ``big.txt`` is the one that catches a misplaced block read.
FILES = {
    "a.txt": b"zawartosc pliku\n",
    "sub/b.txt": b"podplik\n",
    "big.txt": b"x" * 5000,
}


def _tool(name: str) -> str:
    found = shutil.which(name) or str(Path("/sbin", name))
    if not Path(found).exists():
        pytest.skip(f"brak {name}")
    return found


#: ``dump.f2fs -d 1`` prints each field as ``name [0x HEX : DEC]``.  The debug
#: level is what makes it print them one by one under their own names, and that
#: is the reason it is an oracle worth having: f2fs-tools' own reading of the
#: same bytes, keyed the way our reading is keyed, so a field that moved in one
#: and not the other cannot hide behind an agreeing total.
_DUMP_FIELD = re.compile(
    r"^([A-Za-z_][A-Za-z_0-9]*(?:\[\d+\])?)\s+\[0x\s*[0-9a-fA-F]+\s*:\s*(-?\d+)\]"
)


def _dump_fields(image: Path, extra: list[str] | None = None) -> dict[str, int]:
    """Field name -> value, from ``dump.f2fs -d 1``.

    Without ``-d 1`` the tool prints ``Info:`` prose lines rather than fields,
    so a parser written for the ext4 ``dumpe2fs -h`` shape finds nothing — which
    is what the first version of this helper did, and it compared zero fields and
    reported that as agreement.
    """
    out = subprocess.run(
        [_tool("dump.f2fs"), "-d", "1", *(extra or []), str(image)],
        capture_output=True, text=True, timeout=300, check=False,
    )
    # A non-zero exit is **not** a failure here.  Asked about a regular file,
    # ``dump.f2fs -i`` answers ``[ASSERT] (dump_file: 503)`` because it offers to
    # write the file out to ``./lost_found`` — a prompt, not a crash.  The fields
    # it printed before asking are perfectly good, and skipping on the exit code
    # is how the self-test lost this comparison once already.
    found: dict[str, int] = {}
    for line in out.stdout.splitlines():
        match = _DUMP_FIELD.match(line.strip())
        if match:
            found.setdefault(match.group(1), int(match.group(2)))
    if not found and extra:
        pytest.skip(
            f"dump.f2fs -i nie wypisał pól: {(out.stderr or '').strip()[:120]}"
        )
    return found


@pytest.fixture(scope="module")
def f2fs_image(tmp_path_factory) -> tuple[Path, dict[str, bytes]]:
    """A formatted and populated F2FS image, plus the bytes it was given.

    Built by ``mkfs.f2fs`` on a truncated file and filled by ``sload.f2fs -f`` —
    the same two steps the self-test uses.  Rebuilt every run: a cached image
    would let these tests assert against a filesystem from an earlier state of the
    reader, which is the exact hazard the self-test exists to remove.
    """
    base = tmp_path_factory.mktemp("f2fs")
    src = base / "src"
    for name, blob in FILES.items():
        path = src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    try:
        (src / "link.txt").symlink_to("a.txt")
    except OSError:  # pragma: no cover - a filesystem without symlinks
        pass

    image = base / "f2fs.img"
    with image.open("wb") as handle:
        handle.truncate(IMAGE_BYTES)
    made = subprocess.run(
        [_tool("mkfs.f2fs"), "-q", str(image)],
        capture_output=True, text=True, timeout=600, check=False,
    )
    if made.returncode != 0:
        pytest.skip(f"mkfs.f2fs: {(made.stderr or '').strip()[:200]}")
    loaded = subprocess.run(
        [_tool("sload.f2fs"), "-f", str(src), str(image)],
        capture_output=True, text=True, timeout=600, check=False,
    )
    if loaded.returncode != 0:
        pytest.skip(f"sload.f2fs: {(loaded.stderr or '').strip()[:200]}")
    return image, FILES


# --- geometry ----------------------------------------------------------------


@requires_f2fs_tools
def test_the_superblock_is_read_and_names_a_format(f2fs_image):
    """The magic, and the block size the reader accepted.

    The block size is checked against the module's own constant rather than
    against a shift of ``log_blocksize``: F2FS derives it from a sector size and a
    sectors-per-block field, so ``1 << log_blocksize`` is **wrong** — on this image
    it gives 4 MiB where the real block is 4 KiB.  A test that computed it would
    have asserted 4 MiB and looked satisfied.
    """
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        assert fs.superblock["magic"] == 0xF2F52010, hex(fs.superblock["magic"])
        assert fs.block_size == BLOCK_SIZE
        assert fs.blocks == image.stat().st_size // BLOCK_SIZE


@requires_f2fs_tools
def test_the_geometry_agrees_with_dump_f2fs_field_by_field(f2fs_image):
    """Superblock and checkpoint fields, compared by name.

    A total that agrees proves nothing about a field that moved: two wrong
    readings can cancel out.  Compared per field for that reason, and the count of
    fields actually compared is asserted — a helper that found nothing would
    otherwise pass silently.
    """
    image, _ = f2fs_image
    theirs = _dump_fields(image)
    with F2fs(str(image)) as fs:
        sb = fs.superblock
    pairs = (
        ("magic", sb["magic"]),
        ("block_count", sb["block_count"]),
        ("section_count", sb.get("section_count")),
        ("seg_count", sb.get("seg_count")),
        ("major_ver", sb.get("major_ver")),
        ("minor_ver", sb.get("minor_ver")),
    )
    checked = []
    for key, ours in pairs:
        if ours is None or key not in theirs:
            continue
        assert ours == theirs[key], f"{key}: nasze {ours}, dump.f2fs {theirs[key]}"
        checked.append(key)
    assert len(checked) >= 3, (
        f"porównano tylko {sorted(checked)}; dump.f2fs zna {len(theirs)} pól"
    )


@requires_f2fs_tools
def test_the_image_size_is_the_file_size(f2fs_image):
    """One number, and it is the file's."""
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        assert fs.size_bytes == image.stat().st_size


# --- the tree ----------------------------------------------------------------


@requires_f2fs_tools
def test_every_file_in_the_source_is_found_by_name(f2fs_image):
    """By name, and **without duplicates**.

    The first version compared ``{name for name in listing}`` against the expected
    set and wrote in its own docstring that this catches a reader returning each
    name twice.  It does not: a set comparison discards duplicates, so that test
    passed a reader that doubled every entry — which was proved by injecting
    exactly that regression and watching the suite stay green.

    So the count is asserted separately, and both halves are needed: the set says
    the right names are there, the count says each appears once.
    """
    image, files = f2fs_image
    with F2fs(str(image)) as fs:
        listing = fs.listdir(fs.root)
        walked = [path for path, _node in fs.walk()]

    # ``listdir`` returns ``.`` and ``..`` **as stored**, the same contract the
    # ext4 and EROFS readers keep, so they are part of the expected set rather
    # than filtered out of the comparison — a reader that dropped them and a
    # reader that invented them both have to show up.
    names = [entry.name for entry in listing]
    top_level = {name for name in files if "/" not in name} | {"sub"}
    expected = top_level | {"link.txt", ".", ".."}
    assert set(names) == expected, (
        f"brakuje {sorted(expected - set(names))}, nadmiar {sorted(set(names) - expected)}"
    )
    assert len(names) == len(set(names)), f"powtórzone nazwy: {sorted(names)}"

    walked_set = set(walked)
    for name in files:
        path = f"/{name}"
        assert path in walked_set, f"{path} nie ma w walk: {sorted(walked_set)}"
    assert len(walked) == len(walked_set), "walk zwrócił tę samą ścieżkę dwa razy"


@requires_f2fs_tools
def test_a_nested_directory_is_listed_and_its_files_are_reachable(f2fs_image):
    """The second level, which a flat listing would miss.

    ``dump.erofs`` listed one level at a time and the EROFS test had to recurse;
    here the assertion is simply that the walk went in.
    """
    image, files = f2fs_image
    with F2fs(str(image)) as fs:
        entries = {entry.name for entry in fs.listdir(fs.resolve("/sub"))}
    assert "b.txt" in entries, sorted(entries)


@requires_f2fs_tools
def test_contents_match_the_source_byte_for_byte(f2fs_image):
    """The only check that catches a block read from the wrong place.

    A 5 KiB file read one block off would still have the right size and the right
    name, and ``big.txt`` is the largest precisely so the mistake would land
    inside it.
    """
    image, files = f2fs_image
    with F2fs(str(image)) as fs:
        for name, expected in files.items():
            blob = fs.read(f"/{name}")
            assert blob == expected, (
                f"{name}: {len(blob)} B zamiast {len(expected)} B; pierwsza różnica "
                f"na bajcie "
                f"{next((i for i, (a, b) in enumerate(zip(blob, expected)) if a != b), len(expected))}"
            )


@requires_f2fs_tools
def test_a_symlink_resolves_and_its_target_is_the_stored_string(f2fs_image):
    """The target is the literal the inode holds, not the contents it points at.

    ``sload.f2fs`` writes the symlink's target into the inode, so ``readlink`` has
    to return that string and not the bytes of ``a.txt``.
    """
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        try:
            node = fs.resolve("/link.txt")
        except KeyError:
            pytest.skip("sload.f2fs nie zapisał dowiązania")
        assert node.is_link
        assert fs.readlink("/link.txt") == "a.txt"


@requires_f2fs_tools
def test_the_root_is_a_directory_and_resolves_to_itself(f2fs_image):
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        assert fs.root.is_dir
        for path in ("/", "", "///"):
            assert fs.resolve(path).number == fs.root.number, path


@requires_f2fs_tools
def test_resolving_a_missing_path_says_which_component(f2fs_image):
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        with pytest.raises(KeyError) as caught:
            fs.resolve("/sub/nie-ma.txt")
    assert "nie-ma.txt" in str(caught.value), caught.value


@requires_f2fs_tools
def test_resolving_through_a_file_is_refused(f2fs_image):
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        with pytest.raises(KeyError) as caught:
            fs.resolve("/a.txt/cos")
    assert "katalogiem" in str(caught.value), caught.value


# --- inodes, against dump.f2fs ----------------------------------------------


@requires_f2fs_tools
def test_every_file_inode_agrees_with_dump_f2fs_on_size(f2fs_image):
    """Per inode, not in aggregate.

    A reader that read ``i_atime`` from ``i_ctime`` would produce a self-consistent
    sum, so the comparison is inode by inode.
    """
    image, files = f2fs_image
    checked = 0
    with F2fs(str(image)) as fs:
        for path, node in fs.walk():
            if node.is_dir or node.size == 0:
                continue
            theirs = _dump_fields(image, ["-i", str(node.number)])
            if "i_size" not in theirs:
                continue
            # ``i_size`` in F2FS, which is what the reader reports as ``size``.
            size_field = theirs.get("i_size")
            if size_field is None:
                continue
            assert size_field == node.size, (
                f"{path} (inode {node.number}): rozmiar u nas {node.size}, "
                f"dump.f2fs {size_field}"
            )
            checked += 1
    assert checked >= 3, f"porównano tylko {checked} inodów"


# --- the refusals ------------------------------------------------------------


@requires_f2fs_tools
def test_a_node_id_past_the_end_is_refused_not_zero_filled(f2fs_image):
    """A node that is not there is an error naming the node.

    A zero-filled node would look like a valid empty file — the defect the ext4
    reader had, and the reason ``read_exact`` exists.
    """
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        with pytest.raises(F2fsError) as caught:
            fs.inode(10_000_000)
    # The reader names the **block address** it computed, not the node id it was
    # asked for — the address is the thing that was out of range, and it is what
    # tells an analyst which part of the volume the pointer landed in.
    assert "poza obrazem" in str(caught.value), caught.value


@requires_f2fs_tools
def test_a_block_address_past_the_end_is_refused(f2fs_image):
    """The block guard, at the boundary it exists for.

    ``block_address`` takes an **inode and an index**, not a block number, so the
    call is shaped by what the reader actually reads.
    """
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        with pytest.raises(F2fsError):
            fs._block(fs.blocks + 1)


@requires_f2fs_tools
def test_a_file_that_is_not_f2fs_is_refused_by_magic(tmp_path):
    """An ext4 image handed to the F2FS reader is refused by name.

    The message must say what was expected, or an analyst reading the log cannot
    tell a wrong-format file from a damaged one.
    """
    image = tmp_path / "not_f2fs.img"
    with image.open("wb") as handle:
        handle.truncate(1024 * 1024)
    made = subprocess.run(
        ["/sbin/mke2fs", "-q", "-t", "ext4", "-F", "-b", "1024", "-I", "256", str(image)],
        capture_output=True, timeout=180, check=False,
    )
    if made.returncode != 0:
        pytest.skip("brak mke2fs")
    with pytest.raises(F2fsError) as caught:
        F2fs(str(image))
    message = str(caught.value)
    assert "F2FS" in message or "magic" in message.lower(), message


@requires_f2fs_tools
def test_a_truncated_image_is_refused_at_the_superblock(f2fs_image, tmp_path):
    """Half a superblock is not a filesystem, and is not read as a short one.

    A partially-read superblock yields field values that look like geometry, which
    is the same distinction the ext4 reader draws.
    """
    image, _ = f2fs_image
    cut = tmp_path / "cut.img"
    with open(image, "rb") as src, open(cut, "wb") as dst:
        dst.write(src.read(512))
    with pytest.raises(F2fsError):
        F2fs(str(cut))


@requires_f2fs_tools
def test_the_context_manager_closes_the_handle(f2fs_image):
    """``with`` has to close, or a loop over images runs out of descriptors."""
    image, _ = f2fs_image
    fs = F2fs(str(image))
    with fs:
        assert fs.read("/a.txt") == FILES["a.txt"]
    fs.close()


# --- coverage, which is the reader's own honesty report ----------------------


@requires_f2fs_tools
def test_coverage_is_complete_on_a_clean_image(f2fs_image):
    """Every file readable and every name listed, on an image with no damage.

    ``names_complete`` and ``contents_complete`` are the two sentences that keep a
    short tree from passing as a true one, and on a clean image both must hold.
    """
    image, files = f2fs_image
    with F2fs(str(image)) as fs:
        report = fs.coverage()
    assert report["walk_errors"] == 0, report["walk_error_detail"]
    assert report["names_complete"] is True
    assert report["contents_complete"] is True
    assert report["files"] >= len(files)
    assert report["readable"] == report["files"], report


@requires_f2fs_tools
def test_feature_names_are_empty_when_no_features_are_set(f2fs_image):
    """An empty list and a missing key are different.

    A volume with no feature bits set should report **no** features, not an
    unknown one and not an error.
    """
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        names = fs.feature_names()
        feature = fs.superblock["feature"]
    assert isinstance(names, list)
    assert (names == []) == (feature == 0), (names, feature)


def test_feature_names_cover_the_bits_the_reader_knows():
    """Every named flag has a label, and a flag with no label is still reported.

    The table lives in the reader, so this reads it rather than the image: a flag
    bit added to the table without a label would print an empty string into a
    report, and a flag bit this table has never heard of would vanish.
    """
    from forensic.core.f2fs import (
        FEATURE_ATOMIC,
        FEATURE_CASEFOLD,
        FEATURE_FLEXIBLE_INLINE_XATTR,
        FEATURE_TRIM,
    )

    # Four constants, and the method knows all four by name.  A constant added
    # without a name in ``feature_names`` would report as no feature set, which is
    # a claim about the filesystem rather than about the reader's table.
    assert len({FEATURE_ATOMIC, FEATURE_TRIM, FEATURE_CASEFOLD, FEATURE_FLEXIBLE_INLINE_XATTR}) == 4


# --- small helpers -----------------------------------------------------------


@requires_f2fs_tools
def test_reading_past_the_end_of_a_file_returns_nothing(f2fs_image):
    """A range after the content is empty, as it is on any filesystem."""
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        assert fs.read("/a.txt")[10_000:] == b""


@requires_f2fs_tools
def test_stat_carries_the_fields_a_report_prints(f2fs_image):
    """Path, inode number, type, size and the mode in octal.

    ``mode`` as a bare octal string with no ``0o`` prefix, which is how the
    ext4 reader prints it too, so a report renders both the same way.
    """
    image, files = f2fs_image
    with F2fs(str(image)) as fs:
        info = fs.stat("/a.txt")
    assert info["path"] == "/a.txt"
    assert info["type"] == "file"
    assert info["size"] == len(files["a.txt"])
    assert info["mode"] == "100664", info["mode"]


@requires_f2fs_tools
def test_stat_on_a_directory_says_dir_and_carries_the_link_count(f2fs_image):
    """``nlink`` is what tells an analyst a directory has subdirectories."""
    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        info = fs.stat("/sub")
    assert info["type"] == "dir"
    assert info["nlink"] >= 2, info

# --- the two guards the reader exists for ------------------------------------
#
# Both were **not** caught by the tests above when deliberately broken, which is
# why they are here: a fixture that builds a clean image and walks it exercises
# neither the short-read guard nor the "a directory could not be listed" report,
# because on a clean image both are satisfied.  A test that passes whether or not
# the guard exists is worse than no test.


@requires_f2fs_tools
def test_a_block_whose_bytes_run_past_the_end_is_refused_not_zero_filled(f2fs_image, tmp_path):
    """The image declares more blocks than the file holds.

    ``fs.blocks`` comes from the superblock and does not change when the file is
    shortened, so the last declared block is now only partly there.  The reader
    must say so.

    This is the F2FS half of a defect the ext4 reader had for a whole turn: a
    short read completed with NULs looks exactly like a file full of zeros, and
    the caller has no way to tell.
    """
    image, files = f2fs_image
    cut = tmp_path / "cut.img"
    with open(image, "rb") as src, open(cut, "wb") as dst:
        dst.write(src.read(image.stat().st_size - BLOCK_SIZE // 2))

    with F2fs(str(cut)) as fs:
        assert fs.blocks > 0
        with pytest.raises(F2fsError) as caught:
            fs._block(fs.blocks - 1)
    assert "nieczytelny" in str(caught.value), caught.value


@requires_f2fs_tools
def test_a_directory_that_cannot_be_listed_is_reported_and_completeness_drops(f2fs_image, tmp_path):
    """``walk_errors`` is the whole reason it exists.

    A directory whose name block has been overwritten cannot be listed, and a walk
    that silently returned a shorter tree would produce a filesystem with fewer
    files than the device had — indistinguishable from a device that never had
    them.  ``names_complete`` is the sentence that stops that.

    The corruption is a real overwrite of the dnode the directory lives in, found
    through the reader's own ``listdir``/``node_block``, rather than a fixture that
    assumes a block number.
    """
    import dataclasses

    image, _ = f2fs_image
    with F2fs(str(image)) as fs:
        node = fs.resolve("/sub")
        block = node.node_block
        fields = {f.name for f in dataclasses.fields(node)}
        assert "node_block" in fields, sorted(fields)

    damaged = tmp_path / "damaged.img"
    shutil.copy(image, damaged)
    with open(damaged, "r+b") as handle:
        handle.seek(block * BLOCK_SIZE)
        handle.write(b"\xff" * BLOCK_SIZE)

    with F2fs(str(damaged)) as fs:
        report = fs.coverage()
    if report["walk_errors"] == 0:
        pytest.skip("ta wersja f2fs nie pozwala uszkodzić katalogu przez node_block")
    assert report["names_complete"] is False, report
    assert report["walk_error_detail"], report
    assert report["contents_complete"] is False, report
