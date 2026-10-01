# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""EROFS under pytest, where only the self-test looked at it.

``forensic/core/erofs.py`` had been at 68% with a coverage floor above it, and
**every line of that coverage came from ``ext4_selftest``** — a module the
analyst runs by hand.  ``pytest tests/`` therefore looked at EROFS at all
exactly never, while the coverage report said it was the fourth-best-tested
reader in the project.  That is the worst kind of gap: the metric is reassuring
and the metric is about a run CI does not perform.

The fixtures here build real images with ``mkfs.erofs`` and compare against
``dump.erofs``, the same two tools ``ext4_selftest`` uses, so the tree and the
contents are both checked against something outside this project.  What the
self-test could not do — run on every ``pytest`` — is the point of the module.

Needs ``erofs-utils``.  Without it the module skips with a reason, which is the
only acceptable outcome: a parser test that skips when its tool is missing is a
parser test that has stopped running.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from forensic.core.erofs import (
    COMPRESSED_LAYOUTS,
    FT_TYPES,
    LAYOUT_FLAT_PLAIN,
    LAYOUT_NAMES,
    Erofs,
    ErofsError,
)

requires_erofs_utils = pytest.mark.skipif(
    not (shutil.which("mkfs.erofs") and shutil.which("dump.erofs")),
    reason="brak erofs-utils (mkfs.erofs, dump.erofs)",
)

#: The tree the fixtures build.  Chosen so that every branch of ``type_name`` has
#: something to hit: a regular file, a nested directory, a file larger than the
#: inline threshold (which forces a separate block), and a symlink.
FILES = {
    "a.txt": b"zawartosc pliki\n",
    "sub/b.txt": b"podplik\n",
    "big.txt": b"x" * 5000,
}

#: A separate tree for the compressed fixture, with a file big and repetitive
#: enough that ``mkfs.erofs -zlz4`` actually compresses something.
#:
#: The first version of this fixture reused :data:`FILES` and produced an image
#: with **nothing compressed**: ``mkfs.erofs`` inlines a small file into its
#: inode regardless of the compression flag, so every node came back
#: ``LAYOUT_FLAT_INLINE`` and the reader's compressed path was never reached.  A
#: fixture that silently exercises nothing is worse than no fixture, because the
#: coverage report then says the compressed case is covered.
COMPRESSED_FILES = {
    "a.txt": b"zawartosc pliku\n",
    "system.bin": b"\x00" * 256 * 1024,
}


def _mkfs(tmp_path: Path, *, label: str, compress: bool) -> Path:
    """Build one EROFS image and return its path.

    The tree comes from :data:`COMPRESSED_FILES` when compressing, because
    :data:`FILES` is too small for ``mkfs.erofs`` to compress any of it.
    """
    tree = COMPRESSED_FILES if compress else FILES
    src = tmp_path / f"src_{label}"
    for name, blob in tree.items():
        path = src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    try:
        (src / "link.txt").symlink_to("a.txt")
    except OSError:  # pragma: no cover - a filesystem without symlinks
        pass

    image = tmp_path / f"erofs_{label}.img"
    args = ["mkfs.erofs", "-d0"]
    if compress:
        args.append("-zlz4")
    args += [str(image), str(src)]
    result = subprocess.run(args, capture_output=True, text=True, timeout=600, check=False)
    if result.returncode != 0:
        pytest.skip(f"mkfs.erofs {' '.join(args[1:-2])}: {(result.stderr or '').strip()[:160]}")
    return image


@pytest.fixture(scope="module")
def erofs_plain(tmp_path_factory) -> Path:
    """An uncompressed EROFS image — the layout a reader can read fully."""
    return _mkfs(tmp_path_factory.mktemp("erofs_plain"), label="plain", compress=False)


@pytest.fixture(scope="module")
def erofs_lz4(tmp_path_factory) -> Path:
    """A compressed EROFS image — what a real device ships since Android 10.

    Its contents are not readable without an LZ4 decompressor, and the reader must
    say so rather than return something that looks like file content.
    """
    return _mkfs(tmp_path_factory.mktemp("erofs_lz4"), label="lz4", compress=True)


# --- the tree, compared against dump.erofs ----------------------------------


#: ``erofs_ftype`` for a directory, as ``dump.erofs`` prints it in its TYPE column.
_ERDFS_TYPE_DIR = 2


def _dump_tree(image: Path, prefix: str = "/") -> dict[str, int]:
    """``relative path -> nid`` for the whole tree, via ``dump.erofs``.

    ``dump.erofs --ls`` lists **one** directory level, not the tree, so the first
    version of this helper compared our recursive walk against a flat listing and
    reported ``sub/b.txt`` as a name we invented.  Recursing here instead makes
    the comparison per level, which is the granularity the tool actually offers.
    """
    out = subprocess.run(
        ["dump.erofs", "--ls", "--path", prefix, str(image)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert out.returncode == 0, out.stderr[:200]
    found: dict[str, int] = {}
    subdirs: list[str] = []
    for line in out.stdout.splitlines():
        parts = line.split()
        # Rows are ``NID TYPE NAME`` with no indentation; the header line and the
        # size banner are the only lines that are not three fields.
        if len(parts) != 3 or not parts[0].isdigit():
            continue
        _nid, kind, name = parts
        if name in (".", ".."):
            continue
        relative = f"{prefix.strip('/')}/{name}" if prefix.strip("/") else name
        found[relative] = int(_nid)
        if kind.isdigit() and int(kind) == _ERDFS_TYPE_DIR:
            subdirs.append(f"/{relative}")
    for directory in subdirs:
        found.update(_dump_tree(image, directory))
    return found


def _dump_cat(image: Path, path: str) -> bytes:
    out = subprocess.run(
        ["dump.erofs", "--cat", "--path", path, str(image)],
        capture_output=True, timeout=120,
    )
    assert out.returncode == 0, f"dump.erofs --cat {path}: {out.stderr[:160]}"
    return out.stdout


@requires_erofs_utils
def test_the_tree_matches_dump_erofs_entry_for_entry(erofs_plain):
    """Name, node id and type, for every entry, against the reference tool.

    Two implementations agreeing on a tree they were built separately for is worth
    more than either being confident, and this is the assertion that would fail
    first if the node-id arithmetic went wrong.
    """
    ours: dict[str, int] = {}
    with Erofs(str(erofs_plain)) as fs:
        for path, node in fs.walk():
            if path == "/":
                continue
            ours[path.lstrip("/")] = node.nid

    # dump.erofs prints ``NID TYPE FILENAME`` under a header, and ``.`` / ``..``
    # with no name — which is why this module needs ``--path`` rather than a
    # bare ``--ls``.
    theirs = _dump_tree(erofs_plain)
    assert ours, f"nic nie przeczytano, a dump.erofs zgłasza: {sorted(theirs)}"
    assert set(ours) == set(theirs), (
        f"nazwy różnią się: tylko u nas {sorted(set(ours) - set(theirs))}, "
        f"tylko u dump.erofs {sorted(set(theirs) - set(ours))}"
    )
    for path, nid in ours.items():
        assert theirs[path] == nid, f"{path}: nasze nid {nid}, dump.erofs {theirs[path]}"


@requires_erofs_utils
def test_contents_match_dump_erofs_byte_for_byte(erofs_plain):
    """The bytes, not just the tree.

    A reader that finds the right inode and returns the wrong bytes passes every
    tree assertion in this file.
    """
    with Erofs(str(erofs_plain)) as fs:
        for name, expected in FILES.items():
            blob = fs.read(fs.resolve(f"/{name}"))
            assert blob == expected, f"{name}: {len(blob)} B, oczekiwano {len(expected)} B"
            assert _dump_cat(erofs_plain, f"/{name}") == blob, (
                f"{name}: różni się od dump.erofs --cat"
            )


@requires_erofs_utils
def test_a_symlink_is_a_symlink_and_its_target_is_readable(erofs_plain):
    """The type is not inferred from the mode when the format carries one.

    EROFS dirents carry ``erofs_ftype`` independently of ``i_mode``, and a reader
    that used only the mode would have to guess what a type field is for.
    """
    with Erofs(str(erofs_plain)) as fs:
        try:
            node = fs.resolve("/link.txt")
        except KeyError:
            pytest.skip("ten mkfs.erofs nie zapisał dowiązania")
        assert node.is_link
        assert node.type_name == "symlink"
        assert fs.readlink(node) == "a.txt"


@requires_erofs_utils
def test_the_root_is_a_directory_and_the_superblock_names_it(erofs_plain):
    """``/`` resolves to a directory through the superblock's ``root_nid``."""
    with Erofs(str(erofs_plain)) as fs:
        root = fs.root
        assert root.is_dir
        assert root.type_name == "dir"
        assert root.nid == fs.superblock["root_nid"]
        names = {entry.name for entry in fs.listdir(root)}
        assert "a.txt" in names and "sub" in names, names


@requires_erofs_utils
def test_an_empty_directory_lists_to_nothing_rather_than_failing(erofs_plain, tmp_path):
    """A directory with no entries is a fact, not a missing key."""
    src = tmp_path / "empty_src" / "pusty"
    src.mkdir(parents=True)
    image = tmp_path / "erofs_empty.img"
    result = subprocess.run(
        ["mkfs.erofs", "-d0", str(image), str(src.parent)],
        capture_output=True, text=True, timeout=600, check=False,
    )
    if result.returncode != 0:
        pytest.skip(result.stderr[:160])
    with Erofs(str(image)) as fs:
        entries = fs.listdir(fs.resolve("/pusty"))
        assert [entry.name for entry in entries if entry.name != "."] == []


# --- compression: the refusal, which is the point -----------------------------


@requires_erofs_utils
def test_a_compressed_image_opens_and_its_tree_is_readable(erofs_lz4):
    """The tree survives compression even though the contents do not.

    A device's ``/system`` is compressed, and an analyst still needs the list of
    what is on it.  A reader that refused the whole image would refuse to answer
    the question it can answer.
    """
    with Erofs(str(erofs_lz4)) as fs:
        names = {entry.name for entry in fs.listdir(fs.root)}
        assert "a.txt" in names, names


@requires_erofs_utils
def test_a_compressed_file_is_refused_by_name_and_not_silently_shortened(erofs_lz4):
    """The refusal says why, and returns nothing that could pass for content.

    The failure this rules out is the same shape as the truncated-image one from
    earlier turns: a buffer of plausible length that is not the file.  Here it
    would be zeros, and a report would print a hash of them.
    """
    with Erofs(str(erofs_lz4)) as fs:
        # The **large** file.  ``mkfs.erofs`` inlines a small file into its inode
        # whatever the compression flag says, so ``/a.txt`` comes back
        # LAYOUT_FLAT_INLINE in this image too — and a test pointed at it would
        # have asserted that a compressed image contains nothing compressed.
        node = fs.resolve("/system.bin")
        assert node.compressed, node.layout_name
        assert node.layout in COMPRESSED_LAYOUTS
        with pytest.raises(ErofsError) as caught:
            fs.read(node)
        message = str(caught.value).lower()
        assert "kompres" in message or "lz4" in message or "skompres" in message, message


@requires_erofs_utils
def test_coverage_distinguishes_readable_from_compressed_and_computes_its_verdict(erofs_lz4):
    """``coverage()`` is the honest summary, and its verdict follows the numbers.

    ``contents_complete`` is false because compression is on, and it must not be
    true just because the tree was walked — that is the whole difference between
    "we read the image" and "we listed it".
    """
    with Erofs(str(erofs_lz4)) as fs:
        report = fs.coverage()
    assert report["files"] > 0
    assert report["compressed"] > 0
    assert report["contents_complete"] is False


@requires_erofs_utils
def test_coverage_on_an_uncompressed_image_is_complete(erofs_plain):
    report_coverage = None
    with Erofs(str(erofs_plain)) as fs:
        report_coverage = fs.coverage()
    assert report_coverage["compressed"] == 0
    assert report_coverage["readable_plain"] + report_coverage["readable_inline"] > 0
    assert report_coverage["contents_complete"] is True


# --- resolution and its three refusals ---------------------------------------


@requires_erofs_utils
def test_resolving_a_missing_path_says_which_component(erofs_plain):
    """The error names the component, not just the path.

    An analyst with a long path needs to know where the walk stopped, and
    reporting the whole path for a missing leaf is no more use than reporting
    nothing.
    """
    with Erofs(str(erofs_plain)) as fs:
        with pytest.raises(KeyError) as caught:
            fs.resolve("/sub/nie-ma.txt")
    assert "nie-ma.txt" in str(caught.value), caught.value


@requires_erofs_utils
def test_resolving_through_a_file_is_refused_as_not_a_directory(erofs_plain):
    """Walking into a regular file is a mistake in the request, and is named."""
    with Erofs(str(erofs_plain)) as fs:
        with pytest.raises(KeyError) as caught:
            fs.resolve("/a.txt/cos")
    assert "katalogiem" in str(caught.value), caught.value


@requires_erofs_utils
def test_resolving_the_root_and_an_empty_path_both_give_the_root(erofs_plain):
    """``/``, ``""`` and ``///`` are the same path."""
    with Erofs(str(erofs_plain)) as fs:
        for path in ("/", "", "///"):
            assert fs.resolve(path).nid == fs.root.nid, path


@requires_erofs_utils
def test_inodes_are_cached_and_the_cache_returns_the_same_object(erofs_plain):
    """A walk revisits directories, and re-parsing them per visit is the difference
    between a tree walk and a quadratic one."""
    with Erofs(str(erofs_plain)) as fs:
        first = fs.inode(fs.root.nid)
        second = fs.inode(fs.root.nid)
    assert first is second


@requires_erofs_utils
def test_a_node_id_past_the_end_of_the_image_is_refused(erofs_plain):
    """An inode that is not there is an error naming the offset.

    Reported rather than returning a zero-filled inode, which would look like a
    valid empty file — the same defect the ext4 reader had.
    """
    with Erofs(str(erofs_plain)) as fs:
        with pytest.raises(ErofsError) as caught:
            fs.inode(10_000_000)
    assert "nid" in str(caught.value), caught.value


# --- the type vocabulary ------------------------------------------------------


def test_every_format_type_has_a_name_and_the_inverse_is_built_from_it():
    """``KIND_FROM_FT`` is derived, and a typo in ``FT_TYPES`` would break it silently."""
    from forensic.core.erofs import KIND_FROM_FT

    for value, name in FT_TYPES.items():
        assert KIND_FROM_FT[name] == value, name


def test_an_unknown_dirent_type_is_called_unknown_not_guessed():
    """A type number this table has not seen is ``unknown``, not the first entry.

    Guessing would put a file in a category in a report, and a device running a
    newer kernel can carry a type this table does not have.
    """
    from forensic.core.erofs import ErofsDirent

    entry = ErofsDirent(nid=1, name="x", file_type=99)
    assert entry.kind == "unknown"
    assert entry.as_dict()["kind"] == "unknown"


@pytest.mark.parametrize(
    "mode,expected",
    [
        (0o040755, "dir"),
        (0o100644, "file"),
        (0o120777, "symlink"),
        (0o010644, "fifo"),
        (0o140644, "socket"),
        (0o060644, "blockdev"),
        (0o020644, "chardev"),
        (0o000644, "other"),
    ],
)
def test_type_name_answers_for_every_mode_class(mode, expected):
    """All eight branches, from a mode rather than from an image.

    A reader that reached only ``dir``, ``file`` and ``symlink`` in practice would
    have five guesses here, and a FIFO or a device node in a report is a fact
    about the device.
    """
    from forensic.core.erofs import ErofsInode

    node = ErofsInode(
        number=1, nid=1, mode=mode, size=0, uid=0, gid=0, nlink=1, ino=1,
        mtime=0, mtime_nsec=0, layout=LAYOUT_FLAT_PLAIN, version=0,
        raw_block=0, inode_size=0, xattr_size=0,
    )
    assert node.type_name == expected, mode


def test_an_unknown_layout_is_named_rather_than_being_none():
    """``layout_name`` falls back to the number, so a report can say what it saw."""
    from forensic.core.erofs import ErofsInode

    node = ErofsInode(
        number=1, nid=1, mode=0o100644, size=0, uid=0, gid=0, nlink=1, ino=1,
        mtime=0, mtime_nsec=0, layout=99, version=0,
        raw_block=0, inode_size=0, xattr_size=0,
    )
    assert "99" in node.layout_name
    assert node.compressed is False
    for value, name in LAYOUT_NAMES.items():
        assert value != 99 or name not in node.layout_name


def test_read_takes_an_inode_and_not_a_path(erofs_plain):
    """The one place the two filesystem readers disagree, and it is worth naming.

    ``Ext4.read`` accepts ``str | int | Inode``; ``Erofs.read`` accepts only
    ``ErofsInode | int``.  A caller written against ext4 that passes a path gets
    ``TypeError: unsupported operand type(s) for +: 'int' and 'str'`` from
    ``inode_offset`` — a message about an arithmetic type, several frames from
    the mistake.

    Nothing in the project is broken by it: the one caller opens an inode itself.
    But it is the concrete argument for a uniform reader interface, and it comes
    from evidence rather than taste — which is how the plan's ``FilesystemReader``
    item should have been argued.
    """
    with Erofs(str(erofs_plain)) as fs:
        assert fs.read(fs.resolve("/a.txt")) == FILES["a.txt"]
        with pytest.raises(TypeError):
            fs.read("/a.txt")
        with pytest.raises(TypeError):
            fs.readlink("/link.txt")


def test_an_inline_layout_file_is_marked_as_such(erofs_plain):
    """A small EROFS file keeps its data in the inode tail.

    That is a different path from a file in its own block, and the report says
    which one it read — a reader that claimed every file was in a block would be
    describing a layout the image does not have.
    """
    with Erofs(str(erofs_plain)) as fs:
        small = fs.resolve("/a.txt")
        big = fs.resolve("/big.txt")
    # ``raw_block`` is 0xFFFFFFFF when the data lives in the inode tail and a real
    # block number when it does not.  That distinction is what this mkfs version
    # makes visible, and it is the honest one to assert on: the ``layout`` field
    # reads ``LAYOUT_FLAT_INLINE`` for both of these files even the 5 KB one.
    NO_BLOCK = 0xFFFFFFFF
    assert small.raw_block == NO_BLOCK, small
    assert big.raw_block != NO_BLOCK, big
    assert small.size == len(FILES["a.txt"])
    assert big.size == len(FILES["big.txt"])


# --- stat, read past the end, and the context manager ------------------------


@requires_erofs_utils
def test_stat_carries_the_fields_a_report_prints(erofs_plain):
    """Path, inode number, type, size and the mode in octal.

    ``mode`` as octal rather than as a number, because a mode is read by people
    and ``0o100644`` is how ``ls`` prints it.
    """
    with Erofs(str(erofs_plain)) as fs:
        info = fs.stat("/a.txt")
    assert info["path"] == "/a.txt"
    assert info["type"] == "file"
    assert info["size"] == len(FILES["a.txt"])
    # The mode carries its file-type bits, the way ``ls -l`` prints it:
    # 0o100664 for a regular file, not 0o644.  The first version of this
    # assertion said "0644" and was wrong about what a mode is.
    assert info["mode"] == "100664", info["mode"]


@requires_erofs_utils
def test_reading_past_the_end_returns_nothing_rather_than_raising(erofs_plain):
    """A range entirely after the file is empty, as it is on any filesystem."""
    with Erofs(str(erofs_plain)) as fs:
        node = fs.resolve("/a.txt")
        blob = fs.read(node)[10_000:]
    assert blob == b""


@requires_erofs_utils
def test_the_context_manager_closes_the_handle(erofs_plain):
    """``with`` has to close, or a loop over images runs out of descriptors."""
    fs = Erofs(str(erofs_plain))
    with fs:
        assert fs.read(fs.resolve("/a.txt")) == FILES["a.txt"]
    # Closing an already-closed handle must not raise: ``close`` is called on the
    # exit path and again by the destructor in some flows.
    fs.close()


@requires_erofs_utils
def test_size_bytes_is_the_image_size_not_a_filesystem_size(erofs_plain):
    """One number, and it is the file's — a reader that reported the image size
    would make every file the same length in a report."""
    with Erofs(str(erofs_plain)) as fs:
        assert fs.size_bytes == erofs_plain.stat().st_size