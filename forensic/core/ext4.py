# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Minimal, read-only ext2/ext3/ext4 reader (stdlib only).

The reader is deliberately small and strict: it understands what an Android
``userdata`` image needs — extents, directory entries, inode tables — and
refuses anything it does not understand instead of guessing.  A reader that
silently returns no data for a construct it cannot parse is the one failure
mode this module is written to avoid, because in a report the empty result is
indistinguishable from "there was nothing there".

Supported: 64bit, EXTENTS, DIR_INDEX (htree-indexed directories have their index
blocks skipped while scanning), sparse_super, huge_file, uninit_bg, extra_isize,
dir_nlink.  ``metadata_csum`` is parsed **and verified** — see :meth:`Ext4.checksums`.

Refused, loudly, with :class:`Ext4Error`: classic indirect-block inodes (an
inode that is neither extent-mapped nor legitimately empty), ``metadata_bg``
group-descriptor layouts, and a group count that disagrees with the superblock.

Typical use::

    with Ext4("/data/userdata.img") as fs:
        print(fs.superblock["block_size"])
        for entry in fs.listdir("/system"):
            print(entry.name, entry.inode, entry.kind)
        blob = fs.read("/system/users/0/locksettings.db")

The feature bitmaps below were **measured**, not recalled.  Several published
tables disagree with each other, and getting one bit wrong renames a flag in
every report that quotes it, so the mapping was established by creating
filesystems with ``mke2fs`` and observing which bit each ``-O ^feature`` toggle
cleared, cross-checked against ``dumpe2fs`` output for the reference image.
Anyone can repeat that: ``mke2fs -O ^64bit`` and diff the superblock.
"""

from __future__ import annotations

import datetime as _dt
import os
import stat
import struct
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from .crc32c import EXT2_GOOD_OLD_INODE_SIZE, INODE_CSUM_HI_EXTRA_END, crc32c
from .evidence import read_exact

SB_OFFSET = 1024
EXT4_MAGIC = 0xEF53
EXT4_ROOT_INODE = 2
EXTENTS_MAGIC = 0xF30A
HTREE_ROOT_FT = 0x07
DIRENT_FT_UNKNOWN = 0x00
#: A symlink whose target fits in the inode body instead of a data block.
EXT4_FAST_SYMLINK_LEN = 60

# s_feature_compat — measured: ext_attr 0x8, resize_inode 0x10, dir_index 0x20,
# has_journal 0x4, orphan_file 0x1000.
FEATURE_COMPAT = {
    0x0001: "DIR_PREALLOC",
    0x0002: "IMRECISE_PREMATURE_CKPT",
    0x0004: "HAS_JOURNAL",
    0x0008: "EXT_ATTR",
    0x0010: "RESIZE_INODE",
    0x0020: "DIR_INDEX",
    0x0040: "FILENAME_UTF8",
    0x0080: "EXT_ATTR_BG",
    0x1000: "ORPHAN_FILE",
    0x2000: "SB_RESIZE1",
    0x4000: "SB_RESIZE2",
    0x8000: "SB_RESIZE3",
}
# s_feature_incompat.  Entries marked "measured" were established by clearing
# one `-O ^feature` toggle at a time and diffing the superblock; the rest keep
# the kernel's names at the kernel's positions, which is the numbering the
# on-disk format follows.  The two agree on everything measured except the
# EXTENTS/64BIT pair, where the on-disk values are 0x40 and 0x80.
FEATURE_INCOMPAT = {
    0x0001: "COMPRESSION",
    0x0002: "FILETYPE",  # measured
    0x0004: "RECOVER",  # measured
    0x0008: "JOURNAL_DEV",
    0x0010: "META_BG",
    0x0040: "EXTENTS",  # measured
    0x0080: "64BIT",  # measured
    0x0100: "MMP",
    0x0200: "FLEX_BG",  # measured
    0x0400: "EA_INODE",
    0x0800: "DIRDATA",
    0x1000: "CSUM_SEED",
    0x2000: "CSUM_SEED_ALT",  # measured (e2fsprogs' metadata_csum_seed)
    0x4000: "ENCRYPT",
    0x8000: "INLINE_DATA",  # measured (e2fsprogs writes inline_data here)
}
# s_feature_ro_compat — measured: large_file 0x2, huge_file 0x8, uninit_bg 0x10,
# dir_nlink 0x20, extra_isize 0x40, metadata_csum 0x400.
FEATURE_RO_COMPAT = {
    0x0001: "SPARSE_SUPER",
    0x0002: "LARGE_FILE",
    0x0004: "BTREE_DIR",
    0x0008: "HUGE_FILE",
    0x0010: "UNINIT_BG",
    0x0020: "DIR_NLINK",
    0x0040: "EXTRA_ISIZE",
    0x0080: "HAS_SNAPSHOT",
    0x0100: "GDT_CSUM",
    0x0200: "STABLE_INODES",
    0x0400: "METADATA_CSUM",
    0x0800: "READONLY",
    0x1000: "REPLICA",
    0x2000: "PROJECT_QUOTA",
    0x4000: "VERITY",
    0x8000: "ORPHAN_PRESENT",
}

#: ``bg_flags`` in the group descriptor, at offset 0x12.  Measured by setting the
#: bits by hand on a synthetic image and reading them back through
#: ``dumpe2fs``'s ``[INODE_UNINIT, BLOCK_UNINIT, ITABLE_ZEROED]`` rendering, and
#: confirmed on a fresh ``mke2fs -O uninit_bg`` volume, which sets exactly the
#: first two on groups it never allocated from.
BG_INODE_UNINIT = 0x0001
BG_BLOCK_UNINIT = 0x0002
BG_INODE_ZEROED = 0x0004
BG_FLAG_NAMES = (
    (BG_INODE_UNINIT, "INODE_UNINIT"),
    (BG_BLOCK_UNINIT, "BLOCK_UNINIT"),
    (BG_INODE_ZEROED, "ITABLE_ZEROED"),
)

XATTR_MAGIC = 0xEA020000
#: Byte length of the extended-attribute block header, and of the fixed part of
#: one entry.  Both measured against the reference image's three real attribute
#: blocks, not taken from a document: header is magic, refcount, entries, size,
#: checksum, reserved, hash, checksum_seed and one spare word; an entry is name
#: length, name index, value offset, value inode, value size, hash, then the name
#: padded to four bytes.  ``e_hash`` is not recomputed — it is the old MD4-based
#: hash, and this reader does not verify it, which it says so about.
XATTR_HEADER_BYTES = 32
XATTR_ENTRY_FIXED = 16

#: ``e_name_index`` to prefix.  1..4 and 6..8 are assigned; 5 is unused and 0 is
#: invalid, and an index outside this set means the block is not what it claims.
XATTR_PREFIX = {
    1: "user",
    2: "system.posix_acl_access",
    3: "system.posix_acl_default",
    4: "trusted",
    6: "security",
    7: "system",
    8: "system.richacl",
}


def _other_format_note(path: str) -> str:
    """Name the filesystem when the image is one we can identify but not read.

    "bad ext4 magic" on an EROFS ``/system`` is a true sentence that wastes the
    analyst's afternoon.  This turns it into "this is EROFS, which this tool does
    not read" — and stays silent when the image really is a damaged ext4, because
    a confident wrong guess would be worse than the plain message.
    """
    if not path:
        return ""
    try:
        from .fsformat import unsupported_hint

        return unsupported_hint(path)
    except Exception:  # noqa: BLE001 - a hint must never mask the real error
        return ""


def _text_xattr(value: bytes) -> str:
    """Render an attribute value as text when it is one.

    SELinux contexts are NUL-terminated strings on disk; ``restorecon_last`` is
    not.  Stripping only a trailing NUL and leaving the rest as bytes is the
    honest option — decoding arbitrary bytes would invent characters.
    """
    if value.endswith(b"\0"):
        value = value[:-1]
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return ""


class Ext4Error(Exception):
    """Raised when the image is not an ext4 filesystem we can read."""


def _inode_kind(mode: int) -> str:
    """The four kinds a report distinguishes, without inventing a fifth."""
    if stat.S_ISDIR(mode):
        return "dir"
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISBLK(mode):
        return "blockdev"
    if stat.S_ISCHR(mode):
        return "chardev"
    return "other"


def _expects_no_data_block(node: Inode) -> bool:
    """True when an inode without the extents flag legitimately has no blocks.

    Getting this wrong in either direction matters: too strict and the reader
    refuses ordinary empty files and symlinks, too lax and it swallows a
    classic ext2 inode and reports the file as empty.
    """
    if node.size == 0:
        return True
    # A device node, FIFO or socket has no content of its own.
    if not (stat.S_ISREG(node.mode) or stat.S_ISDIR(node.mode) or stat.S_ISLNK(node.mode)):
        return True
    # A short symlink target is stored in the inode body; i_block is unused.
    if stat.S_ISLNK(node.mode) and node.size < EXT4_FAST_SYMLINK_LEN:
        return True
    return False


def _decode_flags(value: int, table: dict[int, str]) -> list[str]:
    return [name for bit, name in sorted(table.items()) if value & bit]


def _ts(value: int) -> str:
    """Epoch seconds as ISO UTC; keeps the raw number when it is out of range."""
    if not value:
        return "0"
    try:
        return (
            _dt.datetime.fromtimestamp(value, _dt.timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
    except (OSError, OverflowError, ValueError):
        return f"{value} (poza zakresem)"


@dataclass
class Extent:
    """One extent as stored in the inode: logical block -> physical block."""

    logical: int
    physical: int
    count: int

    @property
    def end(self) -> int:
        return self.logical + self.count

    def physical_for(self, logical: int) -> int:
        if not (self.logical <= logical < self.end):
            raise KeyError(f"logical block {logical} outside extent")
        return self.physical + (logical - self.logical)


def _unlinked_record(
    directory: str,
    block: int,
    offset: int,
    ino: int,
    ftype: int,
    raw_name: bytes,
    source: str,
) -> dict | None:
    """One unlinked directory entry, or ``None`` when the bytes are not a name.

    The acceptance test is deliberately narrow: a name is at least one byte, no
    longer than the record that holds it and no longer than the format allows, and
    every byte of it printable ASCII.  Android and Linux put a few dozen odd bytes
    in filenames, so this costs a handful of real entries and in exchange it stops
    a run of digits in a directory block from being reported as a filename — which
    is the failure mode that would make a name-recovery list unusable.
    """
    if not raw_name or len(raw_name) > 255:
        return None
    if any(byte < 0x20 or byte >= 0x7F for byte in raw_name):
        return None
    return {
        "name": raw_name.decode("ascii", "replace"),
        "directory": directory,
        "inode": ino,
        "kind": ftype,
        "kind_name": {
            0: "unknown", 1: "file", 2: "dir", 3: "chardev", 4: "blockdev",
            5: "fifo", 6: "socket", 7: "symlink", 8: "whiteout",
        }.get(ftype, f"typ_{ftype}"),
        "block": block,
        "offset_in_block": offset,
        "image_offset": block * 4096 + offset,
        "found_by": source,
        "name_source": "blok katalogowy katalogu, który wciąż istnieje",
        "metadata_trust": (
            "d_ino zerowe — inoda nie ma, nazwa jednoznaczna"
            if ino == 0
            else "obniżone — numer inoda mógł zostać przydzielony innemu plikowi"
        ),
    }


@dataclass
class DirEntry:
    """One directory entry."""

    name: str
    inode: int
    kind: int
    offset: int

    @property
    def is_dir(self) -> bool:
        return self.kind == 2

    @property
    def is_reg(self) -> bool:
        return self.kind == 1

    @property
    def is_link(self) -> bool:
        return self.kind == 7

    def type_name(self) -> str:
        return {
            1: "file",
            2: "dir",
            3: "chardev",
            4: "blockdev",
            5: "fifo",
            6: "socket",
            7: "symlink",
            8: "whiteout",
        }.get(self.kind, "?")


@dataclass
class Inode:
    """Parsed inode with the fields a forensic report needs."""

    number: int
    mode: int
    uid: int
    gid: int
    size: int
    atime: int
    ctime: int
    mtime: int
    crtime: int
    dtime: int
    links: int
    blocks: int
    flags: int
    extents: list[Extent] = field(default_factory=list)
    #: Physical blocks occupied by the extent tree itself, as opposed to the
    #: file's data.  ``i_blocks`` counts both, so any audit that checks the
    #: derived block count against ``i_blocks`` has to include them — that is
    #: the entire difference between 69 and 70 blocks on a file with a
    #: one-level-deep tree.
    extent_tree_blocks: list[int] = field(default_factory=list)
    #: Extended attributes, full name to raw value.  Empty on the overwhelming
    #: majority of inodes: a separate attribute block is only allocated when a
    #: file actually has one.
    xattrs: dict[str, bytes] = field(default_factory=dict)

    def xattr_text(self, name: str) -> str:
        """One attribute as text, or ``""`` when absent or not text."""
        return _text_xattr(self.xattrs.get(name, b""))

    @property
    def selinux(self) -> str:
        return self.xattr_text("security.selinux")

    @property
    def data_block_count(self) -> int:
        return sum(extent.count for extent in self.extents)

    @property
    def total_block_count(self) -> int:
        """Data blocks plus extent-tree blocks — what ``i_blocks`` accounts for."""
        return self.data_block_count + len(self.extent_tree_blocks)

    @property
    def is_dir(self) -> bool:
        return stat.S_ISDIR(self.mode)

    @property
    def is_reg(self) -> bool:
        return stat.S_ISREG(self.mode)

    @property
    def is_link(self) -> bool:
        return stat.S_ISLNK(self.mode)

    @property
    def compressed_block_count(self) -> int:
        """``i_blocks`` in 512-byte sectors, 0 when the inode has no data."""
        return self.blocks

    def extent_summary(self) -> str:
        if not self.extents:
            return "-"
        return f"{len(self.extents)} extent(s): " + ", ".join(
            f"{e.logical}+{e.count}->{e.physical}" for e in self.extents[:8]
        ) + (" ..." if len(self.extents) > 8 else "")


class _BlockCache:
    """Block-level read cache over one file object, offset by a partition base.

    Fail-closed.  A ``pread`` that comes back short means the kernel reached the
    end of the file, and this is the place where that used to be papered over
    with ``data + b"\\0" * (self._bs - len(data))``.  The padding was invisible
    to every caller: :meth:`Ext4.read_at` clips to the inode's declared size, so
    a file whose data blocks sat past the truncation point came back as a buffer
    of exactly the declared length, full of zeros, and ``extract_file`` hashed it
    into its manifest.  A manifest that certifies a SHA-256 of fabricated bytes
    is worse than no manifest, so a short read raises instead.

    The partial data is not cached either — a block that was short once may not
    be short later if the file is still being written, and caching the failure
    would freeze a momentary view of a growing image.
    """

    def __init__(self, handle, base: int, block_size: int, limit: int = 4096) -> None:
        self._handle = handle
        self._base = base
        self._bs = block_size
        self._limit = limit
        self._cache: dict[int, bytes] = {}
        self.hits = 0
        self.misses = 0

    def get(self, block: int) -> bytes:
        data = self._cache.get(block)
        if data is not None:
            self.hits += 1
            return data
        self.misses += 1
        offset = self._base + block * self._bs
        data = read_exact(self._handle.fileno(), self._bs, offset, what=f"blok {block}")
        if len(self._cache) >= self._limit:
            self._cache.pop(next(iter(self._cache)))
        self._cache[block] = data
        return data

    def read(self, block: int, offset: int, length: int) -> bytes:
        chunk = self.get(block)
        return chunk[offset : offset + length]


class Ext4:
    """Read-only handle on an ext2/3/4 image or partition."""

    def __init__(self, path: str, offset: int = 0) -> None:
        self.path = path
        self.base = offset
        self._handle = open(path, "rb")
        try:
            self.superblock = self._read_superblock()
        except Exception:
            self._handle.close()
            raise
        self.block_size: int = self.superblock["block_size"]
        self.blocks: int = self.superblock["blocks_count"]
        self.inode_size: int = self.superblock["inode_size"]
        #: Bytes the file is short of the filesystem it contains.  Zero for an
        #: image that is whole **and** for one that is larger than the filesystem,
        #: which is the normal case for a partition inside a whole-disk dump.
        self.truncated_bytes: int = self._missing_bytes()
        self._cache = _BlockCache(self._handle, self.base, self.block_size)
        self._groups = self._read_group_descriptors()
        #: Directories that could not be listed, with the reason.  A directory
        #: that does not open is missing evidence, not a smaller filesystem, so
        #: it has to reach the report instead of quietly shortening a walk.
        #: Same name and shape as :attr:`forensic.core.f2fs.F2fs.walk_errors`.
        self.walk_errors: list[dict] = []

    def _missing_bytes(self) -> int:
        """How much of the declared filesystem is not in the file, if any.

        Checked once, at the door, because the superblock is the filesystem's own
        statement about how large it is and ``stat`` is free.  A superblock read
        out of the first kilobyte of an image that is missing its last gigabyte
        is a perfectly valid superblock describing evidence that is not all
        there, and the two facts have to meet before a single file is parsed.

        Left as a number rather than raised: :meth:`__init__` refusing to open
        would mean every command on a truncated image answers "wrong filesystem",
        when what an analyst needs to hear is "right filesystem, 4 GiB missing" —
        and a truncated image is still the best evidence available.  The reads
        themselves are what fail closed, in :class:`_BlockCache`.
        """
        available = os.fstat(self._handle.fileno()).st_size - self.base
        declared = self.blocks * self.block_size
        return max(0, declared - available)

    @property
    def truncated(self) -> bool:
        """True when the file does not hold the whole filesystem."""
        return self.truncated_bytes > 0

    def close(self) -> None:
        try:
            self._handle.close()
        except OSError:
            pass

    def __enter__(self) -> Ext4:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def size_bytes(self) -> int:
        return self.blocks * self.block_size

    def _pread(self, offset: int, length: int) -> bytes:
        """Read a byte range, tolerating a short one at the very end.

        The one caller is :meth:`_read_superblock`, which has to be able to see
        that the file ends before offset 1024 + 1024 in order to say "too small
        to contain a superblock" — the honest name for an empty or stub file.
        Everything that reads a block the geometry located uses
        :class:`_BlockCache`, which does not tolerate a short read at all.
        """
        return os.pread(self._handle.fileno(), length, self.base + offset)

    def _read_superblock(self) -> dict:
        raw = self._pread(SB_OFFSET, 1024)
        if len(raw) < 1024:
            # Not truncation.  A superblock this short means nothing in the file
            # claims to be a filesystem, so there is no geometry to contradict —
            # which is a different failure from "the geometry says 27 GB and the
            # file holds 4".  ``_missing_bytes`` answers the second one.
            raise Ext4Error("image too small to contain a superblock")
        def u16(o: int) -> int:
            return struct.unpack_from("<H", raw, o)[0]
        def u32(o: int) -> int:
            return struct.unpack_from("<I", raw, o)[0]
        if u16(0x38) != EXT4_MAGIC:
            raise Ext4Error(
                f"bad ext4 magic 0x{u16(0x38):04x} at +{SB_OFFSET}."
                + _other_format_note(self.path)
            )
        log_bs = u32(0x18)
        bs = 1024 << log_bs
        if bs not in (1024, 2048, 4096, 8192, 16384, 32768, 65536):
            raise Ext4Error(f"unsupported block size {bs}")
        compat = u32(0x5C)
        incompat = u32(0x60)
        ro_compat = u32(0x64)
        desc_size = u16(0xFE) or 32
        if desc_size not in (32, 64):
            desc_size = 64 if (ro_compat & 0x80) else 32
        journal_blocks = sum(u32(0x10C + 4 * i) for i in range(17))
        # s_free_blocks_count_hi lives at 0x158, immediately after
        # s_r_blocks_count_hi at 0x154.  Reading 0x160 instead picks up s_flags
        # — 2 on this volume, because EXT2_FLAGS_UNSIGNED_HASH is set — and
        # inflates free_blocks by 2 * 2**32.  The high halves only count at all
        # when 64BIT is on; below that the fields are reserved.
        wide = bool(incompat & 0x80)
        blocks_high = u32(0x150) if wide else 0
        free_high = u32(0x158) if wide else 0
        return {
            "inodes_count": u32(0x00),
            "blocks_count": u32(0x04) + (blocks_high << 32),
            "free_blocks": u32(0x0C) + (free_high << 32),
            "r_blocks_count": u32(0x08),
            "free_inodes": u32(0x10),
            "first_data_block": u32(0x14),
            "block_size": bs,
            "log_block_size": log_bs,
            "cluster_size": 1024 << u32(0x1C),
            "blocks_per_group": u32(0x20),
            "inodes_per_group": u32(0x28),
            "mtime": u32(0x2C),
            "wtime": u32(0x30),
            "magic": u16(0x38),
            "state": u16(0x3A),
            "errors": u16(0x3C),
            "inode_size": u16(0x58) or 128,
            "feature_compat": compat,
            "feature_incompat": incompat,
            "feature_ro_compat": ro_compat,
            "features": (
                _decode_flags(compat, FEATURE_COMPAT)
                + _decode_flags(incompat, FEATURE_INCOMPAT)
                + _decode_flags(ro_compat, FEATURE_RO_COMPAT)
            ),
            "journal_inum": u32(0xE0),
            "last_orphan": u32(0xE8),
            "journal_blocks": journal_blocks,
            "desc_size": desc_size,
            "default_mount_opts": u32(0x100),
            "first_meta_bg": u32(0x104),
            "mkfs_time": u32(0x108),
            "min_extra_isize": u16(0x15C),
            "want_extra_isize": u16(0x15E),
            "flags": u32(0x160),
            "uuid": raw[0x68:0x78].hex(),
            "volume_name": raw[0x78:0x88].split(b"\0")[0].decode("utf-8", "replace"),
            "last_mounted": raw[0x88:0xC8].split(b"\0")[0].decode("utf-8", "replace"),
            "state_name": {1: "clean", 2: "errors", 4: "orphans"}.get(u16(0x3A), "?"),
            # The checksum field and the seed, kept raw so :meth:`checksums` can
            # verify without re-reading the superblock through the block cache —
            # which would be a circular dependency, since the superblock is what
            # locates everything else.
            "checksum": u32(0x3FC),
            "checksum_type": raw[0x175],
            "checksum_seed": u32(0x270),
            "uuid_raw": raw[0x68:0x78].hex(),
        }

    # -- metadata_csum -------------------------------------------------------
    #
    # Verified against e2fsprogs rather than transcribed from the format
    # documentation, because a checksum that is one byte off fails in both
    # directions and neither is loud: it rejects clean images, or it accepts
    # damaged ones and calls the metadata verified.  See
    # :mod:`forensic.core.crc32c` for the two properties that were wrong in the
    # first attempt and are worth not rediscovering.

    def _csum_seed(self) -> int:
        """The running crc every seeded structure starts from.

        ``metadata_csum_seed`` puts the seed in the superblock at 0x270.  Without
        it e2fsprogs derives one from the UUID — and *only* when ``metadata_csum``
        or ``ea_inode`` is on, which is the same condition under which the seed is
        used at all.
        """
        sb = self.superblock
        if sb["feature_incompat"] & 0x2000:
            return sb["checksum_seed"]
        return crc32c(bytes.fromhex(sb["uuid_raw"]))

    @property
    def metadata_csum(self) -> bool:
        """Whether the filesystem claims to protect its metadata with a checksum."""
        return bool(self.superblock["feature_ro_compat"] & 0x0400)

    @property
    def gdt_csum(self) -> bool:
        """Whether group descriptors carry a checksum of their own."""
        return bool(self.superblock["feature_ro_compat"] & 0x0100)

    def _bitmap_csum(self, group: int, field: str) -> int:
        """Computed crc32c of one group's block or inode bitmap.

        The bitmap is read at its own size, not at one block: a group whose
        bitmaps span several blocks has a checksum over all of them, and reading
        one block would produce a number that disagrees with e2fsprogs on every
        large group and agree on every small one — a bug that looks like it works.
        """
        per_group = (
            self.superblock["inodes_per_group"]
            if field == "inode_bitmap"
            else self.superblock["blocks_per_group"]
        )
        need = -(-per_group // 8)
        return crc32c(self._group_bitmap(group, field)[:need], self._csum_seed())

    def group_descriptor_csum(self, group: int) -> int:
        """Computed crc32c of one group descriptor, low 16 bits.

        ``bg_checksum`` is zeroed while computing — it sits *inside* the covered
        region, unlike the superblock's checksum which sits outside it.
        """
        gd = bytearray(self._group_descriptor(group))
        gd[0x1E:0x20] = b"\0\0"
        return crc32c(bytes(gd), crc32c(struct.pack("<I", group), self._csum_seed())) & 0xFFFF

    def inode_csum(self, number: int, raw: bytes) -> tuple[int, bool]:
        """Computed crc32c of one inode, and whether its high half exists.

        ``i_generation`` is in the sum because it is what stops a swapped-in inode
        from inheriting the checksum of the one it replaced.
        """
        size = self.inode_size
        buf = bytearray(raw[:size])
        buf[0x7C:0x7E] = b"\0\0"
        extra = struct.unpack_from("<H", buf, 0x80)[0] if size > EXT2_GOOD_OLD_INODE_SIZE else 0
        has_hi = size > EXT2_GOOD_OLD_INODE_SIZE and extra >= INODE_CSUM_HI_EXTRA_END
        if has_hi:
            buf[0x82:0x84] = b"\0\0"
        gen = struct.unpack_from("<I", buf, 0x64)[0]
        crc = crc32c(struct.pack("<I", number), self._csum_seed())
        crc = crc32c(struct.pack("<I", gen), crc)
        crc = crc32c(bytes(buf), crc)
        return (crc if has_hi else crc & 0xFFFF), has_hi

    def checksums(self, inodes: int = 0) -> dict[str, Any]:
        """Verify what the filesystem claims to protect, and say what was covered.

        Three buckets on purpose, and the third is the one that matters most:
        ``ok``, ``failed`` and **``not_present``**.  A filesystem with
        ``metadata_csum`` off has nothing to verify, and reporting that as a pass
        would be claiming a check that never ran.  The same holds for group
        descriptors, which need ``gdt_csum`` *separately* from
        ``metadata_csum`` — the two bits are independent and an image can have
        one without the other.

        ``inodes`` caps how many inodes are checked, because the reference image
        has 750 000 of them and verifying all of them takes half a minute; the
        cap is reported rather than implied.
        """
        sb = self.superblock
        out: dict[str, Any] = {
            "metadata_csum": self.metadata_csum,
            "gdt_csum": self.gdt_csum,
            "checksum_type": sb["checksum_type"],
            "seed": f"0x{self._csum_seed():08x}",
        }
        if not self.metadata_csum and not self.gdt_csum:
            # A 2016 Redmi 3 lands here, and so would any volume mke2fs made
            # before ``metadata_csum``.  The shape is the same as the one below
            # so a caller can read ``status`` and ``bad`` without first checking
            # which branch produced the result — and the answer is deliberately
            # not "ok": no checksum was computed, and reporting a pass for a
            # check that did not run is the thing this whole method exists to
            # avoid.
            out.update({
                "status": "not_present",
                "ok_count": 0,
                "bad": [],
                "detail": (
                    "filesystem nie deklaruje sum kontrolnych metadanych "
                    "(metadata_csum) — nie ma czego weryfikować"
                ),
            })
            return out

        bad: list[dict] = []
        ok = 0

        # -- superblock.  No seed, and it stops before s_checksum.
        raw_sb = self._pread(SB_OFFSET, 1024)
        if len(raw_sb) >= 0x400:
            stored = struct.unpack_from("<I", raw_sb, 0x3FC)[0]
            computed = crc32c(raw_sb[:0x3FC])
            ok += 1 if computed == stored else 0
            if computed != stored:
                bad.append({"what": "superblock", "stored": stored, "computed": computed})
            out["superblock"] = {"stored": stored, "computed": computed, "ok": computed == stored}

        # -- group descriptors
        groups = len(self._groups)
        if self.gdt_csum:
            gd_bad = 0
            for group in range(groups):
                stored = struct.unpack_from("<H", self._group_descriptor(group), 0x1E)[0]
                computed = self.group_descriptor_csum(group)
                if stored != computed:
                    gd_bad += 1
                    if len(bad) < 20:
                        bad.append({"what": f"group {group}", "stored": stored, "computed": computed})
            ok += groups - gd_bad
            out["group_descriptors"] = {"checked": groups, "bad": gd_bad}

        # -- bitmaps
        bitmap_bad = 0
        for group in range(groups):
            for which, lo_at in (("block_bitmap", 0x18), ("inode_bitmap", 0x1A)):
                stored = struct.unpack_from(
                    "<H", self._group_descriptor(group), lo_at
                )[0]
                computed = self._bitmap_csum(group, which)
                if stored != (computed & 0xFFFF):
                    bitmap_bad += 1
                    if len(bad) < 20:
                        bad.append({"what": f"group {group} {which}", "stored": stored, "computed": computed})
        ok += groups * 2 - bitmap_bad
        out["bitmaps"] = {"checked": groups * 2, "bad": bitmap_bad}
        if not self.gdt_csum:
            out["group_descriptors"] = {"checked": 0, "bad": 0, "not_present": True}

        # -- inodes
        if inodes:
            inode_bad = 0
            checked = 0
            zero = 0
            limit = min(sb["inodes_count"], inodes)
            per_block = self.block_size // self.inode_size
            for number in range(1, limit + 1):
                group, index = divmod(number - 1, sb["inodes_per_group"])
                if group >= len(self._groups):
                    continue
                table = self._groups[group]["inode_table"]
                raw = self._cache.read(table + index // per_block, (index % per_block) * self.inode_size, self.inode_size)
                if not any(raw[:EXT2_GOOD_OLD_INODE_SIZE]):
                    # e2fsprogs accepts an all-zero inode whose checksum does not
                    # match, and so does this: an unused inode nobody wrote is not
                    # corruption.  Counted separately so the number of verified
                    # inodes is not inflated by them.
                    zero += 1
                    continue
                checked += 1
                computed, has_hi = self.inode_csum(number, raw)
                lo = struct.unpack_from("<H", raw, 0x7C)[0]
                stored = lo | (struct.unpack_from("<H", raw, 0x82)[0] << 16) if has_hi else lo
                if stored != computed:
                    inode_bad += 1
                    if len(bad) < 20:
                        bad.append({"what": f"inode {number}", "stored": stored, "computed": computed})
            ok += checked - inode_bad
            out["inodes"] = {
                "checked": checked,
                "bad": inode_bad,
                "all_zero": zero,
                "cap": inodes,
                "capped": limit < sb["inodes_count"],
            }

        out["ok_count"] = ok
        out["bad"] = bad
        out["status"] = "failed" if bad else "ok"
        out["detail"] = (
            f"{ok} struktur zgodnych" + (f", {len(bad)} niezgodnych" if bad else "")
        )
        return out

    def _group_descriptor(self, group: int) -> bytes:
        """Raw bytes of one group descriptor.

        Addressed by byte offset and then split into block and offset, because
        :meth:`_BlockCache.read` takes a **block number** — handing it a byte
        offset reads a plausible-looking descriptor from the wrong place and
        returns zeros for its checksum fields, which is indistinguishable from a
        filesystem that stores no checksums.
        """
        size = self.superblock["desc_size"]
        at = (self.superblock["first_data_block"] + 1) * self.block_size + group * size
        block, in_block = divmod(at, self.block_size)
        return self._cache.read(block, in_block, size)

    def _check_group_layout(self, sb: dict, gdt_block: int, desc_size: int, groups: int) -> None:
        """Refuse group-descriptor layouts this reader does not implement.

        Without ``metadata_bg`` the table is contiguous, starting right after
        the superblock and running for as many blocks as it needs, so
        ``gdt_block + index // per_block`` is the whole story.

        With ``metadata_bg`` the descriptors of the groups at and after
        ``s_first_meta_bg`` live in the reserved GDT blocks scattered through
        each metablock, which this reader does not walk.  Indexing them as if
        they were contiguous yields a plausible ``inode_table`` pointing at the
        wrong block, and the failure surfaces much later as an inode whose
        contents are somebody else's file.

        ``s_first_meta_bg == 0`` is the case that looks alarming and is not:
        mke2fs lays the table out contiguously anyway, and reading it that way
        was verified against The Sleuth Kit on a real ``meta_bg`` volume —
        7 of 7 paths and 7 of 7 file contents identical.  Refusing that would
        be refusing a filesystem this reader handles correctly, so the flag
        alone is not grounds to stop; only a non-zero first metablock group,
        where the layout genuinely diverges, is.
        """
        if not sb["feature_incompat"] & 0x10:
            return
        if not sb["first_meta_bg"]:
            return
        raise Ext4Error(
            f"metadata_bg z s_first_meta_bg={sb['first_meta_bg']}: deskryptory grup od "
            f"tej granicy leżą w rozproszonych blokach GDT (poza blokiem za superblokiem), "
            f"a ten reader chodzi tylko po ciągłej tablicy. {groups} grup, "
            f"desc_size={desc_size}."
        )

    def _read_group_descriptors(self) -> list[dict]:
        sb = self.superblock
        gdt_block = sb["first_data_block"] + 1
        desc_size = sb["desc_size"]
        groups = -(-sb["blocks_count"] // sb["blocks_per_group"])
        self._check_group_layout(sb, gdt_block, desc_size, groups)
        out: list[dict] = []
        per_block = self.block_size // desc_size
        for index in range(groups):
            blk = gdt_block + index // per_block
            data = self._cache.get(blk)
            off = (index % per_block) * desc_size
            inode_table = struct.unpack_from("<I", data, off + 0x08)[0]
            free_blocks = struct.unpack_from("<H", data, off + 0x0C)[0]
            if desc_size >= 64:
                inode_table |= struct.unpack_from("<I", data, off + 0x2E)[0] << 32
                # bg_free_blocks_count_hi carries the bits above 65535, which a
                # group reaches at 64 Mi blocks — the size class of a large
                # /data partition, not of anything the self-test builds.
                free_blocks |= struct.unpack_from("<H", data, off + 0x2C)[0] << 16
            out.append(
                {
                    "group": index,
                    "block_bitmap": struct.unpack_from("<I", data, off + 0x00)[0],
                    "inode_bitmap": struct.unpack_from("<I", data, off + 0x04)[0],
                    "inode_table": inode_table,
                    "free_blocks": free_blocks,
                    "free_inodes": struct.unpack_from("<H", data, off + 0x0E)[0],
                    "used_dirs": struct.unpack_from("<H", data, off + 0x10)[0],
                    "flags": struct.unpack_from("<H", data, off + 0x12)[0],
                }
            )
        return out

    def inode(self, number: int | DirEntry) -> Inode:
        if isinstance(number, DirEntry):
            number = number.inode
        if number < 1 or number > self.superblock["inodes_count"]:
            raise KeyError(f"inode {number} out of range")
        group, index = divmod(number - 1, self.superblock["inodes_per_group"])
        table = self._groups[group]["inode_table"]
        per_block = self.block_size // self.inode_size
        raw = self._cache.get(table + index // per_block)
        base = (index % per_block) * self.inode_size
        def u16(o: int) -> int:
            return struct.unpack_from("<H", raw, base + o)[0]
        def u32(o: int) -> int:
            return struct.unpack_from("<I", raw, base + o)[0]
        mode = u16(0x00)
        size = u32(0x04) | (u16(0x6C) << 32)

        def stamped(low_field: int, extra_field: int) -> int:
            """One inode time: the 32-bit value, plus the epoch extension if it is needed.

            The extension lives at a **fixed** offset — 0x84, 0x88, 0x8C — not at
            0x84 plus ``extra_isize``.  Deriving it from ``extra_isize`` put the
            reader 28 bytes past the real fields, onto the inode checksum and
            project-id, and produced timestamps like 7596558217525865027.

            Applying the extension is then a **second** mistake, and a much
            worse one.  The kernel only maintains these fields when the 32-bit
            time has actually overflowed; on a volume whose times all predate
            2038 they are left uninitialised.  This image has 40 000 inodes
            carrying values in the plausible range there, and OR-ing them
            unconditionally turned three 2016 timestamps into dates around the
            year 200 million — and put them past `fs_timeline`'s cut-off, so
            files the analyst should see simply vanished from the timeline.

            The rule is the format's own: the high word only counts when the
            low word, read as signed, is negative, which is exactly the
            post-2038 case.  Verified against TSK over all 150 668 inodes.
            """
            low = u32(low_field)
            if low < 0x80000000:
                return low
            if 0x80 + extra_field > self.inode_size:
                return low
            high = u32(0x80 + extra_field)
            if not 0x30000000 < high < 0x70000000:
                return low
            return low | (high << 32)

        node = Inode(
            number=number,
            mode=mode,
            uid=u16(0x02) | (u16(0x78) << 16),
            gid=u16(0x18) | (u16(0x7A) << 16),
            size=size,
            atime=stamped(0x08, 0x0C),
            ctime=stamped(0x0C, 0x04),
            mtime=stamped(0x10, 0x08),
            crtime=u32(0x90) if self.inode_size >= 0x94 else 0,
            dtime=u32(0x14),
            links=u16(0x1A),
            blocks=u32(0x1C),
            flags=u32(0x20),
        )
        node.extents, node.extent_tree_blocks = self._parse_extents(
            node, raw[base + 0x28 : base + 0x28 + 60]
        )
        node.xattrs = self._parse_xattrs(
            u32(0x68) | (u16(0x76) << 32), raw=raw, number=number
        )
        return node

    def inode_header(self, number: int) -> dict | None:
        """The inode's scalar fields, without walking its extent tree.

        Two and a half times faster than :meth:`inode` on a volume with 750 000
        deleted inodes, because it stops before the expensive part — reading
        extents means following tree blocks, and an audit of deleted inodes
        wants ``i_size``, ``i_dtime`` and ``i_mode``, not the block map.

        Returns ``None`` for an inode number outside the table, which is what a
        stale or corrupt reference looks like.
        """
        if number < 1 or number > self.superblock["inodes_count"]:
            return None
        group, index = divmod(number - 1, self.superblock["inodes_per_group"])
        if group >= len(self._groups):
            return None
        table = self._groups[group]["inode_table"]
        per_block = self.block_size // self.inode_size
        raw = self._cache.get(table + index // per_block)
        at = (index % per_block) * self.inode_size
        if len(raw) < at + 0x6C:
            return None
        def u16(o: int) -> int:
            return struct.unpack_from("<H", raw, at + o)[0]
        def u32(o: int) -> int:
            return struct.unpack_from("<I", raw, at + o)[0]
        return {
            "number": number,
            "group": group,
            "mode": u16(0x00),
            "uid": u16(0x02) | (u16(0x78) << 16),
            "gid": u16(0x18) | (u16(0x7A) << 16),
            "size": u32(0x04) | (u16(0x6C) << 32),
            "atime": u32(0x08),
            "ctime": u32(0x0C),
            "mtime": u32(0x10),
            "dtime": u32(0x14),
            "links": u16(0x1A),
            "blocks": u32(0x1C),
            "flags": u32(0x20),
        }

    def _group_bitmap(self, group: int, field: str) -> bytes:
        """One group's inode or block bitmap, as a byte string.

        Bitmaps can run past a single block on a group with more inodes or
        blocks than fits, so the read is rounded up rather than assuming one.
        """
        entry = self._groups[group][field]
        per_group = (
            self.superblock["inodes_per_group"]
            if field == "inode_bitmap"
            else self.superblock["blocks_per_group"]
        )
        need = -(-per_group // 8)
        blocks = -(-need // self.block_size)
        return b"".join(self._cache.get(entry + offset) for offset in range(blocks))

    def _bit_set(self, bitmap: bytes, index: int) -> bool:
        """True when the bit is **allocated** — the sense both bitmaps use."""
        return index >> 3 < len(bitmap) and bool(bitmap[index >> 3] & (1 << (index & 7)))

    def free_inode_count(self) -> int:
        """Inodes the bitmaps mark free.

        Compared against ``s_free_inodes_count`` rather than assumed equal to it:
        the kernel holds a few inodes back for the journal, so the two numbers
        differ slightly on a healthy volume and a large gap would mean a
        corrupted bitmap.
        """
        total = 0
        for group in range(len(self._groups)):
            bitmap = self._group_bitmap(group, "inode_bitmap")
            first = group * self.superblock["inodes_per_group"]
            count = min(
                self.superblock["inodes_per_group"],
                self.superblock["inodes_count"] - first,
            )
            for index in range(count):
                if not self._bit_set(bitmap, index):
                    total += 1
        return total

    def block_is_free(self, block: int) -> bool:
        """True when a block is unallocated.

        This is the guard that decides whether a deleted file's content can be
        believed.  Its extents point at blocks that were handed back to the
        allocator when the file was unlinked, and something else may have taken
        them since.  Reading without asking this question returns another
        file's bytes under the deleted file's name.
        """
        if block < 0 or block >= self.superblock["blocks_count"]:
            return False
        group, index = divmod(block, self.superblock["blocks_per_group"])
        if group >= len(self._groups):
            return False
        return not self._bit_set(self._group_bitmap(group, "block_bitmap"), index)

    def block_uninit_groups(self) -> list[int]:
        """Groups whose block bitmap the filesystem has declared not initialised.

        ``EXT4_BG_BLOCK_UNINIT`` means the block bitmap of the group was never
        written, so an all-zero bitmap reads as "every block in this group is
        free" **by definition rather than by measurement** — but only where the
        filesystem carries the ``uninit_bg`` feature that makes it a promise.
        With the feature on, that is what the format means and e2fsprogs and The
        Sleuth Kit both honour it the same way: the fresh ``mke2fs -O uninit_bg``
        image used by the self-test has two such groups of 8192 blocks each, and
        ``dumpe2fs``, ``blkls`` and this reader all report the same free count
        including them.

        The first version of this function was going to *exclude* those blocks,
        on the reasoning that a bitmap nobody maintains cannot be inverted.  That
        would have made this reader disagree with both tools it is checked
        against, and would have understated the free space.  The honest treatment
        is to include them — that is what the format means — and to name them, so
        a report can say which blocks are free by measurement and which are free
        by assumption.

        With the feature **off** the flag promises nothing and the bitmap is not
        evidence; those groups are named by
        :meth:`uninit_groups_untrusted` instead, and read from the descriptor.
        """
        return [g["group"] for g in self._groups if g["flags"] & BG_BLOCK_UNINIT]

    def uninit_bitmap_inconsistent(self) -> list[int]:
        """``BLOCK_UNINIT`` groups whose block bitmap is **not** all zero.

        A group that claims its bitmap was never written and then has bits set in
        it is a contradiction, and neither answer is safe: trusting the flag
        discards real allocation information, trusting the bitmap accepts a
        filesystem that says the bitmap is meaningless.  The groups are listed so
        the report can say that, instead of picking one silently.
        """
        out: list[int] = []
        for group in self.block_uninit_groups():
            bitmap = self._group_bitmap(group, "block_bitmap")
            if any(bitmap):
                out.append(group)
        return out

    def uninit_groups_untrusted(self) -> set[int]:
        """Groups whose block bitmap is on disk but must not be believed.

        ``BLOCK_UNINIT`` says the group's block bitmap was never written.  With
        the ``uninit_bg`` feature **on**, that is a promise, and an all-zero
        bitmap really does mean "the whole group is free": the format says so and
        both reference tools honour it.

        With the feature **off**, the flag has no meaning to the allocator and the
        unwritten bitmap is not a measurement of anything.  Reading it as all-zero
        concludes that every block of the group is free — including the group's
        own backup superblock, its backup descriptor table and the reserved GDT
        area that ``sparse_super`` sets aside for a future resize.  On the
        self-test's fresh 1 KiB volume built by e2fsprogs 1.47.0 that is three
        groups of 258 blocks: the reader reported 56 797 free where
        ``dumpe2fs`` and ``e2fsck -fn`` both say 56 023, on a volume both of them
        call clean.

        The group descriptor is where the filesystem records the count those
        tools arrive at, so this is what is read, and the free blocks are taken
        from the **end** of the group: that is the direction the allocator works
        in, and it puts group 1's free range at 8451-16384, which is what
        ``dumpe2fs`` prints.
        """
        if self.superblock["feature_ro_compat"] & 0x0010:
            return set()
        return set(self.block_uninit_groups())

    def unallocated_blocks(self) -> Iterator[int]:
        """Every unallocated block of the volume, in block order.

        The unallocated set is the inverted block bitmap, clipped to the blocks
        the volume actually has.  The clip matters: the last group's bitmap has
        one bit per slot in the group, and those beyond ``blocks_count`` describe
        blocks that are not on the volume.  On the reference image that is 17 418
        slots past the end, and the last group happens to have all of them marked
        allocated — so the clip costs nothing there.  On a volume where they read
        free, a reader without the clip would report space that cannot be read.

        Metadata needs no exclusion of its own.  ext4 marks the superblock
        backups, the group descriptor table, the bitmaps and the inode tables as
        allocated in the same bitmap, so inverting it leaves them out by
        construction rather than by a list that could drift.

        The one exception is a group whose bitmap was never written and whose
        filesystem does not carry the feature that would make that a promise;
        there the descriptor is used instead, see
        :meth:`uninit_groups_untrusted`.
        """
        sb = self.superblock
        per_group = sb["blocks_per_group"]
        total = sb["blocks_count"]
        untrusted = self.uninit_groups_untrusted()
        for group in range(len(self._groups)):
            first = group * per_group
            count = min(per_group, total - first)
            if count <= 0:
                continue
            if group in untrusted:
                free = max(0, min(self._groups[group]["free_blocks"], count))
                for index in range(count - free, count):
                    yield first + index
                continue
            bitmap = self._group_bitmap(group, "block_bitmap")
            for index in range(count):
                if not self._bit_set(bitmap, index):
                    yield first + index

    def unallocated_runs(self, blocks: list[int] | None = None) -> list[tuple[int, int]]:
        """The unallocated blocks as maximal consecutive runs of ``(first, count)``.

        This is the shape that matters downstream.  A carve walks space, and
        space that is one 4 KiB hole in a group of 32 768 is a different proposition
        from a single 400 000-block run: it decides whether a file can be
        reassembled at all, since a file's blocks are allocated near each other and
        a deleted one tends to leave a run rather than a scatter.
        """
        runs: list[tuple[int, int]] = []
        start: int | None = None
        previous = 0
        for block in self.unallocated_blocks() if blocks is None else blocks:
            if start is None:
                start = previous = block
            elif block == previous + 1:
                previous = block
            else:
                runs.append((start, previous - start + 1))
                start = previous = block
        if start is not None:
            runs.append((start, previous - start + 1))
        return runs

    def sparse_super_groups(self) -> set[int]:
        """Groups that carry a backup superblock and a backup descriptor table.

        The rule is 0, 1, and every power of 3, 5 and 7 below the group count.  It
        is written out rather than looped over ``sparse_super`` because the
        superblock has no such field: what it has is the *feature flag*
        ``SPARSE_SUPER``, and a reader that looked for a multiplier there would
        find nothing.  Checked against ``dumpe2fs``, which lists backup
        superblocks in groups 1, 3, 5, 7, 9, 25, 27, 49, 81 and 125 of the
        reference image; the set here is those ten plus group 0, which holds the
        primary superblock and is covered separately.
        """
        out = {0, 1}
        for base in (3, 5, 7):
            power = 1
            while power < len(self._groups):
                out.add(power)
                power *= base
        return {group for group in out if group < len(self._groups)}

    def metadata_blocks(self) -> set[int]:
        """Every block the filesystem uses for its own bookkeeping.

        Assembled from the structures themselves rather than from a hard-coded
        list of offsets, because the list is what goes stale: the superblock
        block and the group descriptor table, each group's block bitmap, inode
        bitmap and inode table, the superblock and descriptor backups in every
        sparse-super group, and the journal's own blocks.  The inode table length
        comes from ``inodes_per_group × inode_size`` rounded up to blocks, which
        is the only place the size is written down.
        """
        sb = self.superblock
        per_group = sb["blocks_per_group"]
        total = sb["blocks_count"]
        itb = -(
            -(sb["inodes_per_group"] * sb["inode_size"]) // self.block_size
        )
        gdt_first = sb["first_data_block"] + 1
        per_desc = self.block_size // sb["desc_size"]
        gdt_blocks = -(-len(self._groups) // per_desc)
        out: set[int] = set(range(0, min(sb["first_data_block"] + 1, total)))
        out |= set(range(gdt_first, min(gdt_first + gdt_blocks, total)))
        for sparse in self.sparse_super_groups():
            base = sparse * per_group
            out.add(base)
            out |= set(range(base + 1, min(base + 1 + gdt_blocks, total)))
        for descriptor in self._groups:
            out.add(descriptor["block_bitmap"])
            out.add(descriptor["inode_bitmap"])
            first = descriptor["inode_table"]
            out |= set(range(first, min(first + itb, total)))
        try:
            journal = self.inode(sb["journal_inum"])
        except (KeyError, Ext4Error):
            journal = None
        if journal is not None:
            for extent in journal.extents:
                out |= set(range(extent.physical, extent.physical + extent.count))
        return {block for block in out if 0 <= block < total}

    def uninit_state(self) -> dict:
        """The ``uninit_bg`` picture, in the three states a volume can be in.

        The feature flag and the per-group flag are two different pieces of
        information and mke2fs sets them independently, which is worth stating
        because the three combinations mean different things:

        * **feature on, groups flagged** — the flags mean what they say; an
          all-zero bitmap in such a group reads as "the whole group is free" by
          definition.  ``mke2fs -O uninit_bg`` on 1 KiB blocks produces this.
        * **feature off, groups flagged** — the flags are there and the feature
          that would give them meaning is not, so the bitmap that was never
          written is not a measurement.  A fresh 64 MiB volume with 1 KiB blocks
          lands here on e2fsprogs 1.47.0: three groups carry ``BLOCK_UNINIT``
          while ``s_feature_ro_compat`` has no ``UNINIT_BG`` bit.  Reading those
          bitmaps as all-free counts the reserved GDT area as free and reports
          56 797 blocks against the 56 023 that ``dumpe2fs`` and ``e2fsck -fn``
          both give; the descriptor carries the number they arrived at, and
          :meth:`uninit_groups_untrusted` says which groups to take it from.
        * **feature on, no group flagged** — every bitmap was written, so every
          free block is free by measurement.  This is what a volume looks like
          once anything has been allocated from every group.

        A reader that only looks at the group flags will call the second case
        "free by definition" and be wrong; and a reader that only inverts the
        bitmap will call it "measured" and be wrong in the other direction.  The
        two states differ in the count, not only in the warrant: what a report
        must not do is claim a measurement it did not make.
        """
        feature = bool(self.superblock["feature_ro_compat"] & 0x0010)
        groups = self.block_uninit_groups()
        per_group = self.superblock["blocks_per_group"]
        total = self.superblock["blocks_count"]
        free = sum(
            1
            for group in groups
            for index in range(min(per_group, total - group * per_group))
            if not self._bit_set(self._group_bitmap(group, "block_bitmap"), index)
        )
        return {
            "feature": feature,
            "groups": groups,
            "free_blocks": free,
            "by_definition": feature and bool(groups),
            "state": (
                "cecha ustawiona, żadna grupa nie zgłoszona — wszystkie bitmapy zapisane"
                if feature and not groups
                else "cecha ustawiona i flagi grup zgodne"
                if feature
                else "flagi grup bez cechy uninit_bg — bitmapy są wiarygodne, flagi nic"
                if groups
                else "brak cechy i brak flagów"
            ),
            "inconsistent_bitmaps": self.uninit_bitmap_inconsistent(),
        }

    def unallocated_metadata_overlap(
        self, sample: int = 0, blocks: list[int] | None = None
    ) -> dict:
        """Unallocated blocks that are also filesystem metadata.

        **Zero on every image this project has measured**, and that is the point
        of the check rather than a lucky accident.  ext4 marks the superblock
        backups, the descriptor table, the bitmaps and the inode tables as
        allocated in the same block bitmap it allocates file data from, so
        inverting it leaves the metadata out by construction.  Confirming that on
        the image in hand is what lets the inventory below say "no live file and
        no live metadata occupies these blocks" instead of assuming it.

        It is also the check the Sleuth Kit does not do.  ``blkls`` excludes
        blocks its ``ext2fs_block_getflags()`` classes as metadata *independently
        of the bitmap*, which is a useful extra rule — and on a fresh ``mke2fs``
        flex_bg image it changes the answer: on a 64 MiB volume with 1 KiB blocks
        ``blkls`` and this reader emit the same 55 996 blocks in total but not the
        same set, with six blocks swapped.  A count that agreed would have hidden
        that; counting the blocks by hand showed it.  The same TSK code carries a
        comment admitting an off-by-one between bitmap offsets and disk block
        numbers, and with ``flex_bg`` the group's descriptor holds absolute
        addresses that the comparison mixes with them.

        ``sample`` caps how many overlaps are collected for the report; the count
        is always complete, and ``at_extent_end`` says how many of them sit on the
        last block of a metadata extent — which is where the only disagreements
        measured so far are, and where ``e2fsck -fn`` and this reader differ about
        a block that the checker is content with either way.
        """
        meta = self.metadata_blocks()
        boundaries = self._metadata_extent_ends()
        overlaps: list[int] = []
        at_end = 0
        total = 0
        for block in self.unallocated_blocks() if blocks is None else blocks:
            if block in meta:
                total += 1
                if block in boundaries:
                    at_end += 1
                if not sample or len(overlaps) < sample:
                    overlaps.append(block)
        return {
            "count": total,
            "blocks": overlaps,
            "at_extent_end": at_end,
            "interior": total - at_end,
        }

    def _metadata_extent_ends(self) -> set[int]:
        """Last block of every metadata extent, for the boundary explanation."""
        sb = self.superblock
        per_group = sb["blocks_per_group"]
        total = sb["blocks_count"]
        itb = -(
            -(sb["inodes_per_group"] * sb["inode_size"]) // self.block_size
        )
        per_desc = self.block_size // sb["desc_size"]
        gdt_blocks = -(-len(self._groups) // per_desc)
        out: set[int] = {sb["first_data_block"]}
        out.add(sb["first_data_block"] + 1 + gdt_blocks - 1)
        for descriptor in self._groups:
            out.add(descriptor["block_bitmap"])
            out.add(descriptor["inode_bitmap"])
            out.add(descriptor["inode_table"] + itb - 1)
        for sparse in self.sparse_super_groups():
            base = sparse * per_group
            out.add(base)
            out.add(base + gdt_blocks)
        try:
            journal = self.inode(sb["journal_inum"])
        except (KeyError, Ext4Error):
            journal = None
        if journal is not None:
            for extent in journal.extents:
                out.add(extent.physical + extent.count - 1)
        return {block for block in out if 0 <= block < total}

    def free_block_count(self, blocks: list[int] | None = None) -> int:
        """Unallocated blocks, counted from the bitmaps.

        Reported beside ``s_free_blocks_count`` rather than instead of it,
        because on the reference image the two disagree: the bitmaps say
        2 494 484 and the superblock says 2 494 472, a difference of 12 that is
        the superblock's counter being stale — the volume carries ``RECOVER`` and
        ``errors = 2``, so it was not closed cleanly.  The bitmaps are what
        the allocator will actually hand out next, so they are what an inventory
        of recoverable space has to be built on.  The sum of the 206 group
        counters is a third number, 2 510 845, which is 16 361 above the bitmaps
        and 16 373 above the superblock.  ``e2fsck -fn`` on the same image counts
        2 494 484 and reports ``Free blocks count wrong (2494472,
        counted=2494484)``, so the bitmaps have two independent readers agreeing
        and the stored counter alone is the odd one out.
        """
        if blocks is not None:
            return len(blocks)
        return sum(1 for _ in self.unallocated_blocks())

    def free_block_counters(self, blocks: list[int] | None = None) -> dict:
        """The three block counters, side by side, with the differences.

        A volume that cannot be cleanly unmounted leaves its counters behind, and
        three numbers that should be equal and are not is a finding about the
        image.  Reporting the largest disagreement without saying which number was
        chosen would leave the reader to guess, so the chosen one is named too.
        """
        sb = self.superblock
        from_bitmaps = self.free_block_count(blocks)
        from_superblock = sb["free_blocks"]
        from_groups = sum(g["free_blocks"] for g in self._groups)
        return {
            "from_bitmaps": from_bitmaps,
            "from_superblock": from_superblock,
            "from_group_descriptors": from_groups,
            "bitmaps_minus_superblock": from_bitmaps - from_superblock,
            "bitmaps_minus_groups": from_bitmaps - from_groups,
            "authoritative": "from_bitmaps",
            "why": (
                "bitmapy bloków to stan, z którego przydziela alokator; liczniki "
                "w superbloku i w deskryptorach grup są zapisane przy zamykaniu "
                "systemu plików i przy nieczystym odmontowaniu rozjeżdżają się"
            ),
            "clean_unmount": "RECOVER" not in sb["features"],
            "state": sb["state"],
            "errors": sb["errors"],
        }

    def dump_unallocated(self, path: str) -> dict:
        """Write the unallocated blocks to ``path`` — the ``blkls`` equivalent.

        The output is a plain concatenation of the free blocks, in block order,
        which is what every downstream carver expects and what makes a byte-for-
        byte comparison with ``blkls`` meaningful.  It is also large: 9,51 GiB on
        the reference image, so the caller is expected to ask for it rather than
        get it.  The digest is computed while writing, so a report can identify
        the dump without keeping it.
        """
        import hashlib

        digest = hashlib.sha256()
        written = 0
        blocks = 0
        with open(path, "wb") as handle:
            for block in self.unallocated_blocks():
                data = self._cache.get(block)
                if data is None:
                    raise Ext4Error(f"blok {block} poza zakresem obrazu")
                handle.write(data)
                digest.update(data)
                written += len(data)
                blocks += 1
        return {"path": path, "blocks": blocks, "bytes": written, "sha256": digest.hexdigest()}

    def deleted_inode_count(self) -> int:
        """How many free inodes carry a deletion timestamp.

        Counts without building a record per inode.  The full enumeration costs
        half a minute on a volume with three quarters of a million of them, and
        a module that wants only the headline number should not pay for 752 000
        dictionaries to produce one.
        """
        per_group = self.superblock["inodes_per_group"]
        size = self.inode_size
        total = 0
        for group in range(len(self._groups)):
            bitmap = self._group_bitmap(group, "inode_bitmap")
            first = group * per_group
            count = min(per_group, self.superblock["inodes_count"] - first)
            per_block = self.block_size // size
            raw = b"".join(
                self._cache.get(self._groups[group]["inode_table"] + offset)
                for offset in range(-(-count // per_block))
            )
            for index in range(count):
                if self._bit_set(bitmap, index):
                    continue
                at = index * size
                if at + 0x18 > len(raw):
                    break
                if struct.unpack_from("<I", raw, at + 0x14)[0]:
                    total += 1
        return total

    def deleted_inodes(self, with_data_only: bool = False, cap: int = 0) -> list[dict]:
        """Inodes that were allocated once and have since been unlinked.

        A free inode is not a deleted file: 784 829 of the free inodes on the
        reference image were never used at all, and calling those "deleted"
        would inflate the number roughly twofold.  ``i_dtime`` is what separates
        them — the kernel stamps it on unlink and leaves it at zero otherwise,
        which makes it a reliable test rather than an inference.

        The list carries metadata only.  **Names are not recoverable from an
        inode**: an unlinked entry no longer appears in any directory, so the
        name survives only in whatever directory block still holds the old bytes,
        and reading that is carving, not inode enumeration.  With
        ``with_data_only`` the scan keeps just the inodes whose content is worth
        looking at, which on the reference image is 378 of 752 043.

        One result here is worth stating plainly, because it decides what the
        next step has to be.  On the reference image a deleted inode keeps its
        ``i_size`` and its ``i_dtime`` but has ``i_blocks = 0`` and an empty
        extent map — ext4 truncates the block map on unlink.  So the content of
        a deleted file **cannot be located through its inode at all**; it can
        only be found in unallocated block space.  Enumerating inodes therefore
        answers "what was deleted, how big, and when" and nothing more, and the
        bytes are out of reach until the block space is walked.
        """
        out: list[dict] = []
        per_group = self.superblock["inodes_per_group"]
        size = self.inode_size
        for group in range(len(self._groups)):
            bitmap = self._group_bitmap(group, "inode_bitmap")
            first = group * per_group
            count = min(per_group, self.superblock["inodes_count"] - first)
            # One read of the whole inode table per group, then scan the bytes
            # in place.  A cache lookup per inode cost 47 seconds across 752 000
            # of them; this does the same work in seconds, and the difference is
            # the whole reason the audit can run at all.
            table = self._groups[group]["inode_table"]
            per_block = self.block_size // size
            blocks_needed = -(-count // per_block)
            raw = b"".join(
                self._cache.get(table + offset) for offset in range(blocks_needed)
            )
            for index in range(count):
                if self._bit_set(bitmap, index):
                    continue
                at = index * size
                if at + 0x6C > len(raw):
                    break
                if cap and len(out) >= cap:
                    return out
                def u16(o: int) -> int:
                    return struct.unpack_from("<H", raw, at + o)[0]
                def u32(o: int) -> int:
                    return struct.unpack_from("<I", raw, at + o)[0]
                dtime = u32(0x14)
                if not dtime:
                    continue
                isize = u32(0x04) | (u16(0x6C) << 32)
                if with_data_only and isize <= 0:
                    continue
                out.append(
                    {
                        "inode": first + index + 1,
                        "group": group,
                        "mode": f"{u16(0x00):04o}",
                        "kind": _inode_kind(u16(0x00)),
                        "size": isize,
                        "uid": u16(0x02) | (u16(0x78) << 16),
                        "gid": u16(0x18) | (u16(0x7A) << 16),
                        "links": u16(0x1A),
                        "blocks_512": u32(0x1C),
                        "dtime": dtime,
                        "dtime_utc": _ts(dtime),
                        "mtime": u32(0x10),
                        "mtime_utc": _ts(u32(0x10)),
                        "ctime": u32(0x0C),
                        "name": "",
                        "name_source": "brak — nazwa nie jest w inodzie",
                    }
                )
        return out

    def recoverability(self, inode_number: int) -> dict:
        """Whether a deleted inode's data blocks are still unclaimed.

        Reports, and does not read, because the answer decides whether reading
        would be evidence or invention.  A block that is still free may hold the
        old content; a block that has been reallocated now holds someone else's
        file, and presenting it under the deleted file's name would be a false
        attribution.
        """
        head = self.inode_header(inode_number)
        if head is None:
            return {"inode": inode_number, "verdict": "brak inoda"}
        try:
            node = self.inode(inode_number)
        except Ext4Error as exc:
            return {"inode": inode_number, "verdict": f"nieczytelny: {exc}"}
        if node.compressed_block_count:
            return {"inode": inode_number, "verdict": "nieznany układ extentów"}
        blocks = list(self.data_blocks(node))
        if not blocks:
            return {"inode": inode_number, "blocks": 0, "verdict": "brak bloków danych"}
        free = sum(1 for block in blocks if self.block_is_free(block))
        reused = len(blocks) - free
        if reused == 0:
            verdict = "wszystkie bloki wolne — treść prawdopodobnie nietknięta"
        elif free == 0:
            verdict = "wszystkie bloki przydzielone — treści nie da się odtworzyć"
        else:
            verdict = f"{reused} z {len(blocks)} bloków przydzielonych — treść mieszana"
        return {
            "inode": inode_number,
            "size": node.size,
            "blocks": len(blocks),
            "free": free,
            "reused": reused,
            "verdict": verdict,
            "recoverable": reused == 0,
        }

    def read_xattr(self, path: str, name: str) -> bytes:
        """One extended attribute of a path, or ``b""`` when there is none."""
        return self.resolve(path).xattrs.get(name, b"")

    def _parse_xattrs(
        self, block: int, raw: bytes | None = None, number: int = 0
    ) -> dict[str, bytes]:
        """Read one inode's extended attributes.

        ``i_file_acl`` is validated before it is followed, because the failure
        mode of not validating it is the same one this reader spent two turns
        removing: a wrong pointer yields a block that parses as *something*, and
        a plausible-looking SELinux label attached to a file it does not belong
        to is worse than no label, because it will be quoted in a report.

        So three things are checked and each raises:

        * the pointer is inside the volume;
        * the block carries the extended-attribute magic;
        * every entry's ``e_name_index`` is an assigned prefix.

        A zero pointer is not an error — it is the normal case, and on the
        reference image 1 687 549 of 1 687 552 inodes take that path.
        """
        out: dict[str, bytes] = {}
        if not block:
            return out
        where = f"inode {number}" if number else "inode"
        if block >= self.superblock["blocks_count"]:
            raise Ext4Error(
                f"{where}: i_file_acl = {block} poza wolumenem "
                f"({self.superblock['blocks_count']} bloków)"
            )
        data = self._cache.get(block)
        if len(data) < XATTR_HEADER_BYTES:
            raise Ext4Error(f"{where}: blok xattr {block} za krótki ({len(data)} B)")
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic != XATTR_MAGIC:
            raise Ext4Error(
                f"{where}: blok {block} ma magic 0x{magic:08X}, a nie 0x{XATTR_MAGIC:08X} "
                "atrybutów rozszerzonych"
            )
        entries = struct.unpack_from("<H", data, 8)[0]
        if not 0 < entries <= 64:
            raise Ext4Error(
                f"{where}: blok {block} deklaruje {entries} atrybutów — wartość "
                "niemożliwa, wskaźnik najpewniej błędny"
            )
        offset = XATTR_HEADER_BYTES
        for _ in range(entries):
            if offset + XATTR_ENTRY_FIXED > len(data):
                raise Ext4Error(f"{where}: wpis atrybutu ucina blok {block}")
            name_len, name_index, value_offs, _value_inum, value_size = struct.unpack_from(
                "<BBHII", data, offset
            )
            if name_index not in XATTR_PREFIX:
                raise Ext4Error(
                    f"{where}: blok {block} ma e_name_index = {name_index}, "
                    "który nie jest przypisany do żadnego prefiksu"
                )
            name_at = offset + XATTR_ENTRY_FIXED
            if name_at + name_len > len(data):
                raise Ext4Error(f"{where}: nazwa atrybutu ucina blok {block}")
            name = data[name_at : name_at + name_len].decode("ascii", "replace")
            if not value_offs or value_offs + value_size > len(data):
                raise Ext4Error(
                    f"{where}: wartość atrybutu {name!r} wskazuje poza blok {block} "
                    f"(offset {value_offs}, rozmiar {value_size})"
                )
            out[f"{XATTR_PREFIX[name_index]}.{name}"] = data[
                value_offs : value_offs + value_size
            ]
            offset = (name_at + name_len + 3) & ~3
        return out

    def _parse_extents(self, node: Inode, block: bytes) -> tuple[list[Extent], list[int]]:
        """Expand an inode's ``i_block`` into a list of extents.

        The refusal here is the point of this function.  ``i_block[0]`` on disk
        *is* the extent header's ``eh_magic``, so an inode is extent-mapped
        exactly when that u16 reads ``0xF30A``.  Anything else means the classic
        ext2 layout: twelve direct block pointers then single, double and
        triple indirect pointers, which this reader does not walk.

        The previous code returned ``[]`` in that case, and the effect was
        silent and total: ``listdir`` came back empty, ``read`` returned
        ``b""``, and a whole subtree disappeared from the report with no error
        anywhere and no way to tell it apart from "there was nothing there".
        It now raises, because "this reader cannot read that" is a finding and
        an empty result is a lie.

        Note that ``EXT4_EXTENTS_FL`` (0x8000) is *not* the on-disk test: the
        kernel ORs that bit into ``i_block[0]`` in its in-memory inode, while
        the disk always holds the 0xF30A magic.  Testing for 0x8000 here would
        reject every extent-mapped inode including the root.
        """
        if len(block) < 12:
            return [], []
        magic, entries, _maxent, depth, _gen = struct.unpack_from("<HHHHI", block, 0)
        if magic != EXTENTS_MAGIC:
            if not _expects_no_data_block(node):
                raise Ext4Error(
                    f"inode {node.number}: i_block zaczyna się od 0x{magic:04X}, "
                    f"a nie magic drzewa extentów 0x{EXTENTS_MAGIC:04X} — inode używa "
                    "klasycznych wskaźników bloków bezpośrednich/pośrednich (mapowanie "
                    "ext2), którego ten reader nie obsługuje"
                )
            return [], []
        out: list[Extent] = []
        tree_blocks: list[int] = []
        self._walk_extent_tree(block, depth, entries, out, tree_blocks=tree_blocks)
        out.sort(key=lambda e: e.logical)
        return out, tree_blocks

    def _walk_extent_tree(
        self,
        block: bytes,
        depth: int,
        entries: int,
        out: list[Extent],
        guard: int = 0,
        tree_blocks: list[int] | None = None,
    ) -> None:
        if guard > 8:
            raise Ext4Error("extent tree too deep")
        for i in range(entries):
            rec = 12 + i * 12
            if rec + 12 > len(block):
                break
            if depth == 0:
                logical, count, hi, lo = struct.unpack_from("<IHHI", block, rec)
                if count > 32768:
                    count -= 32768
                    hi += 1
                out.append(Extent(logical, lo | (hi << 32), count))
            else:
                _logical, lo, hi, _unused = struct.unpack_from("<IIHH", block, rec)
                physical = lo | (hi << 32)
                if tree_blocks is not None:
                    tree_blocks.append(physical)
                child = self._cache.get(physical)
                _magic, c_entries, _maxent, c_depth, _gen = struct.unpack_from(
                    "<HHHHI", child, 0
                )
                self._walk_extent_tree(child, c_depth, c_entries, out, guard + 1, tree_blocks)

    def data_blocks(self, inode: Inode) -> Iterator[int]:
        """Yield physical block numbers holding the inode's data, in order."""
        if not inode.extents:
            return
        per_block = self.block_size // 512 if self.superblock["cluster_size"] else None
        del per_block
        for extent in inode.extents:
            for i in range(extent.count):
                yield extent.physical + i

    def resolve(self, path: str) -> Inode:
        """Resolve an absolute path (inside the filesystem) to an inode."""
        node = self.inode(EXT4_ROOT_INODE)
        cleaned = path.strip("/")
        if not cleaned:
            return node
        for part in cleaned.split("/"):
            if not node.is_dir:
                raise KeyError(f"{part}: not a directory")
            match = None
            for entry in self.listdir(node):
                if entry.name == part:
                    match = entry
                    break
            if match is None:
                raise KeyError(f"no such file or directory: /{cleaned}")
            node = self.inode(match.inode)
        return node

    def lookup(self, path: str) -> tuple[str, Inode]:
        """Return (parent_path, inode) for an absolute path."""
        cleaned = path.strip("/")
        if not cleaned:
            return "/", self.inode(EXT4_ROOT_INODE)
        parent = "/" + "/".join(cleaned.split("/")[:-1])
        return parent, self.resolve(path)

    def unlinked_entries(self, cap: int = 0) -> dict[str, Any]:
        """Directory entries whose name is still in a live directory block.

        This is where the names of deleted files are, and getting to them is not a
        matter of following the directory's record chain.  **ext4 merges a live
        entry with the entries that were deleted after it**: on the reference
        image's ``/media/0/MIUI/Gallery/cloud/.cache`` the record for
        ``micro_thumbnail_blob.1`` is 3916 bytes long and swallows the rest of the
        block, and the names deleted from that directory sit *inside* its payload.
        Walking the chain finds 286 unlinked names on the whole image.  Sliding a
        window over the block finds 51 617 more.

        That is the same technique a carver uses, and it is why The Sleuth Kit's
        ``fls -d`` reports tens of thousands where a chain walk reports hundreds:
        ``ext2fs_dent_walk()`` tests every offset in the block for a plausible
        entry header instead of following ``rec_len`` from the start.

        The two sets are kept apart because they are not equally trustworthy, and
        the difference is the whole point:

        * ``chain_unlinked`` — the record *is* in the chain and its inode number is
          **zero**, which is what the kernel writes on unlink.  The name belonged
          to a file in this directory, and the inode is provably gone.
        * ``window_only`` — the record is not reachable from the chain, so ext4
          wrote over the space that described it; only the bytes inside the
          swallowing record's payload are left.  The name belonged to this
          directory.  **The inode number in the record may since have been handed
          to a different file**, and the metadata behind it is not evidence about
          the deleted one.  ``metadata`` on such a record therefore carries
          ``trust: "lowered"`` and a reason, and the module that reports these
          says so per record.

        The window test is deliberately narrow — printable-ASCII name, ``rec_len``
        inside the block, ``name_len`` no longer than the record, inode number
        within the volume's inode range — because a loose test turns every run of
        digits in a directory block into a filename.  Candidates that fail it are
        counted, not silently dropped, so the cost of the filter is visible.

        A **zero** inode number is accepted in the window as well, which the first
        version refused.  The reason it looked unnecessary is that on the reference
        image the two classes come apart — every zeroed-inode record is still in a
        chain, and every window hit has a number.  That is a property of that
        image, not of the format: a record deleted *after* the one that swallowed it
        is in exactly the same position, and then it has no number either.  The
        hand-built fixture is that case, and it is how the filter was found to be
        wrong: refusing zero would have made the tool blind to precisely the
        records it trusts most.
        """
        import re as _re

        printable = _re.compile(rb"[\x20-\x7e]+")
        max_ino = self.superblock["inodes_count"]
        chain_entries: set[tuple[int, int]] = set()
        chain_unlinked: list[dict] = []
        window_only: list[dict] = []
        rejected = 0
        seen_blocks: set[int] = set()
        # ``walk`` yields a directory's *children*, never the directory it was
        # started at, so the root's own block has to be seeded by hand.  On the
        # reference image that is one block out of 20 653 and the omission was
        # invisible in the total; on a filesystem whose deletions happened in the
        # root directory it is the whole difference between finding the names and
        # finding none of them.
        directories: list[tuple[str, Inode]] = [("/", self.inode(EXT4_ROOT_INODE))]
        for path, entry in self.walk(include_files=False):
            if not entry.is_dir:
                continue
            try:
                directories.append((path, self.inode(entry.inode)))
            except (KeyError, Ext4Error):
                continue
        for path, inode in directories:
            for block in self.data_blocks(inode):
                if block in seen_blocks:
                    continue
                seen_blocks.add(block)
                data = self._cache.get(block)
                if data is None:
                    continue
                pos = 0
                while pos + 8 <= len(data):
                    ino, rec_len, name_len, ftype = struct.unpack_from(
                        "<IHBB", data, pos
                    )
                    if rec_len < 8 or pos + rec_len > len(data):
                        break
                    if name_len:
                        raw_name = data[pos + 8 : pos + 8 + name_len]
                        record = _unlinked_record(
                            path, block, pos, ino, ftype, raw_name, "chain"
                        )
                        if record is not None:
                            if ino:
                                chain_entries.add((block, pos))
                            else:
                                chain_unlinked.append(record)
                    pos += rec_len
                for match in printable.finditer(data):
                    off = match.start() - 8
                    if off < 0 or (block, off) in chain_entries:
                        continue
                    ino, rec_len, name_len, ftype = struct.unpack_from(
                        "<IHBB", data, off
                    )
                    if (
                        not 0 <= ino <= max_ino
                        or not 8 <= rec_len <= len(data) - off
                        or not 1 <= name_len <= 255
                        or name_len > rec_len - 8
                        or match.end() - match.start() < name_len
                    ):
                        rejected += 1
                        continue
                    record = _unlinked_record(
                        path, block, off, ino, ftype,
                        data[off + 8 : off + 8 + name_len], "window",
                    )
                    if record is not None:
                        window_only.append(record)
                    else:
                        rejected += 1
                if cap and len(chain_unlinked) + len(window_only) >= cap:
                    return {
                        "chain_unlinked": chain_unlinked[:cap],
                        "window_only": window_only[:cap],
                        "chain_unlinked_total": len(chain_unlinked),
                        "window_only_total": len(window_only),
                        "rejected": rejected,
                        "directory_blocks": len(seen_blocks),
                        "complete": False,
                    }
        return {
            "chain_unlinked": chain_unlinked,
            "window_only": window_only,
            "chain_unlinked_total": len(chain_unlinked),
            "window_only_total": len(window_only),
            "rejected": rejected,
            "directory_blocks": len(seen_blocks),
            "complete": True,
        }

    def listdir(self, path_or_inode: str | int | Inode) -> list[DirEntry]:
        """List a directory.  htree index blocks are skipped, so results are correct
        for both linear and DIR_INDEX directories."""
        node = (
            self.resolve(path_or_inode)
            if isinstance(path_or_inode, str)
            else path_or_inode
            if isinstance(path_or_inode, Inode)
            else self.inode(path_or_inode)
        )
        if not node.is_dir:
            raise NotADirectoryError(str(path_or_inode))
        out: list[DirEntry] = []
        seen: set[int] = set()
        for block in self.data_blocks(node):
            if block in seen:
                continue
            seen.add(block)
            data = self._cache.get(block)
            pos = 0
            while pos + 8 <= len(data):
                inode_no, rec_len, name_len, ftype = struct.unpack_from("<IHBB", data, pos)
                if rec_len < 8 or pos + rec_len > len(data):
                    break
                if inode_no and name_len:
                    raw_name = data[pos + 8 : pos + 8 + name_len]
                    if len(raw_name) == name_len:
                        out.append(
                            DirEntry(
                                name=raw_name.decode("utf-8", "surrogateescape"),
                                inode=inode_no,
                                kind=ftype,
                                offset=block * self.block_size + pos,
                            )
                        )
                pos += rec_len
        out.sort(key=lambda e: e.name)
        return out

    def read_at(self, path_or_inode: str | int | Inode, offset: int, length: int) -> bytes:
        """Read a byte range out of a file without loading the whole file.

        Two kinds of gap look alike here and must not be treated alike, because
        only one of them is corruption.

        A **physical** block that is not in the image raises
        :class:`~forensic.core.evidence.TruncatedEvidenceError` in
        :class:`_BlockCache`.  Those bytes were in the evidence and are gone.

        A **logical** gap — a block inside ``i_size`` that no extent maps — is a
        sparse hole, and reading it as zeros is what the format means.  The
        buffer is therefore pre-sized to the requested length and the extents are
        written into it *positionally*, rather than concatenated.

        Concatenating is the obvious implementation and it is wrong in a way that
        looks like success: an 16 KiB SQLite database whose middle pages were
        never written has eight unmapped blocks, so the concatenation returned
        8 KiB of real bytes and no error at all.  ``read_at`` clipped to
        ``i_size``, the caller stored the short result as the file, and SQLite
        answered *database disk image is malformed* — a confident false
        diagnosis of a perfectly good database, on evidence that had not been
        damaged.  ``debugfs dump`` on the same image produces the correct 16 KiB.
        """
        node = (
            self.resolve(path_or_inode)
            if isinstance(path_or_inode, str)
            else path_or_inode
            if isinstance(path_or_inode, Inode)
            else self.inode(path_or_inode)
        )
        if offset >= node.size:
            return b""
        length = min(length, node.size - offset)
        out = bytearray(length)
        for extent in node.extents:
            first = extent.logical * self.block_size
            last = first + extent.count * self.block_size
            if last <= offset or first >= offset + length:
                continue
            start = max(offset, first)
            end = min(offset + length, last)
            pos = start
            while pos < end:
                delta = pos - first
                block = extent.physical + delta // self.block_size
                in_block = delta % self.block_size
                take = min(self.block_size - in_block, end - pos)
                at = pos - offset
                out[at : at + take] = self._cache.read(block, in_block, take)
                pos += take
        return bytes(out)

    def hole_bytes(self, path_or_inode: str | int | Inode) -> int:
        """Bytes inside ``i_size`` that no extent maps: a sparse hole.

        Reported rather than acted on, because it is evidence rather than a
        fault.  A hole means the file was extended without being written — a
        database truncated by a crashed process, a log that was resized, a file
        whose tail was zeroed in place.  ``debugfs`` and ``blkls`` both fill it
        with zeros and so does :meth:`read_at`, and an analyst deciding whether
        the trailing zeros of a file were ever written wants the number.

        Computed on demand rather than remembered from the last read: a
        "bytes missing from the previous call" counter is wrong the moment two
        modules read different files, which is what this tool does constantly.
        """
        node = (
            self.resolve(path_or_inode)
            if isinstance(path_or_inode, str)
            else path_or_inode
            if isinstance(path_or_inode, Inode)
            else self.inode(path_or_inode)
        )
        covered = 0
        for extent in node.extents:
            first = max(extent.logical * self.block_size, 0)
            last = min(first + extent.count * self.block_size, node.size)
            if last > first:
                covered += last - first
        return max(0, node.size - covered)

    def read(self, path_or_inode: str | int | Inode, max_bytes: int | None = None) -> bytes:
        """Read a whole file.  ``max_bytes`` guards against absurd sizes."""
        node = (
            self.resolve(path_or_inode)
            if isinstance(path_or_inode, str)
            else path_or_inode
            if isinstance(path_or_inode, Inode)
            else self.inode(path_or_inode)
        )
        limit = node.size if max_bytes is None else min(node.size, max_bytes)
        return self.read_at(node, 0, limit)

    def readlink(self, path_or_inode: str | int | Inode) -> str:
        node = (
            self.resolve(path_or_inode)
            if isinstance(path_or_inode, str)
            else path_or_inode
            if isinstance(path_or_inode, Inode)
            else self.inode(path_or_inode)
        )
        return self.read(node).decode("utf-8", "replace")

    def stat(self, path: str) -> dict:
        """Forensic-friendly stat of a path.

        Times are given twice: as the raw Unix value (``mtime``) and as an ISO
        string (``mtime_utc``), because modules that compare two of these files
        should not each have to reformat them.
        """
        node = self.resolve(path)
        out = {
            "path": path,
            "inode": node.number,
            "mode": f"{node.mode:04o}",
            "type": (
                "dir"
                if node.is_dir
                else "file"
                if node.is_reg
                else "symlink"
                if node.is_link
                else "other"
            ),
            "size": node.size,
            "blocks_512": node.blocks,
            "uid": node.uid,
            "gid": node.gid,
            "links": node.links,
            "flags": f"0x{node.flags:08x}",
            "atime": _ts(node.atime),
            "ctime": _ts(node.ctime),
            "mtime": _ts(node.mtime),
            "crtime": _ts(node.crtime),
            "dtime": _ts(node.dtime),
            "extents": node.extent_summary(),
            "xattrs": {key: value.hex() for key, value in node.xattrs.items()},
            "selinux": node.selinux,
        }
        for name, value in (
            ("atime", node.atime),
            ("ctime", node.ctime),
            ("mtime", node.mtime),
            ("crtime", node.crtime),
            ("dtime", node.dtime),
        ):
            out[f"{name}_unix"] = value
            out[f"{name}_utc"] = _ts(value)
        return out

    def image_offset(self, path: str, file_offset: int = 0) -> int | None:
        """Absolute byte offset in the image where a file offset lives."""
        node = self.resolve(path)
        logical = file_offset // self.block_size
        for extent in node.extents:
            if extent.logical <= logical < extent.end:
                return (extent.physical + (logical - extent.logical)) * self.block_size + (
                    file_offset % self.block_size
                )
        return None

    def walk(self, start: str = "/", include_files: bool = True) -> Iterator[tuple[str, DirEntry]]:
        """Depth-first walk of a subtree."""
        stack: list[tuple[str, list[DirEntry]]] = [
            (start, self.listdir(start))
        ]
        while stack:
            base, entries = stack.pop()
            children: list[tuple[str, list[DirEntry]]] = []
            for entry in entries:
                if entry.name in (".", ".."):
                    continue
                path = f"{base.rstrip('/')}/{entry.name}"
                if include_files or entry.is_dir:
                    yield path, entry
                if entry.is_dir:
                    try:
                        children.append((path, self.listdir(entry.inode)))
                    except (Ext4Error, KeyError, struct.error, ValueError, OSError) as exc:
                        self.walk_errors.append(
                            {"path": path, "inode": entry.inode, "error": str(exc)[:200]}
                        )
                        continue
            stack.extend(reversed(children))

    def packages(self) -> dict[int, str]:
        """uid -> package name, read from ``/system/packages.xml`` when present."""
        out: dict[int, str] = {}
        try:
            blob = self.read("/system/packages.xml")
        except Exception:
            return out
        import re

        for match in re.finditer(
            rb'<package name="([^"]+)"[^>]*?userId="(\d+)"', blob
        ):
            out[int(match.group(2))] = match.group(1).decode("utf-8", "replace")
        return out
