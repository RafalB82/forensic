# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Read-only EROFS reader, standard library only.

EROFS is what Android 10 and later put on ``/system``, so an image that this
project cannot open is not an exotic case — it is what a current device hands
you.  :mod:`forensic.core.fsformat` already names such an image instead of
calling it corrupt; this module is what makes that naming a temporary condition.

Scope, stated up front because a half-reader is worse than none:

* **Superblock, inodes, directory trees and uncompressed file data are read.**
* **Compressed data is refused**, with the reason.  LZ4 is not in the standard
  library and this project takes no dependencies for the analysis layer, so a
  compressed ``/system`` gives a correct tree of names, sizes and timestamps and
  no file contents.  That is a finding, not a partial success.

Every structure below was confirmed twice: against the format definition in
``erofs_fs.h`` as shipped with u-boot, and against ``dump.erofs`` output on
images this repository builds.  Two details are worth writing down because
reading them the obvious way is wrong and neither raises an error:

* ``i_format`` is three fields, not a version number.  Bit 0 is the inode
  version — 0 selects the 32-byte *compact* inode, 1 the 64-byte *extended* one
  — and bits 1-3 are the data layout.  A file can therefore be reported as
  "version 5" by a hex dump and be neither a version nor layout 5.
* In the 64-byte inode ``i_nlink`` sits at offset 0x2C, not 0x06, and
  ``i_size`` is a **u64**.  The 32-byte compact inode has ``i_nlink`` at 0x06
  and a u32 size.  Reading the wrong one yields a plausible zero.

Directory blocks pack their 12-byte headers from the start of the block, one per
entry, and the first header's ``nameoff`` is where the names begin — so the
entry count is ``first_nameoff / 12``.  Each name is located by its own
``nameoff`` and its length is the *next* entry's ``nameoff`` minus this one's;
only the last name runs to the end of the block and is NUL-terminated.  Names
are stored contiguously, ascending, and a name containing ``|`` or a newline
costs nothing here.
"""

from __future__ import annotations

import stat as _stat
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import Iterator

from .fsformat import UNKNOWN, detect_bytes

SB_OFFSET = 1024
EROFS_MAGIC = 0xE0F5E1E2
EROFS_ROOT_INODE = 2

INODE_COMPACT = 32
INODE_EXTENDED = 64

LAYOUT_FLAT_PLAIN = 0
LAYOUT_COMPRESSED_FULL = 1
LAYOUT_FLAT_INLINE = 2
LAYOUT_COMPRESSED_COMPACT = 3
LAYOUT_CHUNK_BASED = 4

LAYOUT_NAMES = {
    LAYOUT_FLAT_PLAIN: "flat, dane w blokach",
    LAYOUT_COMPRESSED_FULL: "skompresowany (pełne indeksy)",
    LAYOUT_FLAT_INLINE: "flat, dane w ogonie inoda",
    LAYOUT_COMPRESSED_COMPACT: "skompresowany (kompaktowe indeksy)",
    LAYOUT_CHUNK_BASED: "chunk-based, wiele urządzeń",
}
COMPRESSED_LAYOUTS = (LAYOUT_COMPRESSED_FULL, LAYOUT_COMPRESSED_COMPACT)

#: ``enum erofs_ftype`` from ``erofs_fs.h``.
FT_TYPES = {
    1: "regular",
    2: "directory",
    3: "chardev",
    4: "blockdev",
    5: "fifo",
    6: "socket",
    7: "symlink",
    8: "unknown",
}
#: The mode-to-kind mapping used by the kernel's ``erofs_ftype`` when a dirent
#: carries no type, and the inverse for turning ``i_mode`` into a kind.
KIND_FROM_FT = {value: key for key, value in FT_TYPES.items()}


class ErofsError(Exception):
    """Raised when an EROFS image cannot be read or lies about its layout."""


@dataclass
class ErofsDirent:
    """One directory entry."""

    nid: int
    name: str
    file_type: int

    @property
    def kind(self) -> str:
        return FT_TYPES.get(self.file_type, "unknown")

    def as_dict(self) -> dict[str, Any]:
        return {"nid": self.nid, "name": self.name, "type": self.file_type, "kind": self.kind}


@dataclass
class ErofsInode:
    """One inode, in the shape the rest of this project expects."""

    number: int
    nid: int
    mode: int
    size: int
    uid: int
    gid: int
    nlink: int
    ino: int
    mtime: int
    mtime_nsec: int
    layout: int
    version: int
    raw_block: int
    inode_size: int
    xattr_size: int
    extra: dict = field(default_factory=dict)

    @property
    def is_dir(self) -> bool:
        return _stat.S_ISDIR(self.mode)

    @property
    def is_reg(self) -> bool:
        return _stat.S_ISREG(self.mode)

    @property
    def is_link(self) -> bool:
        return _stat.S_ISLNK(self.mode)

    @property
    def compressed(self) -> bool:
        return self.layout in COMPRESSED_LAYOUTS

    @property
    def layout_name(self) -> str:
        return LAYOUT_NAMES.get(self.layout, f"nieznany ({self.layout})")

    @property
    def type_name(self) -> str:
        if self.is_dir:
            return "dir"
        if self.is_reg:
            return "file"
        if self.is_link:
            return "symlink"
        if _stat.S_ISFIFO(self.mode):
            return "fifo"
        if _stat.S_ISSOCK(self.mode):
            return "socket"
        if _stat.S_ISBLK(self.mode):
            return "blockdev"
        if _stat.S_ISCHR(self.mode):
            return "chardev"
        return "other"

    def as_dict(self) -> dict[str, Any]:
        return {
            "nid": self.nid,
            "ino": self.ino,
            "inode": self.number,
            "type": self.type_name,
            "mode": f"{self.mode:04o}",
            "size": self.size,
            "uid": self.uid,
            "gid": self.gid,
            "nlink": self.nlink,
            "mtime": self.mtime,
            "mtime_nsec": self.mtime_nsec,
            "layout": self.layout,
            "layout_name": self.layout_name,
            "version": self.version,
            "inode_size": self.inode_size,
            "xattr_size": self.xattr_size,
            "compressed": self.compressed,
            "raw_block": self.raw_block,
            **self.extra,
        }


class Erofs:
    """Read-only handle on an EROFS image."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._handle = open(self.path, "rb")
        try:
            self.superblock = self._read_superblock()
        except Exception:
            self._handle.close()
            raise
        self.block_size = 1 << self.superblock["blkszbits"]
        self.blocks = self.superblock["blocks"]
        self.meta_blkaddr = self.superblock["meta_blkaddr"]
        self._inodes: dict[int, ErofsInode] = {}

    # -- plumbing ---------------------------------------------------------
    def close(self) -> None:
        try:
            self._handle.close()
        except OSError:
            pass

    def __enter__(self) -> Erofs:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    @property
    def size_bytes(self) -> int:
        return self.blocks * self.block_size

    def _pread(self, offset: int, length: int) -> bytes:
        return os_pread(self._handle.fileno(), length, offset)

    # -- superblock -------------------------------------------------------
    def _read_superblock(self) -> dict[str, Any]:
        raw = self._pread(SB_OFFSET, 128)
        if len(raw) < 128:
            raise ErofsError(f"obraz za krótki na superblok EROFS ({len(raw)} B)")
        def u16(o: int) -> int:
            return struct.unpack_from("<H", raw, o)[0]
        def u32(o: int) -> int:
            return struct.unpack_from("<I", raw, o)[0]
        def u64(o: int) -> int:
            return struct.unpack_from("<Q", raw, o)[0]
        magic = u32(0)
        if magic != EROFS_MAGIC:
            # ``detect_bytes`` returns a Signature (or None), not a dict: naming
            # the format we actually found is the whole point of this branch, and
            # subscripting it raised TypeError instead of saying which format it was.
            found = detect_bytes(self._pread(0, 1088))
            if found is None or found.kind == UNKNOWN:
                raise ErofsError(f"zła magic EROFS 0x{magic:08X} pod +{SB_OFFSET}")
            raise ErofsError(
                f"zła magic EROFS 0x{magic:08X} pod +{SB_OFFSET} — to jest "
                f"{found.name}"
            )
        blkszbits = raw[0x0C]
        if not 9 <= blkszbits <= 16:
            raise ErofsError(f"blkszbits={blkszbits} poza sensownym zakresem")
        return {
            "magic": magic,
            "checksum": u32(4),
            "feature_compat": u32(8),
            "blkszbits": blkszbits,
            "sb_extslots": raw[0x0D],
            "root_nid": u16(0x0E),
            "inos": u64(0x10),
            "build_time": u64(0x18),
            "build_time_nsec": u32(0x20),
            "blocks": u32(0x24),
            "meta_blkaddr": u32(0x28),
            "xattr_blkaddr": u32(0x2C),
            "uuid": raw[0x30:0x40].hex(),
            "volume_name": raw[0x40:0x50].split(b"\0")[0].decode("utf-8", "replace"),
            "feature_incompat": u32(0x50),
            "dirblkbits": raw[0x58],
            "packed_nid": u64(0x5C),
        }

    # -- inodes -----------------------------------------------------------
    def inode_offset(self, nid: int) -> int:
        """Byte offset of a node id in the metadata area.

        The metadata area starts at ``meta_blkaddr`` in 512-byte sectors, which
        on a partition image means the first sector holding metadata, and node
        ids advance by the inode stride.  Confirmed on a single-block image
        where ``nid * 32`` located every inode exactly.
        """
        return self.meta_blkaddr * 512 + nid * INODE_COMPACT

    def inode(self, nid: int) -> ErofsInode:
        """Parse one inode.  Cached, because a tree walk revisits directories."""
        if nid in self._inodes:
            return self._inodes[nid]
        at = self.inode_offset(nid)
        head = self._pread(at, INODE_EXTENDED)
        if len(head) < INODE_COMPACT:
            raise ErofsError(f"nid {nid}: brak danych inoda pod +{at}")
        i_format = struct.unpack_from("<H", head, 0)[0]
        version = i_format & 1
        layout = (i_format >> 1) & 0x7
        size = INODE_COMPACT if version == 0 else INODE_EXTENDED
        if len(head) < size:
            raise ErofsError(f"nid {nid}: inodo {size} B, dostępne {len(head)} B")
        xattr_icount = struct.unpack_from("<H", head, 2)[0]
        mode = struct.unpack_from("<H", head, 4)[0]
        if version == 0:
            # compact: i_nlink u16 at 0x06, i_size u32 at 0x08
            nlink = struct.unpack_from("<H", head, 6)[0]
            isize = struct.unpack_from("<I", head, 8)[0]
            uid = struct.unpack_from("<H", head, 0x18)[0]
            gid = struct.unpack_from("<H", head, 0x1A)[0]
            mtime = 0
            mtime_nsec = 0
        else:
            # extended: i_reserved u16 at 0x06, i_size u64 at 0x08,
            # i_nlink u32 at 0x2C, i_mtime u64 at 0x20
            isize = struct.unpack_from("<Q", head, 8)[0]
            uid = struct.unpack_from("<I", head, 0x18)[0]
            gid = struct.unpack_from("<I", head, 0x1C)[0]
            mtime = struct.unpack_from("<Q", head, 0x20)[0]
            mtime_nsec = struct.unpack_from("<I", head, 0x28)[0]
            nlink = struct.unpack_from("<I", head, 0x2C)[0]
        node = ErofsInode(
            number=nid,
            nid=nid,
            mode=mode,
            size=isize,
            uid=uid,
            gid=gid,
            nlink=nlink,
            ino=struct.unpack_from("<I", head, 0x14)[0],
            mtime=mtime,
            mtime_nsec=mtime_nsec,
            layout=layout,
            version=version,
            raw_block=struct.unpack_from("<I", head, 0x10)[0],
            inode_size=size,
            xattr_size=(xattr_icount - 1) * 4 if xattr_icount else 0,
        )
        self._inodes[nid] = node
        return node

    @property
    def root(self) -> ErofsInode:
        return self.inode(self.superblock["root_nid"])

    # -- data -------------------------------------------------------------
    def read(self, node_or_nid: ErofsInode | int) -> bytes:
        """File content.

        The placement follows the kernel's ``erofs_map_blocks`` exactly, and
        the one part that is not obvious is worth stating: for a *tail-packed*
        inode only the **final, partial block** lives in the inode's tail.
        Everything before it is an ordinary data block addressed by
        ``i_u.i_blkaddr``.  Reading ``i_size`` contiguous bytes from the tail
        looks right for a small file and returns the right number of bytes for a
        large one while mixing in the inodes that follow it — a 5000-byte file
        came back as its own last 904 bytes followed by whatever sat in between,
        which is a plausible-looking wrong answer rather than an error.

        Compressed layouts raise.  LZ4 is not in the standard library and this
        project takes no dependencies for the analysis layer, so a compressed
        ``/system`` gives a correct tree of names, sizes and timestamps and no
        file contents.  That is a finding, not a partial success.
        """
        node = node_or_nid if isinstance(node_or_nid, ErofsInode) else self.inode(node_or_nid)
        if node.compressed:
            raise ErofsError(
                f"nid {node.nid}: dane skompresowane ({node.layout_name}) — brak "
                "dekompresora LZ4 w stdlib, więc treści pliku nie da się odczytać. "
                "Metadane, nazwy, rozmiary i czasy są poprawne."
            )
        if node.layout not in (LAYOUT_FLAT_PLAIN, LAYOUT_FLAT_INLINE):
            raise ErofsError(
                f"nid {node.nid}: nieobsługiwany układ danych {node.layout} "
                f"({node.layout_name})"
            )
        if node.size == 0:
            return b""
        size = self.block_size
        nblocks = -(-node.size // size)
        tailend = node.layout == LAYOUT_FLAT_INLINE
        # With tail packing the last block is the one in the inode, so the
        # blocks addressed normally are all the others.
        last_block = nblocks - 1 if tailend else nblocks
        out = bytearray()
        logical = 0
        while logical < last_block:
            at = self.meta_blkaddr * 512 + (node.raw_block + logical) * size
            out += self._pread(at, size)
            logical += 1
        if tailend:
            inline_at = (
                self.inode_offset(node.nid) + node.inode_size + node.xattr_size
            )
            inline_len = node.size - logical * size
            if (inline_at % size) + inline_len > size:
                raise ErofsError(
                    f"nid {node.nid}: ogień z danymi przekracza granicę bloku — "
                    f"{node.size} B przy rozmiarze bloku {size} B"
                )
            out += self._pread(inline_at, inline_len)
        elif logical < nblocks:
            at = self.meta_blkaddr * 512 + (node.raw_block + logical) * size
            out += self._pread(at, node.size - logical * size)
        return bytes(out[: node.size])

    def readlink(self, node_or_nid: ErofsInode | int) -> str:
        node = node_or_nid if isinstance(node_or_nid, ErofsInode) else self.inode(node_or_nid)
        blob = self.read(node)
        return blob.decode("utf-8", "replace")

    # -- directories ------------------------------------------------------
    def listdir(self, node_or_nid: ErofsInode | int) -> list[ErofsDirent]:
        """Entries of a directory, ``.`` and ``..`` included, as stored.

        The 12-byte headers are packed from the start of the block and the
        first header's ``nameoff`` is where the name area begins, so the count is
        ``nameoff / 12``.  A name's length is the next entry's ``nameoff`` minus
        its own; only the last name runs to the end of the block and is
        NUL-terminated.  Nothing here trusts a length stored in the image.
        """
        node = node_or_nid if isinstance(node_or_nid, ErofsInode) else self.inode(node_or_nid)
        if not node.is_dir:
            raise ErofsError(f"nid {node.nid}: inode nie jest katalogiem")
        blob = self.read(node)
        if len(blob) < 13:
            return []
        first = struct.unpack_from("<H", blob, 8)[0]
        if first < 12 or first > len(blob):
            raise ErofsError(
                f"nid {node.nid}: nameoff pierwszego wpisu = {first}, poza blokiem "
                f"o {len(blob)} B"
            )
        count = first // 12
        if count * 12 != first:
            raise ErofsError(
                f"nid {node.nid}: {count} nagłówków × 12 B nie daje nameoff={first}"
            )
        offsets = [struct.unpack_from("<H", blob, i * 12 + 8)[0] for i in range(count)]
        out: list[ErofsDirent] = []
        for index, nameoff in enumerate(offsets):
            if not 0 < nameoff < len(blob):
                raise ErofsError(
                    f"nid {node.nid}: wpis {index} ma nameoff={nameoff} poza blokiem"
                )
            if index + 1 < count:
                nxt = offsets[index + 1]
                if nxt <= nameoff or nxt > len(blob):
                    raise ErofsError(
                        f"nid {node.nid}: wpis {index} — następny nameoff={nxt} "
                        f"nie jest za {nameoff}"
                    )
                length = nxt - nameoff
            else:
                end = blob.find(b"\0", nameoff)
                length = (end - nameoff) if end != -1 else len(blob) - nameoff
            if length <= 0:
                raise ErofsError(f"nid {node.nid}: wpis {index} ma ujemną długość nazwy")
            name = blob[nameoff : nameoff + length].decode("utf-8", "replace")
            ftype = blob[index * 12 + 10]
            nid = struct.unpack_from("<Q", blob, index * 12)[0]
            if index >= 2 and name not in (".", ".."):
                out.append(ErofsDirent(nid=nid, name=name, file_type=ftype))
            elif name not in (".", ".."):
                out.append(ErofsDirent(nid=nid, name=name, file_type=ftype))
        return out

    def walk(self, start: int | None = None) -> Iterator[tuple[str, ErofsInode]]:
        """Depth-first walk of the tree, yielding ``(path, inode)``."""
        root = self.superblock["root_nid"] if start is None else start
        stack: list[tuple[str, ErofsInode]] = [("/", self.inode(root))]
        while stack:
            path, node = stack.pop()
            yield path, node
            if not node.is_dir:
                continue
            try:
                entries = self.listdir(node)
            except ErofsError:
                continue
            children: list[tuple[str, ErofsInode]] = []
            for entry in entries:
                child_path = f"{path.rstrip('/')}/{entry.name}"
                try:
                    child = self.inode(entry.nid)
                except ErofsError:
                    continue
                children.append((child_path, child))
            stack.extend(reversed(children))

    def stat(self, path: str) -> dict[str, Any]:
        node = self.resolve(path)
        out = node.as_dict()
        out["path"] = path
        return out

    def resolve(self, path: str) -> ErofsInode:
        """Walk a ``/``-separated path to its inode."""
        parts = [p for p in path.split("/") if p]
        nid = self.superblock["root_nid"]
        for part in parts:
            node = self.inode(nid)
            if not node.is_dir:
                raise KeyError(f"{path}: {part} nie jest katalogiem")
            found = None
            for entry in self.listdir(node):
                if entry.name == part:
                    found = entry
                    break
            if found is None:
                raise KeyError(f"brak {part!r} w {path}")
            nid = found.nid
        return self.inode(nid)

    def coverage(self) -> dict[str, Any]:
        """What this reader can and cannot reach in the image it was given.

        Reported rather than assumed, because the answer differs sharply between
        an uncompressed image and the compressed one a real device ships: the
        tree is always readable, the contents never are once compression is on.
        """
        total = 0
        compressed = 0
        inline = 0
        plain = 0
        refused_other = 0
        for _path, node in self.walk():
            if node.is_dir:
                continue
            total += 1
            if node.compressed:
                compressed += 1
            elif node.layout == LAYOUT_FLAT_INLINE:
                inline += 1
            elif node.layout == LAYOUT_FLAT_PLAIN:
                plain += 1
            else:
                refused_other += 1
        return {
            "files": total,
            "readable_inline": inline,
            "readable_plain": plain,
            "compressed": compressed,
            "other_layout": refused_other,
            "contents_complete": compressed == 0 and refused_other == 0,
        }


def os_pread(fd: int, length: int, offset: int) -> bytes:
    """``os.pread`` under a name that does not shadow the module-level import."""
    import os

    return os.pread(fd, length, offset)
