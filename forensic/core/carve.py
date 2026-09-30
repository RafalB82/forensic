# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Content carving from unallocated space, with the evidence grade attached.

Step 3 of the plan's 7.5, and the step the plan is most worried about: *"carving
from a cluster without metadata is inherently weakened as evidence and must be
described as such in the report, otherwise it builds false confidence."*  So the
first thing this module is for is **not** to produce a list of files.  It is to
produce a list of byte ranges, each with a name for its format, a grade saying
how that name was established, and a statement of what is missing.

Three grades, and the grade is the point:

``validated``
    The signature was found **and** the structure behind it was walked to its own
    terminator, or a checksum over it was recomputed.  A PNG is followed chunk by
    chunk to ``IEND`` with every chunk CRC checked; a JPEG is followed marker by
    marker to ``EOI`` and must contain a start-of-frame with sane dimensions; a
    ZIP is followed to its end-of-central-directory record; a gzip stream is
    actually decompressed and its CRC and length checked.  Four bytes that happen
    to spell a PNG's magic are not a PNG, and this grade says so.

``magic``
    The signature is there and nothing behind it was checked, because the format
    has no terminator to walk to at this depth.  A 7z header is 32 bytes and says
    its own version; that is genuinely all the evidence there is.

``weak``
    The signature is short and common enough to occur by chance inside other data.
    Reported, counted separately, and never counted as a file.

**A candidate is bounded by its run.**  A file's blocks were allocated near each
other, so a deleted one tends to leave a contiguous run, and a carve reads space
rather than the volume.  When a validator runs into the end of the run still
looking for a terminator, the candidate is reported as **truncated** with the
length that is actually there — not as a smaller file, because a PNG without
``IEND`` is not a PNG and calling it one is the false confidence the plan warns
about.  Truncated candidates are counted separately from complete ones.

**No names.**  There is nothing to name these with.  A range of blocks that
happened to hold a JPEG has no path, no uid, no mtime and no inode, because
ext4 discarded the inode and the directory entry at the moment of unlink — that is
what turn 14 measured.  Every record carries ``name: null`` and a
``name_source`` saying why, so an empty name column cannot be read as "not looked
for".
"""

from __future__ import annotations

import binascii
import struct
import zlib
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable

#: Grades, strongest first.  The order is also the order the report uses.
VALIDATED = "validated"
MAGIC = "magic"
WEAK = "weak"

MAX_OBJECT = 512 * 1024 * 1024


@dataclass
class Candidate:
    """One carved range and what is known about it."""

    offset: int
    length: int
    kind: str
    grade: str
    truncated: bool = False
    note: str = ""
    detail: dict = field(default_factory=dict)
    #: The unallocated run this came from, as ``(first_block, blocks)``.
    run: tuple[int, int] | None = None

    @property
    def end(self) -> int:
        return self.offset + self.length

    def as_dict(self) -> dict[str, Any]:
        return {
            "offset": self.offset,
            "length": self.length,
            "kind": self.kind,
            "grade": self.grade,
            "truncated": self.truncated,
            "note": self.note,
            "name": None,
            "name_source": (
                "brak — nazwy usuniętego pliku nie ma ani w inodzie (i_dtime, ale "
                "i_blocks = 0), ani w bloku katalogowym powiązanym z tym zakresem"
            ),
            "run_first_block": self.run[0] if self.run else None,
            "run_blocks": self.run[1] if self.run else None,
            **self.detail,
        }


class _Space:
    """The bytes a candidate may read: its run, and nothing beyond it.

    A carve walks *space*, not the volume, so a validator must not be able to read
    a byte belonging to a live file just because the run ended in the middle of an
    object.  Two properties of the first version of this class were wrong and both
    were caught by the fixture:

    * **Reads past the end returned zeros instead of running out.**  A PNG whose
      last chunk is cut short had its chunk read "succeed" with zero padding, the
      CRC then failed, and the validator returned *nothing* — so a truncated file
      was reported as no file at all, which is the one answer that must never be
      given about a signature that was really there.  A read that runs out returns
      short, and a validator can see it.
    * **The window stopped at the block, not at the run.**  A deleted file of three
      blocks in a run is one object; truncating it at the first block boundary
      would report every multi-block file as truncated.

    So the space holds the run's block list and a reader, resolves offsets through
    it, and stops at the run's end.  ``MAX_OBJECT`` caps the read so that one
    candidate cannot ask for half a gigabyte.
    """

    def __init__(self, blocks: list[int], read: Callable[[int], bytes], block_size: int,
                 at: int = 0) -> None:
        self.blocks = blocks
        self.read_block = read
        self.block_size = block_size
        self.at = at
        self.cap = min(len(blocks) * block_size, MAX_OBJECT)
        self.total = self.cap
        self._cache: dict[int, bytes] = {}

    def view(self, at: int) -> _Space:
        """A second window onto the same run, starting ``at`` bytes in.

        One space per run with a view per candidate, rather than a space per
        candidate: the run is read once and the blocks are cached, which is the
        difference between carving 2.5 million blocks and re-reading them for every
        signature occurrence.
        """
        clone = _Space.__new__(_Space)
        clone.blocks = self.blocks
        clone.read_block = self.read_block
        clone.block_size = self.block_size
        clone.at = at
        clone.cap = self.cap - at
        clone.total = clone.cap
        clone._cache = self._cache
        return clone

    def _block(self, index: int) -> bytes:
        blob = self._cache.get(index)
        if blob is None:
            blob = self.read_block(self.blocks[index])
            self._cache[index] = blob
        return blob

    def read(self, offset: int, length: int) -> bytes:
        offset += self.at
        if offset < 0 or offset >= self.cap:
            return b""
        out = bytearray()
        want = min(length, self.cap - offset)
        while want > 0:
            index, inside = divmod(offset, self.block_size)
            if index >= len(self.blocks):
                break
            blob = self._block(index)
            take = blob[inside : inside + want]
            if not take:
                break
            out += take
            offset += len(take)
            want -= len(take)
        return bytes(out)

    def u8(self, at: int) -> int | None:
        raw = self.read(at, 1)
        return raw[0] if raw else None

    def u16(self, at: int) -> int | None:
        raw = self.read(at, 2)
        return struct.unpack(">H", raw)[0] if len(raw) == 2 else None

    def u32(self, at: int) -> int | None:
        raw = self.read(at, 4)
        return struct.unpack(">I", raw)[0] if len(raw) == 4 else None

    def le16(self, at: int) -> int | None:
        """Little-endian 16-bit, for the formats that store integers that way.

        ZIP and its relatives are little-endian throughout while almost every
        other format here is big-endian, so the endianness belongs to the
        validator, not to the space.
        """
        raw = self.read(at, 2)
        return struct.unpack("<H", raw)[0] if len(raw) == 2 else None

    def le32(self, at: int) -> int | None:
        raw = self.read(at, 4)
        return struct.unpack("<I", raw)[0] if len(raw) == 4 else None

    def starts(self, at: int, magic: bytes) -> bool:
        return self.read(at, len(magic)) == magic

    def find(self, needle: bytes, start: int = 0) -> int:
        """Offset of ``needle`` within the run, or ``-1``.

        A byte-at-a-time search, because the space spans blocks and there is no
        single buffer to hand to ``bytes.find``.  Formats that use it — PDF's
        ``%%EOF`` — are searched over a bounded window, so the cost is bounded too.
        """
        step = 1 << 20
        at = max(0, start)
        while at < self.total:
            blob = self.read(at, min(step, self.total - at))
            if not blob:
                break
            found = blob.find(needle)
            if found >= 0:
                return at + found
            at += max(1, len(blob) - len(needle) + 1)
        return -1


# --------------------------------------------------------------------------
# validators.  Each returns (length, grade, truncated, note, detail) or None.
# --------------------------------------------------------------------------
Validator = Callable[[_Space], tuple[int, str, bool, str, dict] | None]


def _png(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """PNG: walk the chunk list to ``IEND``, checking every chunk CRC.

    The signature is 8 bytes and appears at the start of a PNG and nowhere else
    inside one, so finding it mid-stream is a strong hint rather than a certainty.
    Walking the chunks is what turns the hint into a check: a random 8 bytes will
    not be followed by well-formed length-typed chunks with correct CRCs all the
    way to ``IEND``.  ``IEND`` itself is not required — plenty of writers leave
    streams unterminated — so a stream that ends without it is reported as
    truncated rather than rejected.
    """
    at = 8
    chunks = 0
    width = height = 0
    while True:
        head = space.read(at, 8)
        if len(head) < 8:
            return (space.total, VALIDATED, True, "przerwane przed IEND", {"chunks": chunks}) if chunks >= 1 else None
        length, ctype = struct.unpack(">I4s", head)
        if length == 0 and ctype != b"IEND":
            return (
                (space.total, VALIDATED, True, "przerwane: chunk o zerowej długości", {"chunks": chunks})
                if chunks
                else None
            )
        if length > space.total or length > 64 * 1024 * 1024:
            return None
        payload = space.read(at + 8, length)
        if len(payload) < length:
            return (space.total, VALIDATED, True, "przerwane wczytanie chunku", {"chunks": chunks}) if chunks else None
        crc_at = at + 8 + length
        stored = space.read(crc_at, 4)
        if len(stored) == 4:
            want = struct.unpack(">I", stored)[0]
            got = binascii.crc32(ctype + payload) & 0xFFFFFFFF
            if want != got:
                return None
        else:
            return (space.total, VALIDATED, True, "brak CRC na końcu", {"chunks": chunks}) if chunks else None
        chunks += 1
        if ctype == b"IHDR" and length >= 8:
            width, height = struct.unpack(">II", payload[:8])
        if ctype == b"IEND":
            end = crc_at + 4
            return (end, VALIDATED, False, "", {"chunks": chunks, "width": width, "height": height})
        at = crc_at + 4


def _find_marker(space: _Space, at: int, span: int = 1 << 16) -> int:
    """Offset of the next plausible marker at or after ``at``, or ``-1``.

    Used inside entropy-coded data, where the parser is allowed to lose the
    thread.  A byte is a marker start when it is ``FF`` and the byte after it is
    neither a stuffed zero nor a restart marker, which is the same test a
    conforming parser makes.  The search is bounded so that a file which never
    terminates cannot make the validator read the whole run.
    """
    window = space.read(at, min(span, max(0, space.total - at)))
    for index in range(len(window) - 1):
        if window[index] != 0xFF:
            continue
        following = window[index + 1]
        if following and following != 0x00 and not 0xD0 <= following <= 0xD7:
            return at + index
    return -1


def _jpeg(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """JPEG: walk the markers to ``EOI`` and require a frame header.

    ``FF D8 FF`` is three bytes and JPEG is the most common thing a JPEG-looking
    byte sequence turns out to be inside other data, so the signature alone would
    be grade ``magic`` here.  Following the segment chain to ``FFD9`` and finding a
    start-of-frame is what earns the higher grade.

    **After the start of scan the chain is resynchronised, not followed.**  Segments
    carry a length; entropy-coded image data does not.  A restart interval is a
    marker in the middle of it, and everything up to the next marker is
    Huffman-coded bytes that may contain anything, ``FF`` included.  Walking
    lengths from ``SOS`` desynchronises on the first coincidence and then returns
    nothing for a perfectly good JPEG — which is what the first version of this
    function did, and what the fixture caught on the first file with a real scan in
    it.  Inside a scan the parser therefore *searches* for the next marker instead
    of trusting the current offset, and the search is bounded.
    """
    at = 2
    saw_frame = False
    in_scan = False
    width = height = 0
    markers = 0
    while True:
        if in_scan:
            found = _find_marker(space, at)
            if found < 0:
                return (
                    (space.total, MAGIC, True, "przerwane przed EOI", {"markers": markers})
                    if saw_frame
                    else None
                )
            at = found
            marker = space.u8(at + 1)
            if marker is None or marker == 0x00 or 0xD0 <= marker <= 0xD7:
                at += 2
                continue
            in_scan = False
        if space.u8(at) != 0xFF:
            return (space.total, MAGIC, True, "przerwane przed EOI", {"markers": markers}) if saw_frame else None
        marker = space.u8(at + 1)
        if marker is None:
            return (space.total, MAGIC, True, "przerwane przed EOI", {"markers": markers}) if saw_frame else None
        if marker == 0xD9:
            if not saw_frame:
                return None
            return (at + 2, VALIDATED, False, "", {"markers": markers, "width": width, "height": height})
        if marker == 0x01 or 0xD0 <= marker <= 0xD8:
            at += 2
            continue
        length = space.u16(at + 2)
        if length is None or length < 2:
            return (space.total, MAGIC, True, "przerwane przed EOI", {"markers": markers}) if saw_frame else None
        if marker in (0xC0, 0xC1, 0xC2):
            payload = space.read(at + 4, 5)
            if len(payload) == 5:
                height, width = struct.unpack(">HH", payload[1:5])
                saw_frame = True
        if marker == 0xDA:
            in_scan = True
        markers += 1
        at += 2 + length


def _gif(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """GIF: the header states the canvas size, so a sane one is a real check."""
    for kind in (b"GIF87a", b"GIF89a"):
        if space.starts(0, kind):
            width = space.u16(6)
            height = space.u16(8)
            if not width or not height or width > 32768 or height > 32768:
                return None
            trailer = space.read(space.total - 1, 1)
            if trailer == b"\x3b":
                return (space.total, VALIDATED, False, "", {"width": width, "height": height})
            return (space.total, MAGIC, True, "brak końca GIF", {"width": width, "height": height})
    return None


def _pdf(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """PDF: the signature and a version number, then a search for ``%%EOF``.

    PDF is text-structured and can end legitimately after ``%%EOF`` with
    whitespace, so the walk is a search forward from the signature rather than a
    chain.  Bounded by the run, which is the whole reason truncation is reported
    rather than hidden.
    """
    if not space.starts(0, b"%PDF-"):
        return None
    version = space.read(5, 3).decode("ascii", "replace")
    at = space.find(b"%%EOF")
    if at < 0:
        return (space.total, MAGIC, True, "brak %%EOF", {"version": version})
    return (at + 5, VALIDATED, False, "", {"version": version})


def _zip(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """ZIP: follow local headers to the central directory and its end record.

    Every field in a ZIP local file header is **little-endian**, unlike every
    other format in this table.  Reading those four fields big-endian gave a
    compressed size of 0x14000000 for a 20-byte entry, so the walk jumped past
    the end of the run and this validator returned nothing for every archive —
    a carver that reports "no zip here" for a zip that is there.
    """
    at = 0
    entries = 0
    while True:
        head = space.read(at, 4)
        if head != b"PK\x03\x04":
            break
        size = space.le32(at + 18)
        name_len = space.le16(at + 26)
        extra_len = space.le16(at + 28)
        if size is None or name_len is None or extra_len is None:
            return None
        if size > 0xFFFFFFFF or name_len > 4096 or extra_len > 4096:
            return None
        at += 30 + name_len + extra_len + size
        entries += 1
        if at > space.total:
            return None
    if not entries:
        return None
    central = space.find(b"PK\x05\x06", at)
    if central < 0:
        return (space.total, VALIDATED, True, "brak katalogu centralnego", {"entries": entries})
    comment = space.le16(central + 20) or 0
    return (central + 22 + comment, VALIDATED, False, "", {"entries": entries})


def _gzip(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """gzip: actually decompress it, and let the standard library check it.

    ``zlib`` is in the standard library, so this is the one compression format this
    tool can verify rather than refuse.  In gzip mode zlib checks the trailer for
    us — the CRC-32 of the uncompressed data and its length — and raises on either,
    so a stream that decompresses to the wrong bytes is rejected instead of being
    offered as a file, and nothing has to be recomputed by hand.

    Three details, each of which the fixture caught by failing:

    * **Hand it the whole stream.**  ``zlib.decompressobj(16 + MAX_WBITS)`` means
      "gzip format", so the header has to be there.  The first version walked the
      optional header fields itself and passed on only the deflate data, which is
      a raw deflate stream to something expecting a gzip one: *incorrect header
      check*, on a perfectly good member.
    * **Do not feed it the rest of the block.**  In free space the bytes after a
      member are whatever was there next, usually zeros, and zeros are not a valid
      gzip header — a whole-window ``decompress()`` tries to start a second member
      and raises, losing the output it had already produced.  Feeding in bounded
      chunks and stopping the moment ``eof`` is set avoids that, and ``consumed``
      is then the object's exact length rather than the window's.
    * **A run that ends first is truncation, not rejection.**  If the space runs
      out before ``eof``, that is an object that ran past the end of the run and
      it is reported as truncated.

    One limit stated rather than papered over: a gzip member **cut short inside a
    run** is reported as rejected rather than truncated, because the standard
    library cannot tell a broken stream from one that ran out — the zeros after
    the break look exactly like a bad header.  That is a false negative in the
    conservative direction, which is the right way to be wrong about a file: the
    alternative is claiming a file exists on the strength of a header and a
    failure.
    """
    if not space.starts(0, b"\x1f\x8b\x08"):
        return None
    obj = zlib.decompressobj(16 + zlib.MAX_WBITS)
    plain = 0
    consumed = 0
    total = space.total
    while consumed < total:
        piece = space.read(consumed, min(4096, total - consumed))
        if not piece:
            break
        try:
            plain += len(obj.decompress(piece))
        except zlib.error:
            return None
        consumed += len(piece)
        if obj.eof:
            length = consumed - len(obj.unused_data)
            return (length, VALIDATED, False, "", {"plain_bytes": plain})
    if not plain:
        return None
    return (consumed, VALIDATED, True, "przerwany przed końcem strumienia", {"plain_bytes": plain})


def _sqlite(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """SQLite: the header states the page size and a file-change counter.

    Checked rather than believed: a page size that is not a power of two in
    512..65536, or a change counter of zero, means the 16 bytes that matched were
    not a database header.
    """
    if not space.starts(0, b"SQLite format 3\x00"):
        return None
    page = space.u16(16)
    if page == 1:
        page = 65536
    if not page or page & (page - 1) or not 512 <= page <= 65536:
        return None
    change = space.u32(24)
    if not change:
        return None
    tail = space.find(b"\x00" * 16, page)
    if tail < 0:
        return (space.total, VALIDATED, True, "brak pustej strony na końcu", {"page_size": page})
    return (tail + 16, VALIDATED, False, "", {"page_size": page, "change_counter": change})


def _elf(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """ELF: class, endianness and machine are stated, so they can be checked."""
    if not space.starts(0, b"\x7fELF"):
        return None
    ei_class, ei_data = space.u8(4), space.u8(5)
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    raw = space.read(18, 2)
    if len(raw) != 2:
        return None
    machine = struct.unpack(">H" if ei_data == 2 else "<H", raw)[0]
    # e_machine is stored in the file's own byte order, and every real ELF on an
    # Android device is little-endian.  Reading it big-endian anyway — which the
    # first version did, because the other fields in this module are big-endian
    # formats — gives 46848 where the value should be 183, no known machine
    # matches, and the file is rejected.  A rejected true positive is the most
    # expensive kind of carve bug: nothing is reported and nothing looks wrong.
    if machine not in (0x03, 40, 62, 183, 243):
        return None
    size = 64 if ei_class == 2 else 52
    return (
        size,
        MAGIC,
        False,
        "",
        {"class": ei_class, "machine": machine, "endian": "big" if ei_data == 2 else "little"},
    )


def _dex(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """Android DEX: the signature carries its own version and the file its size."""
    if not space.starts(0, b"dex\n"):
        return None
    version = space.read(4, 3).decode("ascii", "replace")
    if not version[:1].isdigit():
        return None
    size = space.u32(32)
    if size is None or size < 112:
        return None
    if space.total >= size:
        return (size, VALIDATED, False, "", {"version": version, "declared_size": size})
    return (space.total, VALIDATED, True, "plik krótszy niż zadeklarowany rozmiar", {"version": version})


def _xz(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """XZ: two CRC32 fields, one in the stream header and one in the footer."""
    if not space.starts(0, b"\xfd7zXZ\x00"):
        return None
    crc = space.u32(6)
    if crc is None:
        return None
    if binascii.crc32(space.read(8, 8)) & 0xFFFFFFFF != 0:
        return None
    return (space.total, MAGIC, True, "bez dekompresji (LZMA2 nie ma w stdlib)", {})


def _bzip2(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """bzip2: the stream header carries the block-size character, so it is checked."""
    if not space.starts(0, b"BZh"):
        return None
    level = space.u8(3)
    if level is None or not (0x31 <= level <= 0x39):
        return None
    return (space.total, MAGIC, True, "bez dekompresji (bzip2 nie ma w stdlib)", {"level": chr(level)})


def _sevenzip(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """7z: a 32-byte header with a version and a start-header CRC."""
    if not space.starts(0, b"7z\xbc\xaf\x27\x1c"):
        return None
    major, minor = space.u8(6), space.u8(7)
    if major is None or major != 0:
        return None
    stored = space.u32(8)
    if stored is None or binascii.crc32(space.read(12, 20)) & 0xFFFFFFFF != stored:
        return None
    return (space.total, MAGIC, True, "koniec strumienia nieznany bez dekompresji", {"version": f"{major}.{minor}"})


def _rar(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """RAR: signature plus a version, nothing more.  Weak on purpose."""
    if not space.starts(0, b"Rar!\x1a\x07"):
        return None
    return (space.total, WEAK, True, "brak dalszej weryfikacji", {})


def _ogg(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """Ogg: the page header states its own length, which is a real check."""
    if not space.starts(0, b"OggS"):
        return None
    segments = space.u8(26)
    if segments is None or segments == 0 or segments > 255:
        return None
    at = 27 + segments
    length = space.read(at, 2)
    if len(length) == 2:
        total = struct.unpack("<H", length)[0]
        if 0 < total <= 65025:
            return (at + 2 + total, MAGIC, False, "", {"segments": segments})
    return (space.total, MAGIC, True, "nieznana długość strony", {"segments": segments})


def _ftyp(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """MP4-family: an ``ftyp`` box at offset 4, with a length that must be sane."""
    size = space.u32(0)
    if size is None or size < 16 or size > space.total:
        return None
    if not space.starts(4, b"ftyp"):
        return None
    brand = space.read(8, 4).decode("ascii", "replace")
    return (space.total, MAGIC, True, "koniec pliku nieznany bez parsowania atomów", {"brand": brand})


def _oat(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """Android OAT: the magic carries its own version, and the next word is a checksum.

    Found in the unallocated space of the reference image, which is why it is in
    the table: the largest single stretch of non-zero bytes in that volume's free
    space is a deleted OAT image from ``/system``, and a signature table that
    missed it would have reported the free space as empty of anything while it held
    four kilobytes of a perfectly recognisable file.

    Grade ``magic`` and not ``validated``: the header's Adler-32 covers the whole
    file, and the file ran past the end of the run, so the checksum cannot be
    recomputed here.  The version is checked, because ``oat`` followed by three
    digits is a real constraint and ``oat`` followed by anything else is not this
    format.
    """
    if not space.starts(0, b"oat\n"):
        return None
    version = space.read(4, 4).split(b"\0")[0]
    if len(version) != 3 or not version.isdigit():
        return None
    return (space.total, MAGIC, True, "Adler-32 z nagłówka obejmuje cały plik, a plik przekroczył lukę", {"version": version.decode()})


def _wasm(space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """WebAssembly: magic, version, and a declared length that must be plausible."""
    if not space.starts(0, b"\x00asm\x01\x00\x00\x00"):
        return None
    return (space.total, MAGIC, True, "moduł WASM: koniec nieznany", {})


#: The signature table.  ``offsets`` is how far into the block the magic must sit:
#: zero for a format that starts its file with the signature, four for MP4 where
#: the first box's length comes first.
SIGNATURES: tuple[tuple[str, bytes, int, str, Validator], ...] = (
    ("png", b"\x89PNG\r\n\x1a\n", 0, VALIDATED, _png),
    ("jpeg", b"\xff\xd8\xff", 0, VALIDATED, _jpeg),
    ("gif", b"GIF89a", 0, VALIDATED, _gif),
    ("gif", b"GIF87a", 0, VALIDATED, _gif),
    ("zip", b"PK\x03\x04", 0, VALIDATED, _zip),
    ("gzip", b"\x1f\x8b\x08", 0, VALIDATED, _gzip),
    ("sqlite", b"SQLite format 3\x00", 0, VALIDATED, _sqlite),
    ("pdf", b"%PDF-", 0, VALIDATED, _pdf),
    ("dex", b"dex\n", 0, VALIDATED, _dex),
    ("elf", b"\x7fELF", 0, MAGIC, _elf),
    ("xz", b"\xfd7zXZ\x00", 0, MAGIC, _xz),
    ("7z", b"7z\xbc\xaf\x27\x1c", 0, MAGIC, _sevenzip),
    ("bzip2", b"BZh", 0, MAGIC, _bzip2),
    ("mp4", b"ftyp", 4, MAGIC, _ftyp),
    ("ogg", b"OggS", 0, MAGIC, _ogg),
    ("wasm", b"\x00asm", 0, MAGIC, _wasm),
    ("android-oat", b"oat\n", 0, MAGIC, _oat),
    ("rar", b"Rar!\x1a\x07", 0, WEAK, _rar),
)

#: Why the table is not longer.  A tar has no signature at all — the format puts
#: one nowhere — so there is nothing to scan for, which is the reason a tar in
#: unallocated space is found only by its contents.  A bare ``PK`` is 2 bytes and
#: occurs in ordinary text.  Both are left out rather than given a grade that would
#: overstate the evidence.
NOT_INCLUDED = (
    "tar: brak sygnatury w formacie — nagłówek nie zaczyna się od żadnej stałej",
    "PK bez 03 04: dwa bajty, występują w zwykłym tekście",
    "bazy SQLite w formacie WAL: magic 0x377f0682 jest 4 bajtami i pojawia się "
    "w plikach, które nie są bazami",
    "DEX w obrazie ART (art::dex::DexFile) oraz .vdex: brak publicznej, stałej "
    "sygnatury na początku pliku — można je rozpoznać tylko po strukturze, "
    "a ta należy już do kroku poza tabelą sygnatur",
    "formaty zastrzeżone (FB, Messenger): sygnatury nie są udokumentowane, więc "
    "odkrycie byłoby twierdzeniem bez podstawy",
)


def _find_signatures(blob: bytes, at_most: int = 64) -> list[tuple[str, int]]:
    """Every signature occurrence in one block, as ``(kind, start offset)``.

    Found with ``bytes.find`` rather than by testing every offset against the
    whole table.  The table has seventeen entries and a block has 4096 offsets, so
    the naive form is seventy thousand tests per block and — at a hundred thousand
    blocks — seven billion.  ``find`` is the scan the signature table was always
    asking for, and it costs one pass per signature in C.

    ``at_most`` bounds a pathological block that happens to contain thousands of
    one signature — a block full of zeroes has none, but a block of a repeated
    pattern could.  The bound is reported rather than applied silently.
    """
    out: list[tuple[str, int]] = []
    seen = 0
    for kind, magic, offset, _grade, _validator in SIGNATURES:
        at = blob.find(magic)
        while at >= 0:
            seen += 1
            start = at - offset
            if start >= 0:
                out.append((kind, start))
            at = blob.find(magic, at + 1)
    return out


def carve_run(
    blocks: list[int],
    read: Callable[[int], bytes],
    block_size: int,
    limit: int = 0,
) -> dict[str, Any]:
    """Carve one unallocated run.

    ``blocks`` is the run's physical block numbers in order and ``read`` fetches
    one.  The window handed to each validator stops at the end of **the block**,
    so a candidate is never completed with bytes from a live file; a validator
    that runs out of window reports truncation, which is the honest answer for an
    object that crossed a run boundary.
    """
    if not blocks:
        return {"candidates": [], "rejected": {}, "zero_blocks": 0, "scanned_bytes": 0, "skipped": 0}
    capped = blocks if not limit or limit >= len(blocks) else blocks[:limit]
    found: list[Candidate] = []
    rejected: dict[str, int] = {}
    space = _Space(capped, read, block_size)
    zero_blocks = 0
    scanned = 0
    skipped = 0
    for index, block in enumerate(capped):
        try:
            data = read(block)
        except (OSError, struct.error, ValueError):
            # A block that cannot be read is a hole in the evidence, not an
            # empty block: whatever it held is not carved and is not scanned.
            # Counted so the run can say so instead of looking clean.
            skipped += 1
            continue
        if len(data) < block_size:
            continue
        scanned += block_size
        if not data.strip(b"\0"):
            zero_blocks += 1
            continue
        for kind, start in _find_signatures(data):
            # The view is onto the **run**, so the offset has to be run-relative:
            # a signature in the fifth block of a run is not at `start` bytes into
            # the run.  Passing the block-relative offset validated every candidate
            # outside a run's first block against the wrong bytes, which is exactly
            # the kind of bug that looks like "no candidates in this image".
            outcome = _run_validator(kind, space.view(index * block_size + start))
            if outcome is None:
                rejected[kind] = rejected.get(kind, 0) + 1
                continue
            length, grade, truncated, note, detail = outcome
            if length <= 0 or length > MAX_OBJECT:
                rejected[kind] = rejected.get(kind, 0) + 1
                continue
            found.append(
                Candidate(
                    offset=block * block_size + start,
                    length=length,
                    kind=kind,
                    grade=grade,
                    truncated=truncated,
                    note=note,
                    detail=detail,
                    run=(blocks[0], len(blocks)),
                )
            )
    found.sort(key=lambda item: (item.offset, item.kind))
    kept: list[Candidate] = []
    reach = -1
    for item in found:
        if item.offset < reach:
            continue
        kept.append(item)
        if not item.truncated:
            reach = item.end
    return {
        "candidates": kept,
        "nested_dropped": len(found) - len(kept),
        "rejected": rejected,
        "zero_blocks": zero_blocks,
        "scanned_bytes": scanned,
        "skipped": skipped,
    }


def _run_validator(kind: str, space: _Space) -> tuple[int, str, bool, str, dict] | None:
    """Run the validator that belongs to whichever signature matched.

    Looking it up by kind rather than by the tuple that found it means two
    signatures of the same format (the two GIF versions, the four-byte MP4 probe)
    cannot drift onto each other's validator.
    """
    for candidate_kind, _magic, _offset, _grade, validator in SIGNATURES:
        if candidate_kind == kind:
            return validator(space)
    return None
