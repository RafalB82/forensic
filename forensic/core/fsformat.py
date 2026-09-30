# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""What filesystem is this, and can we read it?

The reader in :mod:`forensic.core.ext4` answers "is this an ext2/3/4?" by finding
``0xEF53`` in the superblock, and when it does not find it, the honest answer
arrives as *"not a readable ext2/3/4 image"*.  That is true and useless: the
analyst is holding an EROFS ``/system`` partition — the format every Android 10
and later ships — and is told nothing about what it is.

So the identification is separated from the reading, and the identification knows
the four formats that actually turn up on an Android device.  Detection is
cheap — a magic number and the offset it lives at — and it is the difference
between "your filesystem is broken" and "your filesystem is fine, I just cannot
read this one yet".

Every offset and value below was measured against an image this repository
builds itself, not copied from a table of formats:

============  ==================  ==========================
format        magic               offset
============  ==================  ==========================
ext2/3/4      ``0xEF53``          1080 (superblock + 0x38)
EROFS        ``0xE0F5E1E2``      1024
F2FS         ``0xF2F52010``      1024
squashfs     ``0x73717368``      0
============  ==================  ==========================

The offsets are the ones that catch the formats in the wild.  ext4 and EROFS and
F2FS all put their magic 1024 bytes in, behind a partition or boot area; squashfs
puts it at the very front.  A reader that only looked at offset 0 would find
none of them, which is worth remembering the next time an image looks empty.

A fifth column came later and is worth stating separately: which of these have a
reader *in this repository*.  F2FS and EROFS both do, since the sixteenth and
thirteenth turns, and a signature says so in its ``reader`` field — separately
from ``readable``, which still means "the default ext4 reader".  Those two answers
are different questions and the table keeps both, because the sentence an analyst
gets when an ``Ext4`` open fails must still name the real format.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

#: Bytes to read for identification.  1088 covers the ext4 magic at 1080 and the
#: EROFS and F2FS magics at 1024 with room to spare.
PROBE_BYTES = 1088


@dataclass(frozen=True)
class Signature:
    """One filesystem's magic, where it lives, and whether we can read it.

    ``readable`` and ``reader`` answer two different questions and both are kept,
    because conflating them is what made the twelfth turn's table quietly wrong.
    ``readable`` means *the default reader* — :class:`forensic.core.ext4.Ext4`,
    the one every other module goes through — accepts the format, and it is what
    decides whether a failed ext4 read gets a sentence naming the real format.
    ``reader`` names the dedicated reader that does open it, if any.  F2FS and
    EROFS are therefore ``readable=False, reader="f2fs"``/``"erofs"``: an
    ``Ext4`` refusal must still say "to jest F2FS", and flipping ``readable`` to
    make room for the new reader would have deleted that sentence along with the
    assertion that tests it.
    """

    kind: str
    magic: bytes
    offset: int
    readable: bool
    name: str
    note: str = ""
    reader: str = ""


#: Ordered most-specific first.  ext4 is last among the superblock formats only
#: because its magic sits furthest in and costs the most to reach.
SIGNATURES: tuple[Signature, ...] = (
    Signature(
        "squashfs",
        b"hsqs",
        0,
        False,
        "SquashFS",
        "używany w części obrazów ROM; archiwum tylko do odczytu, brak trybu zapisu",
    ),
    Signature(
        "erofs",
        bytes.fromhex("e2e1f5e0"),
        1024,
        False,
        "EROFS",
        "domyślny /system na Androidzie 10 i nowszych, z kompresją LZ4 — "
        "brak dekompresora w stdlib, więc same metadane dałyby się czytać, "
        "a treści plików nie",
        reader="erofs",
    ),
    Signature(
        "f2fs",
        bytes.fromhex("1020f5f2"),
        1024,
        False,
        "F2FS",
        "częsty wybór na /data; czytany przez core/f2fs.py, poza plikami "
        "skompresowanymi, zaszyfrowanymi i tymi powyżej 7,9 GiB",
        reader="f2fs",
    ),
    Signature(
        "ext",
        bytes.fromhex("53ef"),
        1080,
        True,
        "ext2/ext3/ext4",
        "jedyny format, który ten tool czyta domyślnie",
    ),
)


#: Reported when nothing matched.  Not an error on its own: a partition image
#: may begin with a table, a header, or nothing recognisable at all.
UNKNOWN = "nieznany"


def _probe(path: str | Path) -> bytes:
    try:
        with open(str(path), "rb") as handle:
            return handle.read(PROBE_BYTES)
    except OSError:
        return b""


def detect_bytes(head: bytes) -> Signature | None:
    """Identify already-read bytes, or ``None`` when nothing matches."""
    for signature in SIGNATURES:
        at = signature.offset
        if head[at : at + len(signature.magic)] == signature.magic:
            return signature
    return None


def detect(path: str | Path) -> dict[str, Any]:
    """Identify the filesystem at the start of ``path``.

    Returns the signature fields plus a ``verdict`` meant to be shown to an
    analyst: what the format is, whether this tool can read it, and — when it
    cannot — what that means for the case rather than leaving the failure to
    surface later as an unreadable file.
    """
    head = _probe(path)
    if not head:
        return {
            "kind": UNKNOWN,
            "name": "nieczytelny",
            "readable": False,
            "reader": "",
            "verdict": f"nie można odczytać pierwszych {PROBE_BYTES} B pliku",
            "supported": [],
            "readers": {s.kind: s.reader for s in SIGNATURES if s.reader},
        }
    signature = detect_bytes(head)
    if signature is None:
        return {
            "kind": UNKNOWN,
            "name": "nieznany",
            "readable": False,
            "reader": "",
            "verdict": (
                "żadna ze znanych sygnatur (ext2/3/4, EROFS, F2FS, squashfs) "
                "nie występuje w pierwszych "
                f"{PROBE_BYTES} B — to może być obraz całego urządzenia, partycja "
                "bez tablicy, albo obraz zniekształcony"
            ),
            "supported": [s.kind for s in SIGNATURES if s.readable],
            "readers": {s.kind: s.reader for s in SIGNATURES if s.reader},
        }
    if signature.readable:
        verdict = f"{signature.name}: format obsługiwany"
    elif signature.reader:
        verdict = (
            f"{signature.name}: rozpoznany, obsługiwany przez czytnik "
            f"{signature.reader} (nie przez domyślny czytnik ext4). "
            f"{signature.note}."
        )
    else:
        verdict = (
            f"{signature.name}: rozpoznany, ale NIE obsługiwany przez ten tool. "
            f"{signature.note}. To nie jest błąd obrazu."
        )
    return {
        "kind": signature.kind,
        "name": signature.name,
        "readable": signature.readable,
        "reader": signature.reader,
        "magic": signature.magic.hex(),
        "offset": signature.offset,
        "note": signature.note,
        "verdict": verdict,
        "supported": [s.kind for s in SIGNATURES if s.readable],
        "readers": {s.kind: s.reader for s in SIGNATURES if s.reader},
    }


def unsupported_hint(path: str | Path) -> str:
    """A one-line explanation for why an ext4 read failed, or ``""`` if it should not.

    Called when :class:`forensic.core.ext4.Ext4` refuses an image.  If the image
    is a filesystem we can name but cannot read, that name is the useful part of
    the message; if the image really is a broken ext4, the hint stays out of the
    way.
    """
    found = detect(path)
    if found["kind"] == UNKNOWN:
        return ""
    if found["readable"]:
        return ""
    if found["reader"]:
        return (
            f" To jest {found['name']} — ma go czytnik {found['reader']}, "
            "więc ta ścieżka kodu go nie obsługuje."
        )
    return f" To jest {found['name']} — {found['note']}."