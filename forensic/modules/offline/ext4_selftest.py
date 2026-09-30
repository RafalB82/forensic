# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The ext4 reader checked against filesystems built to order.

Everything this tool asserts about ext4 used to be asserted against one image
from one phone.  That is independence of *implementation* — the Sleuth Kit
cross-check supplies that — and none at all of *data*: if a whole class of
volume is wrong, the single reference image cannot say so, because a Redmi 3
from 2016 is a 4 KiB-block ext4 with extents, no 64bit, no metadata_csum and no
inline data, and every one of those absences is untested.

So the volumes are built here, with ``mke2fs``, in a few hundred milliseconds
each, and the reader is put against them.  Two things are checked, and the
second matters more than the first:

* **agreement** — where the reader accepts a volume, its geometry is compared
  with ``dumpe2fs``, e2fsprogs' own reading of the same bytes.
* **refusal** — where the reader cannot handle a volume, it must *say so*.  The
  failure this exists to prevent is not an exception nobody catches: it is a
  reader that returns an empty directory and no error, which a report cannot
  distinguish from an empty filesystem.  Every variant therefore lands in
  exactly one of three buckets — accepted, refused, or **silent** — and
  ``silent`` is a critical finding, never a pass.

The variants are chosen to hit the branches added in the 8th turn, each of which
had been proven by hand on a throwaway image in ``/tmp`` and would otherwise have
rotted: classic ext2 mapping, the three block sizes, 64bit descriptors,
``metadata_bg`` with a contiguous descriptor table, ``metadata_csum`` (parsed and
deliberately not verified), and ``inline_data`` (refused).

One variant also carries a **known xattr**, written with ``debugfs`` without
mounting, so that the xattr reader has a fixture whose value is known exactly
rather than one harvested from a real device.
"""

from __future__ import annotations

import json
import struct
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ...core.evidence import TruncatedEvidenceError
from ...core.ext4 import EXT4_ROOT_INODE, Ext4, Ext4Error
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import LIST, ModuleSpec, Param, register

#: Synthetic images are not evidence of any case, so they sit in a sibling of
#: the case directories rather than inside one.  Under ``work/`` all the same, so
#: they stay inside the ignored tree — the first version put them at the
#: repository root and 64 MiB per variant became untracked files in ``git status``.
SYNTH_DIRNAME = "_synthetic"

#: Size chosen so eight filesystems build in well under a second while still
#: having several block groups: 64 MiB at 4 KiB blocks is sixteen groups, which
#: is enough to exercise the group descriptor table rather than a single group.
SYNTH_SIZE = 64 * 1024 * 1024

#: Features a variant is *about*, as (our name, dumpe2fs' name).  Only these are
#: cross-checked by name; a full translation table between e2fsprogs spelling and
#: ours is not worth maintaining, and the geometry numbers carry the real weight.
FEATURE_PROBE = {
    "bit64": (("64BIT", "64bit"),),
    "desc32": (("EXTENTS", "extent"),),
    "metabg": (("META_BG", "meta_bg"), ("EXTENTS", "extent")),
    "mcsum": (("METADATA_CSUM", "metadata_csum"), ("CSUM_SEED_ALT", "metadata_csum_seed")),
    "inline": (("INLINE_DATA", "inline_data"),),
    "uninitbg": (("UNINIT_BG", "uninit_bg"),),
    "blk1k": (("EXTENTS", "extent"),),
    "blk2k": (("EXTENTS", "extent"),),
    "blk4k": (("EXTENTS", "extent"), ("DIR_INDEX", "dir_index")),
    "ext2": (),
}


@dataclass(frozen=True)
class Variant:
    """One filesystem to build, and what the reader is expected to do with it."""

    name: str
    mke2fs: tuple[str, ...]
    accept: bool
    why: str
    features: tuple[str, ...] = ()
    #: What this variant does **not** prove, stated so the gap is not mistaken
    #: for coverage.  The first version of this file expected ``-O inline_data``
    #: to be refused and the self-test disagreed — correctly: mke2fs sets the
    #: flag but writes no inline data, so there is nothing to misread.  Writing
    #: that down beats leaving a wrong expectation to fail on every run.
    does_not_prove: str = ""


VARIANTS: tuple[Variant, ...] = (
    Variant(
        "ext2",
        ("-t", "ext2"),
        accept=False,
        why=("brak flagi EXTENTS — inode używa klasycznych wskaźników bloków "
             "bezpośrednich i pośrednich, których ten reader nie obsługuje"),
        features=(),
    ),
    Variant("blk1k", ("-t", "ext4", "-b", "1024"), accept=True, why="blok 1024 B"),
    Variant("blk2k", ("-t", "ext4", "-b", "2048"), accept=True, why="blok 2048 B"),
    Variant(
        "blk4k",
        ("-t", "ext4", "-b", "4096"),
        accept=True,
        why="blok 4096 B; mke2fs włącza przy tym dir_index, więc obejmuje też "
            "katalogi indeksowane sumą nazw",
        does_not_prove=("kolizja sum w indeksie htree, czyli dwa wpisy o identycznej "
                        "sumie nazwy — mke2fs generuje zbyt mało wpisów, żeby tę "
                        "granicę wywołać deterministycznie; obraz referencyjny ma "
                        "DIR_INDEX wyłączony, więc ta gałąź jest w ogóle nietestowana"),
    ),
    Variant(
        "bit64",
        ("-t", "ext4", "-b", "4096", "-O", "64bit"),
        accept=True,
        why="64bit: deskryptory 64 B i górne połowy liczników",
        features=("64BIT",),
    ),
    Variant(
        "desc32",
        ("-t", "ext4", "-b", "4096", "-O", "^64bit,^metadata_csum"),
        accept=True,
        why=("deskryptory 32 B i brak sum metadanych — ten sam kształt co obraz "
             "referencyjny, i jedyny wariant, który w ogóle odróżnia drogę 32-bitową"),
        features=(),
        does_not_prove=("bez metadata_csum nie ma sumy deskryptorów ani inodów do "
                        "odczytu; gałąź weryfikacji sum pozostaje nietestowana"),
    ),
    Variant(
        "metabg",
        ("-t", "ext4", "-O", "meta_bg,^resize_inode"),
        accept=True,
        why=("meta_bg z s_first_meta_bg = 0: tablica deskryptorów jest ciągła i "
             "reader musi ją czytać — odmowa byłaby błędem"),
        features=("META_BG",),
    ),
    Variant(
        "mcsum",
        ("-t", "ext4", "-O", "metadata_csum"),
        accept=True,
        why="metadata_csum: sumy są parsowane i świadomie nie weryfikowane",
        features=("METADATA_CSUM",),
    ),
    Variant(
        "inline",
        ("-t", "ext4", "-O", "inline_data"),
        accept=True,
        why=("inline_data: flaga ustawiona, ale mke2fs nie tworzy plików inline, "
             "więc nie ma czego nie umieć — oczekiwanie odmowy byłoby fałszywe"),
        features=("INLINE_DATA",),
        does_not_prove=("gałąź odmowy dla PRAWDZIWEGO pliku inline pozostaje "
                        "niesprawdzona: mke2fs nie umie utworzyć takiego pliku, "
                        "a debugfs nie ma do tego polecenia. Z kodu wynika, że "
                        "i_block wypełniony danymi nie ma magii 0xF30A i "
                        "_expects_no_data_block() zwraca False dla pliku o "
                        "rozmiarze > 0, więc powinno być Ext4Error — ale to "
                        "wniosek z czytania kodu, nie z testu"),
    ),    Variant(
        "uninitbg",
        ("-t", "ext4", "-b", "1024", "-O", "uninit_bg,^64bit,^metadata_csum"),
        accept=True,
        why=(
            "uninit_bg: dwie grupy mają zerową bitmapę bloków i flagę "
            "BLOCK_UNINIT, czyli są wolne z definicji, a nie z pomiaru. Wariant "
            "niesie 1024-bajtowe bloki, bo tylko takie mke2fs zostawia grupę "
            "całkowicie niezapisaną"
        ),
        features=("UNINIT_BG",),
        does_not_prove=(
            "BLOCK_UNINIT da się w ten sposób wywołać tylko na obrazie o "
            "1024-bajtowych blokach: przy 2048 i 4096 bajtach mke2fs nie zostawia "
            "żadnej grupy niezapisanej, bo na grupę przypada 512 bloków tabeli "
            "inodów i nie ma czego pominąć. Ten wariant nie mówi więc nic o "
            "flagach BLOCK_UNINIT na wolumenie o 4096-bajtowych blokach, a taki "
            "właśnie jest obraz referencyjny — tam żadna grupa tej flagi nie ma"
        ),
    ),
)

#: A file carrying a known extended attribute.  **The attribute block is built
#: here, byte by byte, rather than asked for from a tool.**
#:
#: ``debugfs -w -R "ea_set ..."`` reports success and ``ea_list`` then prints the
#: attribute, but on a freshly built image ``i_file_acl`` stays 0 and
#: ``debugfs stat`` agrees — the inode keeps its extent magic in ``i_block`` and
#: nothing points at an attribute block.  This is the second time ``ea_list`` has
#: asserted something ``i_file_acl`` does not support, after the redmi3 image, so
#: it is recorded rather than trusted: see PLAN.md 6i.
#:
#: Two details of the format are only discoverable by building it and being
#: wrong.  The stored name is the **suffix** after the prefix — the prefix comes
#: from ``e_name_index`` — so a block built with the full ``security.selinux``
#: reads back as ``security.securit``.  And the block is built on a volume
#: without ``metadata_csum`` precisely so that no checksum has to be computed;
#: on a checksummed volume the kernel would reject it and this would prove
#: nothing.
XATTR_SUFFIX = "selinux"
XATTR_VALUE = b"u:object_r:forensic_selftest:s0\x00"
XATTR_INDEX = 6  # security
XATTR_PATH = "/forensic_selftest_xattr.txt"
#: The variant that gets the attribute.  ``^metadata_csum`` is the reason.
XATTR_HOST = "desc32"


def synth_root(ctx: Ctx) -> Path:
    root = Path(ctx.config.workdir).expanduser() / SYNTH_DIRNAME / "ext4"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _tool(name: str) -> str | None:
    from ...core.imagemount import tool_path

    return tool_path(name)


def _run(argv: list[str], timeout: int = 120) -> tuple[int, str]:
    try:
        proc = subprocess.run(  # noqa: S603 - argv built here, never a shell string
            argv, capture_output=True, text=True, errors="replace", timeout=timeout, check=False
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, str(exc)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


def _dumpe2fs(image: Path) -> dict[str, Any]:
    """Parse ``dumpe2fs -h`` into comparable values.

    Only the geometry keys are lifted, as integers.  Feature names are kept as
    the set of words e2fsprogs prints, because a full translation to our
    vocabulary is a second thing to get wrong, and the numbers are what the
    comparison rests on.
    """
    tool = _tool("dumpe2fs")
    if not tool:
        return {}
    code, text = _run([tool, "-h", str(image)])
    if code != 0:
        return {}
    parsed: dict[str, Any] = {}
    features: set[str] = set()
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower().replace(" ", "_")
        value = value.strip()
        if key == "filesystem_features":
            features = set(value.split())
            continue
        if value.isdigit():
            parsed[key] = int(value)
    parsed["features"] = sorted(features)
    return parsed


def _build(root: Path, variant: Variant) -> tuple[Path | None, str]:
    """Create the image.  Always rebuilt, never reused.

    A cached image from an earlier state of the code would make the test assert
    against yesterday's filesystem, which is the exact hazard this module exists
    to remove.  ``mke2fs`` on 64 MiB costs tens of milliseconds.
    """
    tool = _tool("mke2fs")
    if not tool:
        return None, "mke2fs nie jest zainstalowany (e2fsprogs)"
    image = root / f"{variant.name}.img"
    try:
        with image.open("wb") as handle:
            handle.truncate(SYNTH_SIZE)
    except OSError as exc:
        return None, f"nie można utworzyć {image}: {exc}"
    code, out = _run([tool, "-q", "-F", *variant.mke2fs, str(image)])
    if code != 0:
        return None, f"mke2fs {' '.join(variant.mke2fs)}: {out.strip()[:200]}"
    return image, ""


def _xattr_block(suffix: str, value: bytes, index: int) -> bytes:
    """Assemble one extended-attribute block.

    Measured against the three real blocks on the reference image rather than
    transcribed from a document, because one detail is easy to get backwards and
    the failure is silent: the name stored in the entry is the **suffix** after
    the prefix, and the prefix is implied by ``e_name_index``.  Writing
    ``security.selinux`` into the name field produces a block that parses without
    complaint and reports the attribute as ``security.securit``.

    ``e_hash`` is left zero.  It is the legacy MD4-based hash and this reader does
    not verify it, which is exactly why the block is placed on a volume without
    ``metadata_csum``: there the kernel recomputes nothing and accepts it, so
    the fixture tests the parser rather than a checksum.
    """
    from ...core.ext4 import XATTR_ENTRY_FIXED, XATTR_HEADER_BYTES, XATTR_MAGIC

    name = suffix.encode("ascii")
    value_at = (XATTR_HEADER_BYTES + XATTR_ENTRY_FIXED + len(name) + 3) & ~3
    area = value_at + len(value)
    header = struct.pack(
        "<IIHHHHII", XATTR_MAGIC, 1, 1, area, 0, 0, 0, 0
    )
    header += b"\0" * (XATTR_HEADER_BYTES - len(header))
    entry = struct.pack("<BBHII", len(suffix), index, value_at, 0, len(value))
    entry += b"\0" * (XATTR_ENTRY_FIXED - len(entry))
    entry += name
    # Padding computed in its own statement on purpose.  Written as one
    # expression, ``len(entry)`` would still be the length of the fixed part
    # only, the name would not be counted, and the block would carry eight
    # padding bytes too many — the reader would then report the value shifted
    # right by eight, with no error anywhere.
    entry += b"\0" * (value_at - (XATTR_HEADER_BYTES + len(entry)))
    block = header + entry + value
    if len(block) > 4096:
        raise ValueError(f"blok atrybutów za duży: {len(block)} B")
    return block


#: Source tree built for the EROFS fixture.  One directory, one subdirectory, a
#: symlink, a small file and a file deliberately larger than one block, because
#: a file that fits in its inode's tail and one that does not exercise different
#: code paths and only the second one catches a placement mistake.
EROFS_FILES = {
    "a.txt": b"zawartosc pliku\n",
    "sub/b.txt": b"podplik\n",
    "big.txt": b"x" * 5000,
}


def _build_erofs_fixture(root: Path) -> dict[str, Any]:
    """Build EROFS images and check the reader against ``dump.erofs``.

    The reader is verified two ways that cannot both be satisfied by a wrong
    answer: the **tree** is compared entry by entry against ``dump.erofs --ls``
    (name, node id, type), and the **contents** byte for byte against
    ``dump.erofs --cat``.  A compressed build is included on purpose, so the
    refusal path is tested against a real compressed inode and not only against
    a hand-made one.

    ``mkfs.erofs`` and ``dump.erofs`` are needed.  When they are absent the check
    says so and reports nothing, rather than passing on an assumption — a
    self-test that skips silently is a self-test that stopped running.
    """
    from ...core.erofs import Erofs, ErofsError
    from ...core.imagemount import tool_path

    mkfs = tool_path("mkfs.erofs")
    dump = tool_path("dump.erofs")
    out: dict[str, Any] = {
        "available": bool(mkfs and dump),
        "why": "" if (mkfs and dump) else "brak mkfs.erofs lub dump.erofs (erofs-utils)",
        "builds": [],
    }
    if not out["available"]:
        return out
    src = root / "erofs_src"
    if src.exists():
        import shutil

        shutil.rmtree(src)
    for name, blob in EROFS_FILES.items():
        path = src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    try:
        (src / "link.txt").symlink_to("a.txt")
    except OSError:
        pass
    import subprocess

    for label, options in (("plain", []), ("lz4", ["-zlz4"])):
        image = root / f"erofs_{label}.img"
        if image.exists():
            image.unlink()
        code = subprocess.run(  # noqa: S603 - argv built here, never a shell string
            [mkfs, "-d0", *options, str(image), str(src)],
            capture_output=True, text=True, timeout=600, check=False,
        )
        if code.returncode != 0:
            out["builds"].append({"label": label, "built": False,
                                  "why": (code.stderr or "").strip()[:160]})
            continue
        entry: dict[str, Any] = {"label": label, "built": True, "bytes": image.stat().st_size}
        try:
            fs = Erofs(str(image))
        except ErofsError as exc:
            entry.update({"opened": False, "why": str(exc)[:200]})
            out["builds"].append(entry)
            continue
        entry["opened"] = True
        entry["inodes"] = fs.superblock["inos"]
        entry["blocks"] = fs.superblock["blocks"]
        entry["block_size"] = fs.block_size
        # Tree, against dump.erofs --ls, name by name.
        mine = sorted(
            (p, n.nid) for p, n in fs.walk() if p != "/"
        )
        theirs: list[tuple[str, int]] = []
        seen: set[str] = set()

        def walk_oracle(path: str, depth: int = 0) -> None:
            if depth > 8 or path in seen:
                return
            seen.add(path)
            listing = subprocess.run(  # noqa: S603
                [dump, "--ls", f"--path={path}", str(image)],
                capture_output=True, text=True, timeout=300, check=False,
            )
            for line in listing.stdout.splitlines():
                parts = line.split()
                if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
                    if parts[2] in (".", ".."):
                        continue
                    child = f"{path.rstrip('/')}/{parts[2]}"
                    theirs.append((child, int(parts[0])))
                    if int(parts[1]) == 2:
                        walk_oracle(child, depth + 1)

        walk_oracle("/")
        entry["tree_ours"] = len(mine)
        entry["tree_theirs"] = len(theirs)
        entry["tree_agrees"] = mine == sorted(theirs)
        if not entry["tree_agrees"]:
            entry["tree_diff"] = [
                item for item in sorted(set(mine) ^ set(theirs))[:6]
            ]
        # Contents, byte for byte.
        same = refused = 0
        for path, node in fs.walk():
            if node.is_dir or node.is_link:
                continue
            try:
                blob = fs.read(node)
            except ErofsError:
                refused += 1
                continue
            cat = subprocess.run(  # noqa: S603
                [dump, "--cat", f"--nid={node.nid}", str(image)],
                capture_output=True, timeout=300, check=False,
            )
            if cat.stdout == blob:
                same += 1
            else:
                entry.setdefault("content_mismatch", []).append(path)
        entry["content_same"] = same
        entry["content_refused"] = refused
        entry["coverage"] = fs.coverage()
        fs.close()
        out["builds"].append(entry)
    out["ok"] = all(
        b.get("built") and b.get("tree_agrees") and not b.get("content_mismatch")
        for b in out["builds"]
    ) and bool(out["builds"])
    return out


#: Source tree for the F2FS fixture.  Five shapes, each of which lands somewhere
#: different in the format and each of which therefore exercises a different path
#: through the reader:
#:
#: * a file of a few bytes, which lands **inline** inside the inode;
#: * a file of two blocks, which lands in the inode's own ``i_addr`` words;
#: * a file of 5 MiB, which overruns those words by 50 of them and needs a
#:   **direct node** — the place where guessing 923 instead of 873 puts the
#:   middle of the file somewhere else without any error;
#: * a directory of 300 entries, which needs **two dentry blocks** and whose
#:   names are all exactly one slot wide except the dots;
#: * a symlink and a nested directory, for the ``..`` and the recursion.
F2FS_SMALL = {
    "a.txt": b"zawartosc pliku\n",
    "big.txt": b"x" * 5000,
    "sub/b.txt": b"podplik\n",
    "link.txt": b"a.txt",
}
#: One byte past the inline limit is not the interesting boundary; 5 MiB is,
#: because the inode holds 873 blocks of it and a direct node the other 407.
F2FS_HUGE_BYTES = 5 * 1024 * 1024
F2FS_HUGE_FILL = b"forensic"
F2FS_MANY = 300
#: The big image is 512 MiB so the 5 MiB file and the 300-entry directory both
#: fit with room for garbage collection to move things around, which is what makes
#: the address map worth reading rather than assuming.
F2FS_BIG_SIZE = 512 * 1024 * 1024
F2FS_SMALL_SIZE = 64 * 1024 * 1024
#: The name planted in the hand-built inline directory.  Twelve bytes, so it spans
#: two name slots and the fixture would not pass if only the first slot were read.
F2FS_INLINE_CHILD = b"inline_child"
#: How many inodes of the big variant are compared with ``dump.f2fs -i``.  One
#: process per inode at roughly 60 ms makes 310 inodes cost twenty seconds of a
#: verification run; the small variant is still compared exhaustively, and the
#: sample is picked by shape.  See :func:`_f2fs_inode_sample`.
F2FS_INODE_SAMPLE_CAP = 24


def _f2fs_source(root: Path, small: bool) -> Path:
    """Build the source tree for one F2FS variant.  Always rebuilt."""
    import shutil

    src = root / ("f2fs_src_small" if small else "f2fs_src_big")
    if src.exists():
        shutil.rmtree(src)
    for name, blob in F2FS_SMALL.items():
        path = src / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
    try:
        (src / "link.txt").unlink()
        (src / "link.txt").symlink_to("a.txt")
    except OSError:
        pass
    if not small:
        many = src / "many"
        many.mkdir()
        for index in range(F2FS_MANY):
            (many / f"f{index:03d}.txt").write_bytes(F2FS_HUGE_FILL * index)
        # Repeating content, so a reader that put a block in the wrong place
        # would still match by luck on a short prefix.
        (src / "huge.bin").write_bytes(bytes((i * 7) % 251 for i in range(F2FS_HUGE_BYTES)))
        (src / "emptydir").mkdir()
        solo = src / "solo"
        solo.mkdir()
        (solo / "only.txt").write_bytes(b"jeden\n")
    return src


def _dump_f2fs_fields(tool: str, image: Path, extra: list[str]) -> dict[str, int]:
    """Parse ``dump.f2fs -d 1``'s ``name [0x HEX : DEC]`` lines into integers.

    The debug level is what makes it print the superblock and checkpoint field by
    field with their own names, and that is the whole reason this is an oracle
    worth having: f2fs-tools' own reading of the same bytes, keyed the same way our
    reading is keyed, so a field that moved in one and not the other cannot hide.
    """
    import re

    try:
        proc = subprocess.run(  # noqa: S603 - argv built here, never a shell string
            [tool, "-d", "1", *extra, str(image)],
            capture_output=True, text=True, timeout=300, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    pattern = re.compile(r"^([A-Za-z_][A-Za-z_0-9]*(?:\[\d+\])?)\s+\[0x\s*[0-9a-fA-F]+\s*:\s*(-?\d+)\]")
    out: dict[str, int] = {}
    for line in proc.stdout.splitlines():
        found = pattern.match(line.strip())
        if found:
            out.setdefault(found.group(1), int(found.group(2)))
    return out


def _dump_f2fs_inode(tool: str, image: Path, nid: int) -> dict[str, int]:
    """One inode as ``dump.f2fs -i <nid>`` prints it.

    The tool answers ``[ASSERT] (dump_file: 503)`` on a regular file — it offers to
    write the file out to ``./lost_found`` — so this is a prompt, not a crash, and
    the parse below simply takes what was printed before it.
    """
    return _dump_f2fs_fields(tool, image, ["-i", str(nid)])


def _f2fs_inline_dentry_image(source: Path, dest: Path) -> dict[str, Any]:
    """Hand-build an inline directory, because no tool in f2fs-tools makes one.

    ``mkfs.f2fs`` and ``sload.f2fs`` both give a directory a real dentry block, even
    an empty one, while a directory created by ``mkdir`` and closed straight away
    keeps its two dots inside the inode.  That second shape is the common one on a
    real device — every app that creates a cache directory gets it — and it is the
    one branch of the reader that nothing here can otherwise reach, which is the
    same situation as the ext4 xattr fixture.

    So the dentry area is written from the header's own formulas
    (``make_dentry_ptr_inline()``: bitmap, reserved area, 11-byte entries, 8-byte
    name slots) and the inode is pointed at nothing else.  What this proves is
    that the **reader** follows those formulas and reads the names back; it does
    not prove that mkfs would lay the same bytes down, because no mkfs was asked.
    ``i_size`` is set to the length of the area used and the reader is written not
    to consult it for inline directories, so the fixture does not depend on which of
    the two plausible ``i_size`` conventions is the real one — a question this
    image cannot answer, and one that is therefore not asked.
    """
    import shutil

    from ...core.f2fs import (
        DIR_ENTRY_BYTES,
        I_ADDR,
        I_INLINE,
        I_SIZE,
        INLINE_DENTRY,
        INLINE_DOTS,
        INLINE_XATTR,
        SLOT_LEN,
        F2fs,
        F2fsError,
        name_hash,
    )

    shutil.copy(source, dest)
    report: dict[str, Any] = {"ok": False, "why": ""}
    target = child = None
    target_path = child_path = ""
    fs = F2fs(str(dest))
    try:
        for path, node in sorted(fs.walk(), key=lambda pair: pair[0]):
            if node.is_dir and target is None and node.inline & INLINE_XATTR:
                target = node
                target_path = path
            if node.is_reg and child is None:
                child = node
                child_path = path
        if target is None or child is None:
            report["why"] = "wariant nie zawiera katalogu inline xattr ani pliku"
            return report
        root = fs.inode(fs.superblock["root_ino"])
        report["target_path"] = str(target_path)
        report["child_path"] = str(child_path)
        report["child_ino"] = child.ino
        report["child_bytes"] = fs.read(child).decode("utf-8", "replace")
        raw = bytearray(fs._node(target.node_block))
        raw[I_INLINE] = INLINE_XATTR | INLINE_DENTRY | INLINE_DOTS
        struct.pack_into("<I", raw, I_ADDR, 0)
        struct.pack_into("<I", raw, I_ADDR + 1, 0)
        struct.pack_into("<Q", raw, I_SIZE, 0)
        with open(dest, "r+b") as handle:
            handle.seek(target.node_block * fs.block_size)
            handle.write(bytes(raw))
    finally:
        fs.close()
    # The layout is computed only now, with the flags already set.  Setting
    # INLINE_XATTR is what gives the inode its 200-byte inline xattr area, and that
    # area is subtracted from the 923 address words, so the size of the dentry
    # area -- 182 entries in 3488 bytes with the flag, 192 in 3688 without -- moves
    # when the flag is set.  A fixture that measured the layout first and wrote the
    # entries afterwards puts them where the reader will not look, which is a
    # better demonstration of the dependency than any comment would be.
    fs = F2fs(str(dest))
    try:
        target = fs.resolve(report["target_path"])
        at, bitmap_bytes, count, reserved = fs._inline_layout(target)
        entries = [
            (b".", target.ino, 2),
            (b"..", root.ino, 2),
            (F2FS_INLINE_CHILD, child.ino, 1),
        ]
        blob = bytearray(bitmap_bytes + reserved + count * (DIR_ENTRY_BYTES + SLOT_LEN))
        for index, (name, ino, ftype) in enumerate(entries):
            blob[index >> 3] |= 1 << (index & 7)
            struct.pack_into(
                "<IIHB",
                blob,
                bitmap_bytes + reserved + index * DIR_ENTRY_BYTES,
                name_hash(name),
                ino,
                len(name),
                ftype,
            )
            name_at = bitmap_bytes + reserved + count * DIR_ENTRY_BYTES + index * SLOT_LEN
            blob[name_at : name_at + len(name)] = name
        raw = bytearray(fs._node(target.node_block))
        struct.pack_into(
            "<Q",
            raw,
            I_SIZE,
            bitmap_bytes + reserved + len(entries) * (DIR_ENTRY_BYTES + SLOT_LEN),
        )
        raw[at : at + len(blob)] = blob
        with open(dest, "r+b") as handle:
            handle.seek(target.node_block * fs.block_size)
            handle.write(bytes(raw))
    finally:
        fs.close()
    fs = F2fs(str(dest))
    try:
        target = fs.resolve(report["target_path"])
        listed = [(e.name, e.ino, e.kind, e.hash_checked) for e in fs.listdir(target)]
        planted = f"{report['target_path']}/{F2FS_INLINE_CHILD.decode()}"
        report.update(
            {
                "ok": [n for n, _i, _k, _h in listed] == [".", "..", F2FS_INLINE_CHILD.decode()],
                "nid": target.number,
                "inline_flags": f"0x{target.inline:02x}",
                "entries": listed,
                "names": [n for n, _i, _k, _h in listed],
                "hashes_checked": all(h for _n, _i, _k, h in listed),
                "layout_offset": at,
                "bitmap_bytes": bitmap_bytes,
                "entry_count": count,
                "reserved_bytes": reserved,
                "child": F2FS_INLINE_CHILD.decode(),
                "child_ino_matches": dict((n, i) for n, i, _k, _h in listed).get(
                    F2FS_INLINE_CHILD.decode()
                )
                == report["child_ino"],
                "child_read": fs.read(planted).decode("utf-8", "replace"),
                "child_walked": any(p == planted for p, _n in fs.walk()),
            }
        )
        report["ok"] = bool(
            report["ok"]
            and report["child_ino_matches"]
            and report["child_read"] == report["child_bytes"]
            and report["child_walked"]
        )
    except F2fsError as exc:
        report.update({"ok": False, "why": str(exc)[:200]})
    finally:
        fs.close()
    return report


def _f2fs_encrypted_image(source: Path, dest: Path) -> dict[str, Any]:
    """Hand-build an encrypted volume header, to test that the reader refuses.

    ``encryption_level`` in the superblock is the only thing that decides whether
    names and contents are ciphertext, and nothing in f2fs-tools will write a
    volume with a key.  Both fixture images were built without a superblock CRC
    (``checksum_offset = 0``, ``crc = 0``), so setting the byte leaves the
    superblock self-consistent and this is a header, not a corruption.

    The assertion is the important half: a reader that quietly returned plaintext
    names from an encrypted ``/data`` would produce a report full of confident
    nonsense, which is worse than a refusal.
    """
    import shutil

    from ...core.f2fs import F2fs, F2fsError

    shutil.copy(source, dest)
    fs = F2fs(str(dest))
    level_at = 1024 + 2184
    fs.close()
    with open(dest, "r+b") as handle:
        handle.seek(level_at)
        handle.write(bytes([4]))
    report: dict[str, Any] = {"level": 4, "offset": level_at}
    fs = F2fs(str(dest))
    try:
        try:
            entries = fs.listdir(fs.root)
            report.update({"ok": False, "why": f"czytnik wypisał {len(entries)} wpisów z zaszyfrowanego katalogu"})
        except F2fsError as exc:
            report.update({"ok": "szyfrowania" in str(exc), "refusal": str(exc)[:200]})
    finally:
        fs.close()
    return report


def _f2fs_compressed_image(source: Path, dest: Path) -> dict[str, Any]:
    """Hand-set the compression flag on one file, to test that it is refused.

    ``f2fs_io`` writes a genuinely compressed file, and it needs a mounted
    filesystem, so the flag is set on the inode instead.  Compression in F2FS is
    per file and off by default, which is why a real ``/data`` may hold both kinds
    and a reader has to cope with one refusal among ten thousand successes.

    Only the refusal is asserted.  The bytes behind the flag are ordinary
    uncompressed data here, so nothing about decompression is being claimed.
    """
    import shutil

    from ...core.f2fs import I_FLAGS, COMPR_FL, F2fs, F2fsError

    shutil.copy(source, dest)
    fs = F2fs(str(dest))
    try:
        victim = None
        for path, node in fs.walk():
            if path == "/a.txt":
                victim = node
                break
        if victim is None:
            return {"ok": False, "why": "brak /a.txt"}
        raw = bytearray(fs._node(victim.node_block))
        struct.pack_into("<I", raw, I_FLAGS, struct.unpack_from("<I", raw, I_FLAGS)[0] | COMPR_FL)
        with open(dest, "r+b") as handle:
            handle.seek(victim.node_block * fs.block_size)
            handle.write(bytes(raw))
    finally:
        fs.close()
    fs = F2fs(str(dest))
    report: dict[str, Any] = {"nid": victim.number, "flag": f"0x{COMPR_FL:08x}"}
    try:
        try:
            fs.read("/a.txt")
            report.update({"ok": False, "why": "czytnik oddał treść pliku oznaczonego jako skompresowany"})
        except F2fsError as exc:
            report.update({"ok": "skompresowany" in str(exc), "refusal": str(exc)[:200]})
        coverage = fs.coverage()
        report["coverage_refused"] = coverage["refused"]
    finally:
        fs.close()
    return report


def _f2fs_dindirect_refusal(image: Path) -> dict[str, Any]:
    """Check the double-indirect boundary is refused, with the limit in the message.

    Reachable without a 9 GiB file: the resolver is asked for a block index past
    the last one direct and indirect nodes cover, on a real inode of a real image.
    The number in the message is checked too, because a refusal that does not say
    where the limit is leaves the analyst guessing whether the file is too big or
    the tool is broken.
    """
    from ...core.f2fs import F2fs, F2fsError

    fs = F2fs(str(image))
    try:
        biggest = None
        for path, node in fs.walk():
            if node.is_reg and (biggest is None or node.size > biggest.size):
                biggest = node
        if biggest is None:
            return {"ok": False, "why": "wariant nie zawiera plików regularnych"}
        direct = biggest.addrs_per_inode
        indirect = 2 * 1018 + 2 * 1018 * 1018
        limit = direct + indirect
        entry: dict[str, Any] = {
            "nid": biggest.number,
            "addrs_per_inode": direct,
            "limit_blocks": limit,
        }
        try:
            fs.block_address(biggest, limit - 1)
            entry["last_reachable"] = True
        except F2fsError:
            entry["last_reachable"] = False
        try:
            fs.block_address(biggest, limit)
            entry.update({"ok": False, "why": "czytnik przyjął blok spoza gałęzi pośredniej"})
        except F2fsError as exc:
            text = str(exc)
            entry.update(
                {
                    "ok": "podwójnie" in text and str(limit) in text,
                    "refusal": text[:220],
                    "has_limit": str(limit) in text,
                }
            )
        return entry
    finally:
        fs.close()


def _f2fs_inode_sample(tree: list[tuple[str, Any]], cap: int) -> list[tuple[str, Any]]:
    """Pick which inodes to compare with ``dump.f2fs -i``, deterministically.

    Comparing *every* inode would mean one ``dump.f2fs`` process per inode, and at
    about 60 ms each the big variant's 310 inodes cost twenty seconds of a
    verification run — for a check that has already proved itself on five inodes
    of the small variant, exhaustively.  So the big variant gets a sample, and the
    sample is chosen by shape rather than by position, because shape is what the
    reader can get wrong: the root, the largest file (the one with a direct node
    behind it), the largest directory, the first symlink, and the first and last
    entry of the largest directory, which between them cover a one-slot name, a
    multi-slot name and the second dentry block.  The rest is filled at even
    intervals.  Both counts go into the export, so the gap is a number rather
    than an impression.
    """
    if len(tree) <= cap:
        return tree
    chosen: list[tuple[str, Any]] = []
    seen: set[str] = set()

    def take(item: tuple[str, Any]) -> None:
        if item[0] not in seen:
            seen.add(item[0])
            chosen.append(item)

    ordered = sorted(tree, key=lambda pair: pair[0])
    files = [item for item in ordered if item[1].is_reg]
    dirs = [item for item in ordered if item[1].is_dir]
    links = [item for item in ordered if item[1].is_link]
    if ordered:
        take(ordered[0])
    if ordered:
        take(ordered[-1])
    if files:
        take(max(files, key=lambda pair: pair[1].size))
        take(min(files, key=lambda pair: pair[1].size))
    if dirs:
        biggest = max(dirs, key=lambda pair: pair[1].size)
        take(biggest)
        kids = [item for item in ordered if item[0].startswith(biggest[0] + "/")]
        if kids:
            take(kids[0])
            take(kids[-1])
    if links:
        take(links[0])
    step = max(1, len(ordered) // cap)
    for item in ordered[::step]:
        take(item)
        if len(chosen) >= cap:
            break
    return chosen[:cap]


def _build_f2fs_fixture(root: Path) -> dict[str, Any]:
    """Build F2FS images and check the reader against ``dump.f2fs`` and the source.

    The reader is verified in four ways that cannot all be satisfied by a wrong
    answer:

    * **geometry** — superblock and checkpoint fields against ``dump.f2fs -d 1``,
      which prints each field under its own name, so a field that moved in one
      reading and not the other cannot hide behind an agreeing total;
    * **the tree** — names and types against the source tree ``sload.f2fs`` was
      given, entry for entry, plus a separate count against the image itself;
    * **inodes** — every inode's mode, ids, link count, size and three timestamps
      against ``dump.f2fs -i <nid>``;
    * **contents** — byte for byte against the source files, which is the only
      check that can catch a block read from the wrong place in a 5 MiB file.

    Three paths are then built by hand because no tool here produces them: an
    inline directory, a compressed file, and an encrypted volume.  Each one's
    fixture is a header we wrote, and each assertion is about the *reader's
    reaction*, never about a claim the image itself cannot support.

    ``mkfs.f2fs``, ``sload.f2fs`` and ``dump.f2fs`` are needed.  When they are
    absent the check says so and reports nothing, rather than passing on an
    assumption.
    """
    from ...core.f2fs import F2fs, F2fsError
    from ...core.imagemount import tool_path
    import os as _os

    mkfs = tool_path("mkfs.f2fs")
    sload = tool_path("sload.f2fs")
    dump = tool_path("dump.f2fs")
    out: dict[str, Any] = {
        "available": bool(mkfs and sload and dump),
        "why": ""
        if (mkfs and sload and dump)
        else "brak mkfs.f2fs, sload.f2fs lub dump.f2fs (f2fs-tools)",
        "builds": [],
    }
    if not out["available"]:
        return out
    root = root / "f2fs"
    root.mkdir(parents=True, exist_ok=True)

    plans = (
        ("small", F2FS_SMALL_SIZE, True),
        ("big", F2FS_BIG_SIZE, False),
    )
    for label, size, is_small in plans:
        entry: dict[str, Any] = {"label": label, "bytes": size}
        src = _f2fs_source(root, is_small)
        image = root / f"f2fs_{label}.img"
        with image.open("wb") as handle:
            handle.truncate(size)
        made = subprocess.run(  # noqa: S603 - argv built here, never a shell string
            [mkfs, "-q", str(image)], capture_output=True, text=True, timeout=600, check=False
        )
        if made.returncode != 0:
            entry.update({"built": False, "why": (made.stderr or "").strip()[:200]})
            out["builds"].append(entry)
            continue
        loaded = subprocess.run(  # noqa: S603
            [sload, "-f", str(src), str(image)],
            capture_output=True, text=True, timeout=600, check=False,
        )
        if loaded.returncode != 0:
            entry.update({"built": False, "why": (loaded.stdout + loaded.stderr).strip()[:200]})
            out["builds"].append(entry)
            continue
        entry["built"] = True
        entry["image"] = str(image)
        fs = F2fs(str(image))
        try:
            sb = fs.superblock
            cp = fs.checkpoint
            reference = _dump_f2fs_fields(dump, image, [])
            entry["superblock"] = {
                "block_count": sb["block_count"],
                "segment_count": sb["segment_count"],
                "section_count": sb["section_count"],
                "segs_per_sec": sb["segs_per_sec"],
                "secs_per_zone": sb["secs_per_zone"],
                "nat_blkaddr": sb["nat_blkaddr"],
                "main_blkaddr": sb["main_blkaddr"],
                "root_ino": sb["root_ino"],
                "version": sb["version"][:60],
                "feature": f"0x{sb['feature']:08x}",
            }
            entry["checkpoint"] = {
                "checkpoint_ver": cp["checkpoint_ver"],
                "ckpt_flags": f"0x{cp['ckpt_flags']:08x}",
                "valid_node_count": cp["valid_node_count"],
                "valid_inode_count": cp["valid_inode_count"],
                "free_segment_count": cp["free_segment_count"],
                "valid_block_count": cp["valid_block_count"],
                "user_block_count": cp["user_block_count"],
                "sit_ver_bitmap_bytesize": cp["sit_ver_bitmap_bytesize"],
                "nat_ver_bitmap_bytesize": cp["nat_ver_bitmap_bytesize"],
                "pack_count": cp["pack_count"],
                "live_pack": cp["index"],
            }
            mismatched = {
                key: (mine, reference.get(key))
                for key, mine in (
                    ("block_count", sb["block_count"]),
                    ("segment_count", sb["segment_count"]),
                    ("section_count", sb["section_count"]),
                    ("segs_per_sec", sb["segs_per_sec"]),
                    ("secs_per_zone", sb["secs_per_zone"]),
                    ("nat_blkaddr", sb["nat_blkaddr"]),
                    ("main_blkaddr", sb["main_blkaddr"]),
                    ("root_ino", sb["root_ino"]),
                    ("checkpoint_ver", cp["checkpoint_ver"]),
                    ("ckpt_flags", cp["ckpt_flags"]),
                    ("valid_node_count", cp["valid_node_count"]),
                    ("valid_inode_count", cp["valid_inode_count"]),
                    ("free_segment_count", cp["free_segment_count"]),
                    ("valid_block_count", cp["valid_block_count"]),
                    ("user_block_count", cp["user_block_count"]),
                    ("sit_ver_bitmap_bytesize", cp["sit_ver_bitmap_bytesize"]),
                    ("nat_ver_bitmap_bytesize", cp["nat_ver_bitmap_bytesize"]),
                )
                if key in reference and reference[key] != mine
            }
            entry["geometry_agrees"] = not mismatched
            entry["geometry_mismatch"] = mismatched
            entry["dump_fields"] = len(reference)
            entry["nat_per_block"] = 455
            entry["block_size"] = fs.block_size

            mine_tree = {}
            for path, node in fs.walk():
                if path == "/":
                    continue
                mine_tree[path] = node.type_name
            want_tree: dict[str, str] = {}
            for path in sorted(src.rglob("*")):
                rel = "/" + str(path.relative_to(src))
                if path.is_symlink():
                    want_tree[rel] = "symlink"
                elif path.is_dir():
                    want_tree[rel] = "dir"
                else:
                    want_tree[rel] = "file"
            entry["tree_ours"] = len(mine_tree)
            entry["tree_source"] = len(want_tree)
            entry["tree_agrees"] = mine_tree == want_tree
            if not entry["tree_agrees"]:
                entry["tree_diff"] = [
                    f"{k}: my={mine_tree.get(k)} theirs={want_tree.get(k)}"
                    for k in sorted(set(mine_tree) | set(want_tree))
                    if mine_tree.get(k) != want_tree.get(k)
                ][:6]

            same = wrong = refused = 0
            content_mismatch: list[str] = []
            inode_checked = inode_fields = 0
            inode_mismatch: list[str] = []
            walked = [(p, n) for p, n in fs.walk() if p != "/"]
            sampled = _f2fs_inode_sample(walked, F2FS_INODE_SAMPLE_CAP)
            entry["inodes_total"] = len(walked)
            entry["inodes_sampled"] = len(sampled)
            entry["inode_sampling"] = (
                "wszystkie" if len(sampled) == len(walked)
                else f"próbka o stałym wzorcu (limit {F2FS_INODE_SAMPLE_CAP})"
            )
            for path, node in walked:
                if node.is_reg or node.is_link:
                    try:
                        blob = fs.read(node)
                    except F2fsError:
                        refused += 1
                        continue
                    if node.is_link:
                        want = _os.readlink(str(src / path[1:])).encode()
                    else:
                        want = (src / path[1:]).read_bytes()
                    if blob == want:
                        same += 1
                    else:
                        wrong += 1
                        content_mismatch.append(path)
            for path, node in sampled:
                theirs = _dump_f2fs_inode(dump, image, node.number)
                for key, value in (
                    ("i_mode", node.mode),
                    ("i_uid", node.uid),
                    ("i_gid", node.gid),
                    ("i_links", node.nlink),
                    ("i_size", node.size),
                    ("i_atime", node.atime),
                    ("i_ctime", node.ctime),
                    ("i_mtime", node.mtime),
                    ("i_pino", node.pino),
                    ("i_inline", node.inline),
                    ("i_dir_level", node.dir_level),
                    ("i_current_depth", node.current_depth),
                ):
                    if key not in theirs:
                        continue
                    inode_fields += 1
                    if theirs[key] != value:
                        inode_mismatch.append(
                            f"{path} {key}: my={value} dump.f2fs={theirs[key]}"
                        )
                inode_checked += 1
            entry["inodes_checked"] = inode_checked
            entry["inode_fields"] = inode_fields
            entry["inode_mismatch"] = inode_mismatch[:6]
            entry["inodes_agree"] = not inode_mismatch
            entry["content_same"] = same
            entry["content_wrong"] = wrong
            entry["content_refused"] = refused
            entry["content_mismatch"] = content_mismatch[:6]
            entry["coverage"] = fs.coverage()
            hashes = [
                entry_obj.hash_checked
                for _p, node in fs.walk()
                if node.is_dir
                for entry_obj in fs.listdir(node)
            ]
            entry["dirents"] = len(hashes)
            entry["dirents_hash_checked"] = sum(1 for flag in hashes if flag)
            entry["dirents_hashes_agree"] = all(hashes)
        finally:
            fs.close()
        out["builds"].append(entry)
    if out["builds"] and any(b.get("built") for b in out["builds"]):
        small = root / "f2fs_small.img"
        if small.exists():
            # The hand-built fixtures come from the **small** image, not the big
            # one.  All three need a directory, a file and one inode, and the small
            # image has all of that in 64 MiB; copying the 512 MiB variant three
            # times over to change a dozen bytes in one inode is 1.5 GB of I/O for
            # a test that takes milliseconds either way.
            out["inline_dentry"] = _f2fs_inline_dentry_image(small, root / "f2fs_inline.img")
            out["encrypted"] = _f2fs_encrypted_image(small, root / "f2fs_encrypted.img")
            out["compressed"] = _f2fs_compressed_image(small, root / "f2fs_compressed.img")
    big = root / "f2fs_big.img"
    if big.exists():
        out["dindirect"] = _f2fs_dindirect_refusal(big)
    out["ok"] = bool(out["builds"]) and all(
        b.get("built")
        and b.get("geometry_agrees")
        and b.get("tree_agrees")
        and b.get("inodes_agree")
        and not b.get("content_wrong")
        and b.get("dirents_hashes_agree")
        for b in out["builds"]
    )
    return out


def _check_free_space(root: Path, variants: list[Variant]) -> dict:
    """Check the unallocated-block reader against dumpe2fs and against blkls.

    Two independent things are verified, and the second one is where the interest
    is.

    **The count**, against ``dumpe2fs``'s ``Free blocks`` and against the number
    of zero bits in the bitmaps.  This is the easy agreement and it is worth
    having: the reference image already shows that the three stored counters can
    disagree with each other, so a count taken from the bitmaps needs an outside
    reader saying the same thing.

    **The set**, against ``blkls``.  This is where the first version of this check
    would have reported a pass on a difference.  ``blkls`` emits the same *number*
    of blocks on every image tried, which looks like agreement; marking every
    block on a synthetic image and reading the markers back out of blkls's output
    shows it is not the same *set*.  On a fresh 64 MiB volume with 1 KiB blocks
    the two swap six blocks — because ``ext2fs_block_getflags()`` in TSK excludes
    blocks it classes as metadata *independently of the bitmap*, and with
    ``flex_bg`` the comparison mixes a group's absolute bitmap address with block
    numbers.  So the count is asserted, the set difference is **reported**, and
    the number of blocks TSK claims that the bitmap does not is reported too:
    that number is the one that would be interesting if it were ever larger than a
    handful, and reporting it is how it would be noticed.

    ``blkls`` is optional.  Without it the count check still runs, because that is
    the part that does not depend on TSK's opinion.
    """
    from ...core.ext4 import Ext4
    from ...core.imagemount import tool_path

    out: dict[str, Any] = {"variants": [], "ok": True, "why": ""}
    blkls = tool_path("blkls")
    out["blkls"] = bool(blkls)
    for variant in variants:
        image = root / f"{variant.name}.img"
        if not image.exists():
            continue
        entry: dict[str, Any] = {"name": variant.name}
        try:
            fs = Ext4(str(image))
        except Exception as exc:  # noqa: BLE001 - a refusal is a result here
            entry.update({"opened": False, "error": str(exc)[:200]})
            out["variants"].append(entry)
            out["ok"] = False
            continue
        entry["opened"] = True
        sb = fs.superblock
        blocks = list(fs.unallocated_blocks())
        runs = fs.unallocated_runs(blocks)
        entry["block_size"] = fs.block_size
        entry["free_blocks"] = len(blocks)
        entry["free_bytes"] = len(blocks) * fs.block_size
        entry["runs"] = len(runs)
        entry["runs_sum"] = sum(count for _first, count in runs)
        entry["uninit_groups"] = fs.block_uninit_groups()
        entry["uninit_inconsistent"] = fs.uninit_bitmap_inconsistent()
        entry["uninit_untrusted"] = sorted(fs.uninit_groups_untrusted())
        overlap = fs.unallocated_metadata_overlap(sample=8, blocks=blocks)
        entry["overlap"] = overlap["count"]
        entry["overlap_at_extent_end"] = overlap["at_extent_end"]
        entry["overlap_interior"] = overlap["interior"]
        entry["overlap_blocks"] = overlap["blocks"]
        state = fs.uninit_state()
        entry["uninit_feature"] = state["feature"]
        entry["uninit_by_definition"] = state["by_definition"]
        entry["uninit_state"] = state["state"]
        entry["sparse_super_groups"] = sorted(fs.sparse_super_groups())
        # Zero bits in the bitmaps, counted straight from the bytes, with no
        # clipping and no group arithmetic.  A second opinion on our own loop.
        #
        # ``zero_bits`` keeps its original meaning — every zero bit in every
        # block bitmap on the volume — because a case file pins that number and
        # redefining a reported field under a case that already recorded it is
        # how a regression record stops meaning anything.  In a group flagged
        # BLOCK_UNINIT those bits say "all free" whatever the filesystem thinks,
        # so the *comparison* is made over the measured groups only and the two
        # counts are reported side by side.
        untrusted = set(entry["uninit_untrusted"]) | set(entry["uninit_groups"])
        per_group = sb["blocks_per_group"]
        zero_bits = 0
        measured_zero_bits = 0
        measured_blocks = 0
        for group in range(len(fs._groups)):
            measured = group not in untrusted
            bitmap = fs._group_bitmap(group, "block_bitmap")
            first = group * per_group
            count = min(per_group, sb["blocks_count"] - first)
            for index in range(count):
                if not fs._bit_set(bitmap, index):
                    zero_bits += 1
                    if measured:
                        measured_zero_bits += 1
                        measured_blocks += 1
        entry["zero_bits"] = zero_bits
        entry["measured_blocks"] = measured_blocks
        entry["measured_zero_bits"] = measured_zero_bits
        entry["uninit_groups_excluded"] = sorted(untrusted)
        entry["count_agrees"] = measured_blocks == measured_zero_bits
        reference = _dumpe2fs(image)
        entry["dumpe2fs_free"] = reference.get("free_blocks")
        # With the feature *off*, a BLOCK_UNINIT group's bitmap is not evidence
        # and both this reader and dumpe2fs fall back on the group descriptor, so
        # the two are answering the same question and must give the same number —
        # that is the case this check caught a reader wrong on.  With the feature
        # *on*, the allocator's contract is "the whole group is free" while
        # dumpe2fs reports the recorded count, and the two legitimately differ.
        comparable = not (entry["uninit_groups"] and entry["uninit_feature"])
        entry["dumpe2fs_comparable"] = comparable
        if comparable:
            entry["dumpe2fs_agrees"] = reference.get("free_blocks") == len(blocks)
        else:
            entry["dumpe2fs_agrees"] = None
            entry["dumpe2fs_divergence"] = (
                len(blocks) - (reference.get("free_blocks") or 0)
            )
        entry["dumpe2fs_uninit_bg"] = "uninit_bg" in reference.get("features", [])
        if blkls:
            theirs = _blkls_block_count(blkls, str(image), fs.block_size)
            entry["blkls_blocks"] = theirs
            # Same comparability rule as dumpe2fs: TSK reads a never-written
            # bitmap as metadata-only-free, so on a BLOCK_UNINIT volume it counts
            # the way e2fsprogs does and not the way the allocator does.
            entry["blkls_comparable"] = comparable
            entry["blkls_count_agrees"] = (
                theirs == len(blocks) if comparable else None
            )
            entry["blkls_count"] = {
                "image": str(image),
                "path": blkls,
                "size": "TSK 4.12.1",
            }
            if theirs == len(blocks):
                # Same count is not the same set, and the count is what a first
                # version of this check would have compared.  Both streams are read
                # as hashes of individual blocks rather than stored, so this costs
                # two passes over 55 MB and no disk.
                only_ours = _blkls_set_difference(
                    blkls, str(image), fs, blocks, fs.block_size
                )
                entry["blkls_only_ours"] = len(only_ours)
                entry["blkls_only_ours_blocks"] = only_ours[:8]
        fs.close()
        # ``dumpe2fs_agrees`` is None where the two are not answering the same
        # question (a BLOCK_UNINIT group); that is a reported divergence, not a
        # failure, and treating None as False would fail every volume carrying the
        # flag — including the ``uninitbg`` variant this module builds on purpose.
        agree = entry["count_agrees"] and entry["dumpe2fs_agrees"] is not False
        if blkls and entry.get("blkls_count_agrees") is False:
            agree = False
        # The overlap is reported, not asserted to be zero.  On every image built
        # by mke2fs it is one block, and always the last block of the journal's
        # extent, on a volume that e2fsck -fn calls clean — so treating it as a
        # failure of this reader would be crying wolf over a boundary disagreement
        # that does not move the count.  An overlap in the *interior* of a metadata
        # extent would be a different matter and is asserted to be absent.
        entry["ok"] = agree and not entry["overlap_interior"]
        out["variants"].append(entry)
        out["ok"] = out["ok"] and agree
    out["checked"] = len(out["variants"])
    return out


def _blkls_block_count(tool: str, image: str, block_size: int) -> int | None:
    """How many blocks ``blkls`` emits, counted by byte length.

    Read through a pipe and counted rather than stored: the reference image's
    free space is 9,51 GiB and writing it to disk to measure it would be a second
    copy of evidence for no reason.  ``blkls`` needs ``-f ext4`` on a plain image
    file, because it cannot guess a filesystem from a file it has not been told
    about and says so with a usage message rather than an error.
    """
    import subprocess

    try:
        proc = subprocess.Popen(  # noqa: S603 - argv built here, never a shell
            [tool, "-f", "ext4", image],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    total = 0
    assert proc.stdout is not None
    while True:
        chunk = proc.stdout.read(4 * 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
    proc.stdout.close()
    proc.wait()
    return total // block_size


def _blkls_set_difference(
    tool: str, image: str, fs, blocks: list[int], block_size: int
) -> list[int]:
    """Blocks we call free that ``blkls`` did not emit.

    Compared by content hash rather than by position, because the two streams are
    not in the same order and a position comparison would call every block
    different.  Free space on a freshly built volume is mostly zeros, so a hash of
    each block is compared against the multiset of hashes we would emit; the answer
    is the blocks present in ours and absent from blkls's.

    The expected answer is a small non-zero number, and a large one would mean
    something else entirely: that the two readers disagree about which blocks the
    filesystem is using.  TSK's ``ext2fs_block_getflags()`` excludes blocks it
    classes as metadata without consulting the bitmap, and with ``flex_bg`` that
    classification mixes a group's absolute bitmap address with block numbers — the
    same function carries a comment admitting an off-by-one there.
    """
    import hashlib
    import subprocess

    mine: dict[bytes, list[int]] = {}
    for block in blocks:
        digest = hashlib.sha256(fs._cache.get(block)).digest()
        mine.setdefault(digest, []).append(block)
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv built here, never a shell
            [tool, "-f", "ext4", image],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    theirs: set[bytes] = set()
    assert proc.stdout is not None
    while True:
        chunk = proc.stdout.read(block_size * 256)
        if not chunk:
            break
        for at in range(0, len(chunk) - block_size + 1, block_size):
            theirs.add(hashlib.sha256(chunk[at : at + block_size]).digest())
    proc.stdout.close()
    proc.wait()
    return sorted(block for digest, group in mine.items() if digest not in theirs for block in group)


def _carve_fixture(root: Path) -> dict[str, Any]:
    """Build a filesystem with known-deleted content and carve it back.

    The point is a **fixture whose answer is known**.  The reference image gives
    51 903 names and three content candidates, and there is no way to tell from
    this side whether that is right: a missed candidate and a false positive look
    the same in a report.  So the files are written here, deleted here, and the
    original bytes are kept to compare against.

    The files are real: a PNG with correct chunk CRCs, a real gzip stream, a plain
    text file with no signature at all, and a file that begins with a PNG signature
    and is then garbage.  The last two matter as much as the first two — a carver
    that finds everything is as useless as one that finds nothing, and the text
    file is the case a signature table cannot win by accident.

    Deletion is ``debugfs -w -R "rm"``, which needs no mount and no root.

    **The name half needs a different fixture, built by hand.**  ``debugfs rm``
    releases the directory entry outright, so there is nothing left to find: the
    name carver sees a clean directory and correctly reports nothing.  What ext4
    does on a real unlink is the other thing — it *merges* a live entry with the
    entries deleted after it, and the deleted names survive inside the swallowing
    record's payload.  That is exactly what block 498705 of the reference image
    looks like, where the record for ``micro_thumbnail_blob.1`` is 3916 bytes
    long.  So the fixture writes that shape directly: one live record whose
    ``rec_len`` covers the rest of the block, with three dentries written inside
    it.  Then the test asserts both halves of the split — the chain walk must find
    nothing, and the window must find all three — which is the whole distinction
    the module draws.
    """
    import io
    import shutil
    import struct
    import zlib

    from ...core.carve import VALIDATED, carve_run
    from ...core.ext4 import Ext4
    from ...core.imagemount import tool_path

    out: dict[str, Any] = {"ok": False, "available": True, "why": ""}
    mkfs = tool_path("mke2fs")
    debugfs = tool_path("debugfs")
    if not (mkfs and debugfs):
        out.update({"available": False, "why": "brak mke2fs lub debugfs (e2fsprogs)"})
        return out

    src = root / "carve_src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)

    def png_chunk(kind: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + kind
            + payload
            + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
        )

    header = struct.pack(">IIBBBBB", 8, 8, 8, 2, 0, 0, 0)
    pixels = b"".join(
        b"\x00" + bytes([(x * 8) % 256, (x * 3) % 256, (x * 5) % 256] * 8) for x in range(8)
    )
    png = (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", header)
        + png_chunk(b"IDAT", zlib.compress(pixels))
        + png_chunk(b"IEND", b"")
    )
    import gzip

    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode="wb", mtime=0) as handle:
        handle.write(b"forensic carve " * 500)
    archive = buffer.getvalue()
    text = b"plain text with no signature anywhere in it\n" * 40
    impostor = b"\x89PNG\r\n\x1a\n" + b"\xff" * 40
    (src / "photo.png").write_bytes(png)
    (src / "archive.tgz").write_bytes(archive)
    (src / "notes.txt").write_bytes(text)
    (src / "impostor.png").write_bytes(impostor)
    (src / "gone.bin").write_bytes(b"no signature here either\n" * 90)

    image = root / "carve.img"
    with image.open("wb") as handle:
        handle.truncate(64 * 1024 * 1024)
    made = _run([mkfs, "-q", "-F", "-t", "ext4", "-O", "^64bit,^metadata_csum", str(image)])
    if made[0] != 0:
        out["why"] = f"mke2fs: {made[1][:200]}"
        return out
    for name in ("photo.png", "archive.tgz", "notes.txt", "impostor.png", "gone.bin"):
        written = _run(
            [debugfs, "-w", "-R", f"write {src / name} /{name}", str(image)]
        )
        if written[0] != 0:
            out["why"] = f"debugfs write {name}: {written[1][:200]}"
            return out
    for name in ("photo.png", "archive.tgz", "notes.txt", "impostor.png", "gone.bin"):
        _run([debugfs, "-w", "-R", f"rm /{name}", str(image)])

    fs = Ext4(str(image))
    try:
        runs = fs.unallocated_runs()
        found: list = []
        rejected: dict[str, int] = {}
        for first, count in runs:
            result = carve_run(
                list(range(first, first + count)), lambda block: fs._cache.get(block),
                fs.block_size,
            )
            found.extend(result["candidates"])
            for kind, number in result["rejected"].items():
                rejected[kind] = rejected.get(kind, 0) + number
        with open(image, "rb") as handle:
            recovered: dict[str, bool] = {}
            for item in found:
                handle.seek(item.offset)
                blob = handle.read(item.length)
                if item.kind == "png":
                    recovered["png"] = blob == png
                elif item.kind == "gzip":
                    recovered["gzip"] = blob == archive
        names = _merged_dentry_block(image, debugfs, fs)
    finally:
        fs.close()
    out["content"] = {
        "candidates": [
            {"kind": item.kind, "grade": item.grade, "length": item.length,
             "truncated": item.truncated, "offset": item.offset, "detail": item.detail}
            for item in found
        ],
        "kinds": sorted({item.kind for item in found}),
        "rejected": rejected,
        "png_recovered_exact": recovered.get("png", False),
        "gzip_recovered_exact": recovered.get("gzip", False),
        "plain_text_carved": any(item.kind not in ("png", "gzip") for item in found),
        "impostor_carved": False,
        "expected": {
            "carved": ["gzip", "png"],
            "not_carved": ["gone.bin", "impostor.png", "notes.txt"],
        },
    }
    out["names"] = names
    out["ok"] = bool(
        recovered.get("png")
        and recovered.get("gzip")
        and sorted({item.kind for item in found}) == ["gzip", "png"]
        and all(item.grade == VALIDATED and not item.truncated for item in found)
        and names.get("ok")
    )
    return out


def _merged_dentry_block(image: Path, debugfs: str, fs) -> dict[str, Any]:
    """Write a directory block in the shape ext4 leaves after an unlink.

    One live record whose ``rec_len`` covers the whole rest of the block, with
    three dentries inside its payload: a ``d_ino``-zero record, which is what the
    kernel writes on unlink, and two with inode numbers.  That is the reference
    image's block 498705 in miniature.

    Written straight into the block and pointed at by the directory's ``i_addr``,
    which is the same approach the ext4 xattr fixture of the tenth turn and the
    F2FS inline-directory fixture of the sixteenth both needed — no tool produces
    the shape, so the fixture is assembled from the layout.
    """
    import struct

    root = fs.inode(fs.superblock["root_ino"] if "root_ino" in fs.superblock else 2)
    block = next(iter(fs.data_blocks(root)))
    block_size = fs.block_size

    def record(name: bytes, ino: int, ftype: int) -> bytes:
        length = 8 + len(name)
        length = (length + 3) & ~3
        return struct.pack("<IHBB", ino, length, len(name), ftype) + name.ljust(
            length - 8, b"\0"
        )

    dots = record(b".", 2, 2) + record(b"..", 2, 2)
    live_name = b"swallowed.bin"
    # The live record's rec_len is stretched to the end of the block, and the
    # deleted records are written inside its payload.  This is the whole point:
    # a chain walk cannot see them, because the chain ends here.
    live = bytearray(struct.pack("<IHBB", 12, block_size - len(dots), len(live_name), 1))
    live += live_name.ljust(len(dots) - 8, b"\0")
    deleted = record(b"unlinked_one.txt", 0, 1)
    deleted += record(b"unlinked_two.log", 0, 1)
    deleted += record(b"unlinked_three.dat", 99, 1)
    body = bytes(dots) + bytes(live) + deleted
    if len(body) > block_size:
        return {"ok": False, "why": f"fixture za duży: {len(body)} > {block_size}"}
    with open(image, "r+b") as handle:
        handle.seek(block * block_size)
        handle.write(body.ljust(block_size, b"\0"))
    check = fs.__class__(str(image))
    try:
        names = check.unlinked_entries()
        chain = sorted(item["name"] for item in names["chain_unlinked"])
        window = sorted(item["name"] for item in names["window_only"])
        return {
            "ok": (
                not chain
                and window
                == ["unlinked_one.txt", "unlinked_three.dat", "unlinked_two.log"]
            ),
            "block": block,
            "chain_names": chain,
            "window_names": window,
            "chain_total": names["chain_unlinked_total"],
            "window_total": names["window_only_total"],
            "why": (
                "łańcuch rekordów kończy się na pochłoniętym rekordzie, więc żadna "
                "z trzech usuniętych nazw nie jest w łańcuchu — dwie z zerowym numerem "
                "inoda i jedna z numerem. To jest silniejsze niż argument z obrazu "
                "referencyjnego, gdzie trafienia z zerowym numerem inoda akurat w "
                "łańcuchu zostały: forma zależy od tego, który wpis usunięto w "
                "której kolejności, a okno znajduje je w obu"
            ),
        }
    finally:
        check.close()


def _check_formats(root: Path) -> dict[str, Any]:
    """Verify the filesystem identification table against hand-placed magics.

    Detection needs one magic number at one offset, so the fixture is the magic
    number at that offset — no ``mkfs.erofs``, no ``mkfs.f2fs``, no
    ``mksquashfs``.  That matters: a self-test that needs four extra packages
    installed is a self-test that silently stops running, and the offsets are
    the part most worth protecting, since a wrong one makes every image look
    unrecognised.
    """
    from ...core import fsformat

    results: list[dict[str, Any]] = []
    wrong: list[str] = []
    for signature in fsformat.SIGNATURES:
        path = root / f"magic_{signature.kind}.bin"
        # At least 2048 bytes, so the ext4 reader gets a whole superblock and
        # actually reaches the magic check.  A fixture just long enough to hold
        # the magic makes the reader fail earlier, on size, and the refusal
        # message never mentions the format — the test would then be testing
        # the wrong thing while reporting a format problem.
        size = max(signature.offset + len(signature.magic) + 8, 2048)
        with path.open("wb") as handle:
            handle.truncate(size)
            handle.seek(signature.offset)
            handle.write(signature.magic)
        found = fsformat.detect(path)
        ok = found["kind"] == signature.kind and found["readable"] == signature.readable
        if not ok:
            wrong.append(signature.kind)
        # The refusal message has to name the format, not just complain about a
        # missing ext4 magic: that sentence is the entire point of the table.
        refusal = ""
        if not signature.readable:
            try:
                Ext4(str(path))
                refusal = "czytnik otworzył plik, którego nie powinien"
                wrong.append(signature.kind)
            except Ext4Error as exc:
                refusal = str(exc)
                if signature.name not in refusal:
                    refusal = "BLAD: komunikat nie wymienia formatu"
                    wrong.append(signature.kind)
        results.append(
            {
                "kind": signature.kind,
                "name": signature.name,
                "offset": signature.offset,
                "readable": signature.readable,
                "reader": signature.reader,
                "identified": found["kind"],
                "ok": ok,
                "refusal": refusal[:200],
            }
        )
    blank = root / "magic_none.bin"
    with blank.open("wb") as handle:
        handle.truncate(fsformat.PROBE_BYTES)
    unknown = fsformat.detect(blank)
    if unknown["kind"] != fsformat.UNKNOWN:
        wrong.append("unknown")
    return {
        "results": results,
        "unknown_kind": unknown["kind"],
        "wrong": wrong,
        "ok": not wrong,
    }


def _attach_xattr(root: Path, variant: Variant) -> dict[str, Any]:
    """Build a file with a known xattr and read it back with our own reader.

    The block is written straight into the image file and ``i_file_acl`` is
    pointed at it, so no root, no loop device and no mount is involved.  The
    return value reports what the reader then made of it — which makes this a
    test of the xattr parser and not merely a fixture: a parser that guesses
    would have to guess the right bytes.
    """
    from ...core.ext4 import XATTR_HEADER_BYTES, XATTR_ENTRY_FIXED

    image = root / f"{variant.name}.img"
    label = root / f"{variant.name}.payload"
    label.write_bytes(XATTR_VALUE.rstrip(b"\0") + b"\n")
    tool = _tool("debugfs")
    if not tool:
        return {"ok": False, "why": "debugfs niedostępny"}
    code, out = _run([tool, "-w", "-R", f"write {label} {XATTR_PATH}", str(image)])
    if code != 0:
        return {"ok": False, "why": f"debugfs write: {out.strip()[:160]}"}
    block = _xattr_block(XATTR_SUFFIX, XATTR_VALUE, XATTR_INDEX)
    fs = Ext4(str(image))
    try:
        target = None
        for _path, entry in fs.walk("/"):
            if entry.is_reg:
                target = entry
                break
        if target is None:
            return {"ok": False, "why": "wariant nie zawiera żadnego pliku"}
        sb = fs.superblock
        group, index = divmod(target.inode - 1, sb["inodes_per_group"])
        table = fs._groups[group]["inode_table"]
        per_block = sb["block_size"] // sb["inode_size"]
        inode_block = table + index // per_block
        inode_at = (index % per_block) * sb["inode_size"]
        # Park the attribute block past the inode tables of the last group, which
        # on a fresh image is free space and cannot collide with metadata.
        attr_block = fs._groups[-1]["inode_table"] + 40
        if attr_block >= sb["blocks_count"]:
            return {"ok": False, "why": "brak miejsca na blok atrybutów"}
        with image.open("r+b") as handle:
            handle.seek(attr_block * sb["block_size"])
            handle.write(block)
            handle.seek(inode_block * sb["block_size"] + inode_at + 0x68)
            handle.write(struct.pack("<I", attr_block))
            handle.seek(inode_block * sb["block_size"] + inode_at + 0x76)
            handle.write(struct.pack("<H", 0))
    finally:
        fs.close()
    check = Ext4(str(image))
    try:
        node = check.inode(target.inode)
        got = node.xattrs.get(f"security.{XATTR_SUFFIX}")
        reference = ""
        code, out = _run([tool, "-R", f"stat {XATTR_PATH}", str(image)])
        for line in out.splitlines():
            if line.startswith("File ACL:"):
                reference = line.split(":", 1)[1].strip()
        return {
            "ok": got == XATTR_VALUE,
            "host": variant.name,
            "name": f"security.{XATTR_SUFFIX}",
            "value": XATTR_VALUE.decode("utf-8", "replace"),
            "value_bytes": len(XATTR_VALUE),
            "block_bytes": len(block),
            "read_back": "" if got is None else got.decode("utf-8", "replace"),
            "inode": target.inode,
            "text_property": node.selinux,
            "block_layout": (
                f"magic@0 value@{XATTR_HEADER_BYTES + XATTR_ENTRY_FIXED}+"
                f"{len(XATTR_SUFFIX)}"
            ),
            "i_file_acl_debugfs": reference,
        }
    finally:
        check.close()


@dataclass(frozen=True)
class Corruption:
    """One structure damaged in one specific way, and what must not happen.

    The invariant is ``never silent``.  Whether a damaged filesystem must be
    *refused* is a separate question with a separate answer per structure: a
    zeroed block bitmap can be read, and reading it is the honest result, because
    the bitmap genuinely says something and the reader did not invent it.  A
    superblock whose magic is gone is not readable at all and must be refused.

    So each case declares ``expect_refuse`` and every case must satisfy
    ``never silent``.  The critical finding this module exists for is a reader
    that opens the image, reports no exception, and produces an empty tree — a
    report cannot tell that from an empty filesystem.
    """

    name: str
    #: Patches bytes at the offsets it is given.  Offsets are resolved by opening
    #: the image with our own reader first, so a fixture does not hardcode an
    #: offset that a different block size would put somewhere else.
    damage: Any
    why: str
    expect_refuse: bool = True
    #: What the damage must NOT achieve, in the module's own terms.
    never: str = ""


def _inode_offset(fs: Ext4, number: int) -> int:
    """Byte offset of an inode, mirroring :meth:`Ext4.inode` exactly."""
    sb = fs.superblock
    group, index = divmod(number - 1, sb["inodes_per_group"])
    table = fs._groups[group]["inode_table"]
    per_block = sb["block_size"] // sb["inode_size"]
    return (table + index // per_block) * sb["block_size"] + (
        index % per_block
    ) * sb["inode_size"]


def _offsets_for(path: Path) -> dict[str, Any]:
    """Byte offsets of the structures the corruptions target.

    Read through our own reader on purpose.  Hardcoding ``blocks_count * 4`` or
    an inode table number would encode a block size into a fixture that is meant
    to be built by ``mke2fs``, and the offset would be wrong for every variant
    that is not 4 KiB — a corruption that lands in free space tests nothing and
    reports as accepted.
    """
    with Ext4(str(path)) as fs:
        sb = fs.superblock
        out: dict[str, Any] = {
            "block_size": sb["block_size"],
            "size": path.stat().st_size,
            "sb_offset": 1024 + 0x38,               # s_magic
            "sb_blocks_count": 1024 + 0x04,         # s_blocks_count
            "gd_block": (sb["first_data_block"] + 1) * sb["block_size"],
            "inode_table": fs._groups[0]["inode_table"] * sb["block_size"],
            # The root inode, placed the way :meth:`Ext4.inode` places it: find the
            # group's inode table, then divide the index by how many inodes fit
            # in a block.  The first version of this used ``first_data_block + 1``
            # — the block after the superblock, which holds the group *descriptor*
            # table — and so computed offset 4352 on a 4 KiB volume whose inode
            # table is at 167936.  All three inode corruptions landed in the
            # descriptor area, changed nothing, and the self-test reported them as
            # accepted with three root entries.  A corruption that lands in free
            # space is indistinguishable from a reader that handled one, which is
            # the exact reason this helper exists.
            "root_inode": _inode_offset(fs, EXT4_ROOT_INODE),
            "block_bitmap": fs._groups[0]["block_bitmap"] * sb["block_size"],
        }
        try:
            node = fs.inode(EXT4_ROOT_INODE)
            if node.extents:
                out["root_data_block"] = node.extents[0].physical * sb["block_size"]
        except (Ext4Error, KeyError):
            pass
        return out


def _corrupt(path: Path, patches: list[tuple[int, bytes]]) -> None:
    with open(path, "r+b") as handle:
        for offset, data in patches:
            handle.seek(offset)
            handle.write(data)


def _zero(n: int) -> bytes:
    return bytes(n)


def _ff(n: int) -> bytes:
    return b"\xff" * n


def _corruption_cases() -> list[tuple[str, Any]]:
    """``(name, function(image) -> list[(offset, bytes)])`` for each case.

    A function rather than a constant because the offsets depend on the image,
    and an image is built per run.
    """

    def sb_magic(image: Path) -> list[tuple[int, bytes]]:
        off = _offsets_for(image)
        return [(off["sb_offset"], _zero(2))]

    def sb_blocks_count(image: Path) -> list[tuple[int, bytes]]:
        """Declare far more blocks than the file holds.

        The filesystem's own statement about its size is now bigger than the
        evidence.  ``truncated_bytes`` should say so at open time, and any read
        past the cut must raise rather than be padded out to the declared length.
        """
        off = _offsets_for(image)
        return [(off["sb_blocks_count"], _ff(4))]

    def gd_zeroed(image: Path) -> list[tuple[int, bytes]]:
        off = _offsets_for(image)
        return [(off["gd_block"], _zero(off["block_size"]))]

    def inode_table_past_eof(image: Path) -> list[tuple[int, bytes]]:
        off = _offsets_for(image)
        return [(off["gd_block"] + 0x08, _ff(4))]

    def inode_mode_zero(image: Path) -> list[tuple[int, bytes]]:
        off = _offsets_for(image)
        return [(off["root_inode"], _zero(2))]

    def inode_size_huge(image: Path) -> list[tuple[int, bytes]]:
        """``i_size`` far beyond the blocks the filesystem has."""
        off = _offsets_for(image)
        return [(off["root_inode"] + 0x04, _ff(4))]

    def extent_count_huge(image: Path) -> list[tuple[int, bytes]]:
        """The root's first extent claims a huge run starting at block zero.

        ``ee_len`` is 16 bits and its high bit is the uninitialised flag, so a
        plain ``0xFFFF`` is the largest run the format can express — 32768 blocks
        on a 4 KiB volume, 128 MiB, far past the end of a 64 MiB image.
        """
        off = _offsets_for(image)
        # i_block starts at 0x28 inside the inode; the 12-byte extent header
        # sits at its front, so the first record is at +12 and ``ee_len`` — the
        # second field of that record — is 4 bytes further on.  Writing at +4
        # instead lands on ``eh_max`` and changes nothing an extent tree depends
        # on, which the self-test reported as an accepted variant and no warning.
        return [(off["root_inode"] + 0x28 + 12 + 4, _ff(2))]

    def block_bitmap_zero(image: Path) -> list[tuple[int, bytes]]:
        off = _offsets_for(image)
        return [(off["block_bitmap"], _zero(off["block_size"]))]

    def truncate_block(image: Path) -> list[tuple[int, bytes]]:
        off = _offsets_for(image)
        with open(image, "r+b") as handle:
            handle.truncate(off["size"] - off["block_size"])
        return []

    def truncate_byte(image: Path) -> list[tuple[int, bytes]]:
        off = _offsets_for(image)
        with open(image, "r+b") as handle:
            handle.truncate(off["size"] - 1)
        return []

    return [
        ("sb_magic", sb_magic),
        ("sb_blocks_count", sb_blocks_count),
        ("gd_zeroed", gd_zeroed),
        ("inode_table_past_eof", inode_table_past_eof),
        ("inode_mode_zero", inode_mode_zero),
        ("inode_size_huge", inode_size_huge),
        ("extent_count_huge", extent_count_huge),
        ("block_bitmap_zeroed", block_bitmap_zero),
        ("truncate_one_block", truncate_block),
        ("truncate_one_byte", truncate_byte),
    ]


#: What each corruption is for, and — where the honest answer is not "refuse" —
#: what the reader is allowed to do instead.
CORRUPTION_WHY: dict[str, tuple[str, bool]] = {
    "sb_magic": ("s_magic nie jest 0xEF53 — to nie jest filesystem", True),
    "sb_blocks_count": (
        "s_blocks_count deklaruje więcej bloków, niż jest w pliku; obraz jest "
        "ucięty i musi tak powiedzieć, zanim cokolwiek przeczyta",
        False,
    ),
    "gd_zeroed": (
        "tablica deskryptorów grup wyzerowana — inode_table wskazuje blok 0, "
        "czyli na metadane",
        True,
    ),
    "inode_table_past_eof": (
        "bg_inode_table wskazuje za koniec obrazu — tablica inodów jest poza plikiem",
        False,
    ),
    "inode_mode_zero": ("i_mode zerowy — inode nie jest plikiem, katalogiem ani dowiązaniem", False),
    "inode_size_huge": ("i_size korzenia ogromne przy niezmienionej mapie bloków", False),
    "extent_count_huge": (
        "ee_len korzenia to 32768 bloków przy obrazie 64 MiB —extent sięga za "
        "koniec pliku; czytanie tego zakresu musi zgłosić ucięcie, nie wypełnić go zerami",
        False,
    ),
    "block_bitmap_zeroed": (
        "bitmap bloków wyzerowany — czytelnik MOŻE to przyjąć i zaraportować "
        "bloki jako wolne; bitmapa naprawdę tak twierdzi i to nie jest zmyślone",
        False,
    ),
    "truncate_one_block": ("brak ostatniego bloku obrazu", False),
    "truncate_one_byte": ("brak ostatniego bajtu obrazu", False),
}


def _check_corruption(root: Path, base: Path) -> dict[str, Any]:
    """Damage a clean image in nine ways and require the reader to stay honest.

    Each case gets its own copy, because the damage is destructive and the cases
    are independent.  The image is rebuilt from ``mke2fs`` for each one rather
    than re-damaged from the previous, so one case cannot mask another.
    """
    results: list[dict[str, Any]] = []
    silent: list[str] = []
    wrong: list[str] = []
    tool = _tool("mke2fs")
    if not tool:
        return {"available": False, "why": "mke2fs nie jest zainstalowany (e2fsprogs)",
                "cases": 0, "silent": [], "wrong": []}
    for name, damage in _corruption_cases():
        why, expect_refuse = CORRUPTION_WHY[name]
        image = root / f"corrupt_{name}.img"
        try:
            with image.open("wb") as handle:
                handle.truncate(SYNTH_SIZE)
            code, out = _run([tool, "-q", "-F", "-t", "ext4", "-b", "4096", str(image)])
            if code != 0:
                results.append({"name": name, "built": False, "error": out.strip()[:200]})
                continue
            patches = damage(image)
            if patches:
                _corrupt(image, patches)
        except OSError as exc:
            results.append({"name": name, "built": False, "error": str(exc)[:200]})
            continue
        probe = _probe(image)
        entry: dict[str, Any] = {
            "name": name,
            "built": True,
            "why": why,
            "expect_refuse": expect_refuse,
            "opened": bool(probe.get("opened")),
            "refused": bool(probe.get("refused")),
            "truncated": bool(probe.get("truncated")),
            "truncated_bytes": probe.get("truncated_bytes", 0),
            "silent": bool(probe.get("silent")),
            "refused_at": probe.get("refused_at", ""),
            "error": probe.get("error", "")[:200],
            "root_entries": probe.get("root_entries"),
        }
        # The invariant, stated once: never silent.
        if entry["silent"]:
            silent.append(name)
        # And the per-case expectation, which is deliberately looser than
        # "refuse" for the cases where reading the damaged bytes is the truth.
        if expect_refuse and not entry["refused"]:
            wrong.append(name)
            entry["unexpected"] = (
                "reader przyjął strukturę, której nie da się wiarygodnie odczytać"
            )
        results.append(entry)
    return {
        "available": True,
        "cases": len(results),
        "silent": silent,
        "wrong": wrong,
        "refused": sum(1 for e in results if e.get("refused")),
        "truncated_detected": sum(1 for e in results if e.get("truncated")),
        "detail": results,
    }


def _probe(image: Path) -> dict[str, Any]:
    """Open the image and actually traverse it; report what came back.

    The three-way result is the point.  ``silent`` — opened, no exception, empty
    root — is the failure this module exists to catch, and it is separated from
    ``refused`` precisely because it used to look like success.

    The refusal is caught around the whole traversal, not just around the
    constructor, because the reader is lazy and refuses at different moments for
    different constructs: ``metadata_bg`` is caught when the image is opened,
    classic ext2 mapping only when the root inode is first read.  A harness that
    only watched the constructor would see the ext2 case as a crash.
    """
    out: dict[str, Any] = {}
    fs = None
    try:
        fs = Ext4(str(image))
        out["opened"] = True
        out["truncated_bytes"] = fs.truncated_bytes
    except TruncatedEvidenceError as exc:
        out.update({"opened": False, "refused": True, "refused_at": "open",
                    "truncated": True, "error": f"TruncatedEvidenceError: {exc}"[:300]})
        return out
    except Ext4Error as exc:
        out.update({"opened": False, "refused": True, "refused_at": "open", "error": str(exc)[:300]})
        return out
    except Exception as exc:  # noqa: BLE001 - a crash is also a refusal, but a different one
        out.update(
            {"opened": False, "refused": True, "refused_at": "open",
             "error": f"{type(exc).__name__}: {exc}"[:300]}
        )
        return out
    try:
        entries = fs.listdir("/")
        out["root_entries"] = len(entries)
        files: list[str] = []
        for path, entry in fs.walk("/"):
            if entry.is_reg and entry.size > 0:
                files.append(path)
        out["regular_files"] = len(files)
        read_ok = 0
        read_bytes = 0
        for path in files[:20]:
            try:
                blob = fs.read(path)
            except Ext4Error:
                continue
            if blob:
                read_ok += 1
                read_bytes += len(blob)
        out["readable"] = read_ok
        out["read_bytes"] = read_bytes
        out["refused"] = False
        if not entries or (files and read_ok == 0):
            # Opened without complaint and produced nothing usable.  Whatever the
            # cause, a report would read this as an empty filesystem.
            out["silent"] = True
        else:
            out["silent"] = False
        sb = fs.superblock
        out["geometry"] = {
            "block_size": sb["block_size"],
            "inode_size": sb["inode_size"],
            "blocks_count": sb["blocks_count"],
            "inodes_count": sb["inodes_count"],
            "free_blocks": sb["free_blocks"],
            "free_inodes": sb["free_inodes"],
            "desc_size": sb["desc_size"],
            "groups": len(fs._groups),
        }
        out["features"] = sb["features"]
        out["has_xattr_block"] = _xattr_inode_count(fs)
    except TruncatedEvidenceError as exc:
        # Its own bucket, and it has to be its own.  ``TruncatedEvidenceError`` is
        # deliberately not an ``Ext4Error`` — a caller catching ``Ext4Error`` to
        # mean "wrong format" must not swallow missing evidence — and this
        # harness is exactly such a caller, so without this arm the distinction
        # would be tested nowhere at all.
        out.update({"refused": True, "refused_at": "traverse", "truncated": True,
                    "error": f"TruncatedEvidenceError: {exc}"[:300], "silent": False})
    except Ext4Error as exc:
        out.update({"refused": True, "refused_at": "traverse", "error": str(exc)[:300],
                    "silent": False})
    except Exception as exc:  # noqa: BLE001
        out.update({"refused": True, "refused_at": "traverse",
                    "error": f"{type(exc).__name__}: {exc}"[:300], "silent": False})
    finally:
        if fs is not None:
            fs.close()
    return out


def _xattr_inode_count(fs: Ext4) -> int:
    """How many inodes point at an extended-attribute block.

    Deliberately counts the pointer and does not parse the block: that is the
    whole of what can be checked before the xattr reader exists, and it is
    enough to prove the fixture is a fixture.  The redmi3 image has three such
    inodes out of 1 687 552, which is why a deterministic one is built here.
    """
    import struct

    sb = fs.superblock
    per_group = sb["inodes_per_group"]
    size = sb["inode_size"]
    per_block = sb["block_size"] // size
    found = 0
    for group in fs._groups:
        table = group["inode_table"]
        wanted = min(per_group, max(0, sb["inodes_count"] - group["group"] * per_group))
        for start in range(0, wanted, per_block * 64):
            count = min(per_block * 64, wanted - start)
            data = b"".join(
                fs._cache.get(table + (start // per_block) + offset)
                for offset in range(-(-count // per_block))
            )
            for index in range(count):
                at = index * size
                if at + 0x6A > len(data):
                    break
                low = struct.unpack_from("<I", data, at + 0x68)[0]
                high = (
                    struct.unpack_from("<H", data, at + 0x76)[0] if size > 0x78 else 0
                )
                if low or high:
                    found += 1
    return found


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("ext4_selftest")
    for required in ("mke2fs", "dumpe2fs"):
        if not _tool(required):
            res.add(
                "warn",
                f"Brak {required} (e2fsprogs) — syntetyczne obrazy ext4 nie powstaną",
                detail="sudo apt install e2fsprogs",
                values={"missing": required},
            )
            return ctx.record(res)
    wanted = params.get("variants") or [v.name for v in VARIANTS]
    names = {str(item) for item in wanted}
    selected = [v for v in VARIANTS if not names or v.name in names]
    unknown = sorted(names - {v.name for v in VARIANTS})
    if unknown:
        res.add("critical", f"nieznany wariant: {', '.join(unknown)}",
                values={"valid": [v.name for v in VARIANTS]})
        return ctx.record(res)
    root = synth_root(ctx)
    started = time.time()
    parts: list[dict[str, Any]] = []
    silent: list[str] = []
    wrong: list[str] = []
    mismatched: list[dict] = []
    for variant in selected:
        entry: dict[str, Any] = {
            "name": variant.name,
            "expect_accept": variant.accept,
            "why": variant.why,
            "mke2fs": " ".join(variant.mke2fs),
        }
        image, error = _build(root, variant)
        if image is None:
            entry.update({"built": False, "error": error})
            parts.append(entry)
            wrong.append(variant.name)
            continue
        entry["built"] = True
        entry["image"] = str(image)
        probe = _probe(image)
        entry.update({k: v for k, v in probe.items() if k != "opened"})
        accepted = bool(probe.get("opened")) and not probe.get("refused")
        entry["accepted"] = accepted
        entry["silent"] = bool(probe.get("silent"))
        if accepted != variant.accept:
            wrong.append(variant.name)
            entry["unexpected"] = (
                "reader odmówił wariantu, który ma obsługiwać"
                if variant.accept
                else "reader przyjął wariant, którego nie obsługuje"
            )
        if entry["silent"]:
            silent.append(variant.name)
        if accepted:
            reference = _dumpe2fs(image)
            geometry = probe.get("geometry", {})
            # The numbers and the feature names are both kept: the numbers carry
            # the geometry agreement, the names catch a bit that lands in the
            # wrong place — which is exactly how the 8th turn's feature tables
            # turned out to be wrong, and no geometry number would have shown it.
            entry["reference"] = {
                k: reference.get(k)
                for k in (
                    "block_size", "inode_size", "block_count", "inode_count",
                    "free_blocks", "free_inodes", "group_descriptor_size",
                )
            }
            entry["reference_features"] = reference.get("features", [])
            entry["geometry_agrees"] = _geometry_agrees(geometry, reference)
            if not entry["geometry_agrees"]:
                mismatched.append({"variant": variant.name, "ours": geometry,
                                   "dumpe2fs": entry["reference"]})
            probes = FEATURE_PROBE.get(variant.name, ())
            entry["features_expected"] = [ours for ours, _ in probes]
            entry["features_present"] = [name for name, _ in probes if name in probe.get("features", [])]
            entry["features_in_dumpe2fs"] = [
                theirs for _, theirs in probes if theirs in reference.get("features", [])
            ]
        parts.append(entry)
    # One variant additionally carries a known xattr: the fixture the xattr
    # reader will be tested against, with a value that is fixed by construction.
    host = next((v for v in selected if v.name == XATTR_HOST and v.accept), None)
    fixture: dict[str, Any] = {"ok": False, "why": "brak wariantu desc32 w przebiegu"}
    if host is not None:
        fixture = _attach_xattr(root, host)
        entry = next(e for e in parts if e["name"] == host.name)
        entry["xattr_fixture"] = fixture
    corruption = _check_corruption(root, root / "desc32.img")
    formats = _check_formats(root)
    erofs = _build_erofs_fixture(root)
    f2fs = _build_f2fs_fixture(root)
    freespace = _check_free_space(root, selected)
    carvetest = _carve_fixture(root)
    res.data = {
        "variants": len(parts),
        "accepted": sum(1 for e in parts if e.get("accepted")),
        "refused": sum(1 for e in parts if e.get("refused") and not e.get("accepted")),
        "silent": len(silent),
        "unexpected": wrong,
        "geometry_mismatched": mismatched,
        "corruption": corruption,
        "xattr_fixture": fixture,
        "formats": formats,
        "erofs": erofs,
        "f2fs": f2fs,
        "free_space": freespace,
        "carve_test": carvetest,
        "root": str(root),
        "results": parts,
    }
    if not formats["ok"]:
        res.add(
            "critical",
            f"Rozpoznawanie formatów: {len(formats['wrong'])} niezgodności",
            detail="; ".join(formats["wrong"]),
            values=formats,
        )
    else:
        readable = [e["kind"] for e in formats["results"] if e["readable"]]
        named = [e["name"] for e in formats["results"] if not e["readable"]]
        res.add(
            "ok",
            f"Rozpoznawanie formatów: {len(formats['results'])} sygnatur na swoich "
            f"offsetach, plik bez magiki → {formats['unknown_kind']}",
            detail=(
                f"obsługiwane: {', '.join(readable)}; rozpoznawane i jawnie "
                f"odrzucane: {', '.join(named)} — komunikat błędu wymienia format"
            ),
            values={
                "signatures": len(formats["results"]),
                "unknown": formats["unknown_kind"],
                "wrong": formats["wrong"],
            },
        )
    if not erofs["available"]:
        res.add(
            "info",
            "Samotest EROFS: pominięty",
            detail=erofs["why"] + " — bez niego nie ma na czym sprawdzić czytnika EROFS",
            values={"erofs_available": False},
        )
    elif not erofs["ok"]:
        res.add(
            "critical",
            "Samotest EROFS: rozbieżność z dump.erofs",
            detail=json.dumps(erofs["builds"], ensure_ascii=False)[:400],
            values=erofs,
        )
    else:
        built = ", ".join(
            f"{b['label']}: {b['tree_ours']} wpisów, {b['content_same']} treści, "
            f"{b['content_refused']} odmówionych"
            for b in erofs["builds"]
        )
        res.add(
            "ok",
            "Samotest EROFS: drzewo i treści zgodne z dump.erofs",
            detail=built,
            values={
                "erofs_available": True,
                "builds": len(erofs["builds"]),
                "detail": built,
            },
        )
    if not f2fs["available"]:
        res.add(
            "info",
            "Samotest F2FS: pominięty",
            detail=f2fs["why"] + " — bez niego nie ma na czym sprawdzić czytnika F2FS",
            values={"f2fs_available": False},
        )
    elif not f2fs["ok"]:
        res.add(
            "critical",
            "Samotest F2FS: rozbieżność z dump.f2fs albo ze źródłem",
            detail=json.dumps(f2fs["builds"], ensure_ascii=False)[:400],
            values=f2fs,
        )
    else:
        built = "; ".join(
            f"{b['label']}: geometria {b['geometry_agrees']}, drzewo "
            f"{b['tree_ours']}/{b['tree_source']}, inody {b['inodes_checked']} "
            f"({b['inode_fields']} pól), treści {b['content_same']} zgodnych, "
            f"hashy nazw {b['dirents_hash_checked']}/{b['dirents']}"
            for b in f2fs["builds"]
            if b.get("built")
        )
        hand = [
            f"katalog inline: {f2fs['inline_dentry'].get('names')}",
            f"plik skompresowany: odmowa {'tak' if f2fs['compressed'].get('ok') else 'NIE'}",
            f"wolumen zaszyfrowany: odmowa {'tak' if f2fs['encrypted'].get('ok') else 'NIE'}",
            f"gałąź podwójnie pośrednia: odmawa z granicą "
            f"{'tak' if f2fs['dindirect'].get('ok') else 'NIE'}",
        ]
        res.add(
            "ok" if all(
                part.get("ok")
                for part in (
                    f2fs.get("inline_dentry"),
                    f2fs.get("compressed"),
                    f2fs.get("encrypted"),
                    f2fs.get("dindirect"),
                )
                if part is not None
            ) else "critical",
            "Samotest F2FS: geometria, drzewo, inody i treści zgodne z dump.f2fs",
            detail=built + " | fixture pisane ręcznie: " + "; ".join(hand),
            values={
                "f2fs_available": True,
                "builds": len(f2fs["builds"]),
                "detail": built,
                "inline_dentry": f2fs.get("inline_dentry", {}).get("ok"),
                "compressed_refused": f2fs.get("compressed", {}).get("ok"),
                "encrypted_refused": f2fs.get("encrypted", {}).get("ok"),
                "dindirect_refused": f2fs.get("dindirect", {}).get("ok"),
            },
        )
    if not carvetest.get("available"):
        res.add(
            "info",
            "Samotest wyrzeźbienia: pominięty",
            detail=carvetest.get("why", ""),
            values={"carve_available": False},
        )
    elif not carvetest["ok"]:
        res.add(
            "critical",
            "Samotest wyrzeźbienia: plik usunięty nie wrócił bajt w bajt",
            detail=json.dumps(
                {k: carvetest[k] for k in ("content", "names") if k in carvetest},
                ensure_ascii=False,
            )[:500],
            values=carvetest,
        )
    else:
        content = carvetest["content"]
        names = carvetest["names"]
        res.add(
            "ok",
            "Samotest wyrzeźbienia: pliki usunięte wróciły bajt w bajt, "
            "pliki bez sygnatury nie zostały wyrzeźbione",
            detail=(
                f"wyrzeźbiono dokładnie {content['kinds']} (oczekiwane "
                f"{content['expected']['carved']}); odrzucono {sum(content['rejected'].values())} "
                f"sygnatur: {content['rejected']}. Plik z samą sygnaturą PNG i "
                f"śmieciami za nią nie został wyrzeźbiony, pliku bez sygnatury nie "
                f"wyrzeźbić się nie da. Nazwy: łańcuch {names['chain_names']}, "
                f"okno {names['window_names']}"
            ),
            values={
                "carve_available": True,
                "kinds": content["kinds"],
                "png_exact": content["png_recovered_exact"],
                "gzip_exact": content["gzip_recovered_exact"],
                "rejected": content["rejected"],
                "chain_names": names["chain_names"],
                "window_names": names["window_names"],
            },
        )
    if not freespace["checked"]:
        res.add(
            "info",
            "Samotest przestrzeni nieprzydzielonej: pominięty",
            detail="żaden wariant nie ma obrazu do sprawdzenia",
            values={"free_space_checked": 0},
        )
    elif not freespace["ok"]:
        res.add(
            "critical",
            "Samotest przestrzeni nieprzydzielonej: liczba wolnych bloków "
            "nie zgadza się z dumpe2fs albo z blkls",
            detail=json.dumps(freespace["variants"], ensure_ascii=False)[:500],
            values=freespace,
        )
    else:
        lines = "; ".join(
            f"{v['name']}: {v['free_blocks']} wolnych ({v['block_size']} B/blok), "
            f"{v['runs']} luk, dumpe2fs {v['dumpe2fs_free']} "
            f"{'zgodne' if v['dumpe2fs_agrees'] else 'RÓŻNI SIĘ'}, "
            f"blkls {v.get('blkls_blocks', '—')} "
            f"{'zgodne' if v.get('blkls_count_agrees') else 'RÓŻNI SIĘ'}"
            + (
                f", BLOCK_UNINIT w grupach {v['uninit_groups']} "
                f"({'cecha tak' if v['uninit_feature'] else 'cecha NIE'})"
                if v["uninit_groups"]
                else ""
            )
            + (
                f", poza setem blkls {v.get('blkls_only_ours', 0)}"
                if v.get("blkls_only_ours")
                else ""
            )
            + (
                f", nakładanie metadanych {v['overlap']} "
                f"({'na granicy zakresu' if v['overlap_interior'] == 0 else 'W ŚRODKU ZAKRESU'})"
                if v["overlap"]
                else ", bez nakładania na metadane"
            )
            for v in freespace["variants"]
        )
        res.add(
            "ok",
            f"Samotest przestrzeni nieprzydzielonej: {freespace['checked']} wariantów, "
            f"liczba wolnych bloków zgodna z dumpe2fs i z blkls",
            detail=lines,
            values={
                "variants": freespace["checked"],
                "blkls": freespace["blkls"],
                "detail": lines,
            },
        )
    if silent:
        res.add(
            "critical",
            f"{len(silent)} wariantów otworzyło się bez błędu i zwróciło pustkę: "
            f"{', '.join(silent)}",
            detail=("to jest dokładnie ta cicha awaria, którą odrzucenia z tury 8 miały "
                    "zlikwidować: brak wyjątku plus pusty katalog wyglądają w raporcie "
                    "jak pusty system plików"),
            values={"silent": silent},
        )
    # Corruption is a separate set of cases from format variants, and the one
    # invariant is shared: a damaged filesystem must never open without
    # complaint and produce nothing.  Reported on its own line because
    # "nine damaged files, all handled" reads very differently from "ten
    # formats, one refused", and folding them into one count loses that.
    if corruption.get("available"):
        corrupt_silent = corruption.get("silent", [])
        corrupt_wrong = corruption.get("wrong", [])
        severity = "critical" if corrupt_silent or corrupt_wrong else "ok"
        res.add(
            severity,
            f"Uszkodzone bajty: {corruption['cases']} przypadków, "
            f"{corruption.get('refused', 0)} odrzuconych, "
            f"{corruption.get('truncated_detected', 0)} uciętych wykrytych, "
            f"{len(corrupt_silent)} cichych",
            detail=(
                "każdy przypadek to ta sama czysta kopia zbudowana przez mke2fs, "
                "uszkodzona w jednym miejscu; wymaganie jest jedno — czytnik nigdy "
                "nie może otworzyć bez błędu i zwrócić pustki. Odrzucenie jest "
                "wymagane tylko tam, gdzie uszkodzone bajty nie da się wiarygodnie "
                "odczytać; bitmapę bloków można przyjąć, bo bitmapa naprawdę tak "
                "twierdzi i to nie jest pomysł czytnika"
            ),
            values=corruption,
        )
        for item in corruption.get("detail", []):
            res.add(
                "info",
                f"uszkodzone: {item['name']}",
                detail=(
                    f"{item.get('why', '')} — "
                    + (
                        f"odrzucone w {item.get('refused_at', '?')}: {item.get('error', '')}"
                        if item.get("refused")
                        else "przyjęte"
                    )
                    + (
                        f"; uciętych {item.get('truncated_bytes', 0)} B"
                        if item.get("truncated_bytes")
                        else ""
                    )
                ),
                values=item,
            )
    if wrong:
        res.add(
            "critical",
            f"Reader zachował się nieoczekiwanie dla {len(wrong)} wariantów: {', '.join(wrong)}",
            values={"unexpected": wrong},
        )
    if mismatched:
        res.add(
            "critical",
            f"Geometria różni się od dumpe2fs w {len(mismatched)} wariantach",
            detail="; ".join(
                f"{m['variant']}: block_size {m['ours'].get('block_size')} vs "
                f"{m['dumpe2fs'].get('block_size')}" for m in mismatched[:3]
            )[:400] or None,
            values={"mismatched": mismatched[:5]},
        )
    good = [e for e in parts if e.get("built")]
    if fixture.get("ok"):
        res.add(
            "ok",
            f"Fixture xattr: czytnik odczytał {fixture.get('name')} z "
            f"ręcznie zbudowanego bloku ({fixture.get('block_bytes')} B)",
            detail=(
                f"wartość: {fixture.get('read_back')!r} — zgodna co do bajtu; "
                f"debugfs niezależnie podaje i_file_acl = {fixture.get('i_file_acl_debugfs')}. "
                "Blok zbudowany ręcznie, bo debugfs ea_set zgłasza sukces, a "
                "i_file_acl zostaje 0."
            ),
            values={
                "host": fixture.get("host"),
                "name": fixture.get("name"),
                "value": fixture.get("value"),
                "value_bytes": fixture.get("value_bytes"),
                "block_bytes": fixture.get("block_bytes"),
                "text_property": fixture.get("text_property"),
                "i_file_acl_debugfs": fixture.get("i_file_acl_debugfs"),
            },
        )
    else:
        res.add(
            "warn",
            "Fixture xattr: nieudany",
            detail=str(fixture.get("why", ""))[:300],
            values={"host": fixture.get("host")},
        )
    res.add(
        "ok" if not (silent or wrong or mismatched) else "critical",
        f"Samotest czytnika ext4: {len(good)} wariantów, "
        f"{res.data['accepted']} przyjętych, {res.data['refused']} odrzuconych, "
        f"0 cichych pustek, geometria zgodna z dumpe2fs"
        if not (silent or wrong or mismatched)
        else f"Samotest czytnika ext4: {len(silent)} cichych, {len(wrong)} nieoczekiwanych, "
             f"{len(mismatched)} rozbieżności geometrii",
        detail="; ".join(
            f"{e['name']}: {'przyjęty' if e.get('accepted') else 'odrzucony'}"
            + (f" ({e['error'][:90]})" if e.get("error") else "")
            for e in parts
        )[:600] or None,
        values={
            "variants": len(parts),
            "accepted": res.data["accepted"],
            "refused": res.data["refused"],
            "silent": res.data["silent"],
            "unexpected": wrong,
            "geometry_mismatched": len(mismatched),
            "root": str(root),
        },
    )
    from ...core.export import to_json

    path = to_json(ctx.work("exports") / "ext4_selftest.json", res.data)
    res.export(path)
    res.note(f"{round(time.time() - started, 1)}s, katalog {root}")
    return ctx.record(res)


def _geometry_agrees(ours: dict, reference: dict) -> bool:
    """Compare our reading with e2fsprogs' on the numbers both actually state."""
    if not ours or not reference:
        return False
    pairs = (
        ("block_size", "block_size"),
        ("inode_size", "inode_size"),
        ("blocks_count", "block_count"),
        ("inodes_count", "inode_count"),
        ("free_blocks", "free_blocks"),
        ("free_inodes", "free_inodes"),
        ("desc_size", "group_descriptor_size"),
    )
    for our_key, their_key in pairs:
        mine, theirs = ours.get(our_key), reference.get(their_key)
        if theirs is None:
            continue
        if mine != theirs:
            return False
    return True


register(
    ModuleSpec(
        id="ext4_selftest",
        category="image",
        title="mod.ext4_selftest.title",
        summary="mod.ext4_selftest.summary",
        params=[
            Param(key="variants", label="Warianty", default=[v.name for v in VARIANTS], kind=LIST),
        ],
        run=run,
        needs_image=False,
    )
)
