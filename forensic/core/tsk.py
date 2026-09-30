# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Sleuth Kit as an independent second reader — the cross-check layer.

``forensic`` parses ext4 with its own reader (:mod:`forensic.core.ext4`).  A
reader that is wrong in the same way every time still looks self-consistent, so
the only way to know whether the numbers in a report are true is to ask a
different implementation.  The Sleuth Kit is that implementation: a C library
written by other people, packaged by Debian, used by courts.

This module owns everything mechanical about that conversation — locating the
binaries, running them read-only, and parsing their output — so the analysis
module only has to decide what to compare.  Nothing here is required: when the
tools are absent every entry point returns an empty result and the caller
reports a single ``warn`` finding.

Two behaviours are deliberate:

* **Read-only.** Only the ``-r``/``-f``-less read paths are ever used, the image
  is passed by path and never opened for writing, and no ``sudo`` is involved.
* **Never guess.** A parse failure yields a verdict string, not an exception, and
  a field TSK does not print is reported as absent rather than defaulted.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

from .imagemount import tool_path

# The tools this layer knows how to drive.  ``img_stat`` is read-only too and
# reports the image layout, but nothing here needs it yet.
TOOLS = ("fsstat", "fls", "istat", "icat", "ils", "img_stat")

#: Default wall-clock allowance.  ``fls -r`` walks 200k entries in ~21s on the
#: reference image; an hour is far past any sane value and only ever hit when a
#: tool is genuinely stuck.
DEFAULT_TIMEOUT = 3600

_FSSTAT_PAIR = re.compile(r"^(?P<indent>\s*)(?P<key>[A-Za-z][A-Za-z0-9 /()]*?):\s{1,}(?P<value>.*)$")
_FSSTAT_RANGE = re.compile(r"^(\d+)\s*-\s*(\d+)$")
_FSSTAT_GROUP = re.compile(r"^Group:\s*(\d+):\s*$")
# ``fls`` prints  name-type, inode-alloc, inode-type, [ '*' ], inode, (note) ':'
# with the name always in the second tab-separated column.
#
# The two allocation-looking characters mean different things and conflating
# them is the trap here.  ``inode_alloc`` at position 1 is the *inode bitmap*
# state (``/`` allocated, ``*`` free, blank neither); the ``*`` after it marks a
# *directory entry* that is no longer linked, which is what ``fls -d`` lists.
# On the reference image every one of 202 593 entries still has an allocated
# inode while 51 924 of the names are unlinked — so a parser that reads the
# first ``*`` it sees reports a filesystem with nothing allocated at all.
#
# The first letter is the type TSK inferred from the name, the third is the
# type from the inode mode, and the two disagree exactly when a directory is
# reported under a regular-file name.  Without ``-l`` there are two columns;
# ``-l`` appends atime, mtime, ctime, crtime, size, uid, gid.
_FLS_HEAD = re.compile(
    r"^(?P<indent>[+ ]*)(?P<type>[drbplsV-])(?P<inode_alloc>[/ *])(?P<meta>[a-zA-Z-])?"
    r"\s+(?P<link_deleted>\*)?\s*(?P<inode>\d+)(?:\((?P<note>[^)]*)\))?:\s*$"
)

#: ``fls`` type letters mapped to a stable name.  TSK uses r/d/b for regular,
#: directory and block device, p for FIFO, l for symlink, s for socket, ``-``
#: when the type cannot be determined (the auxiliary tables SQLite's FTS module
#: creates, with names full of non-printable bytes), and ``V`` for the virtual
#: ``$OrphanFiles`` container TSK invents to hold unallocated inodes.  The last
#: one is not on the disk and must never be counted as an entry.
FLS_TYPES = {
    "r": "regular",
    "d": "directory",
    "b": "block",
    "p": "fifo",
    "l": "symlink",
    "s": "socket",
    "-": "unknown",
    "V": "virtual",
}

_ISTAT_INODE = re.compile(r"^inode:\s*(\d+)")
_ISTAT_FIELD = re.compile(r"^(size|num of links|uid / gid|Group|Generation Id):\s*(.*)$")
_ISTAT_TIME = re.compile(r"^(Accessed|File Modified|Inode Modified|File Created):\s*(.*)$")
_ISTAT_BLOCK = re.compile(
    r"^(?P<label>Direct Blocks|Extent Blocks|Indirect Blocks|"
    r"Double Indirect Blocks|Triple Indirect Blocks):\s*(?P<rest>.*)$"
)
_ISTAT_NUMBER = re.compile(r"^\d+(\s+\d+)*$")


def available() -> dict[str, str]:
    """Map every known tool to its path, or to an empty string when absent."""
    return {name: tool_path(name) or "" for name in TOOLS}


def present() -> list[str]:
    """Names of the tools that are actually installed."""
    return [name for name, path in available().items() if path]


def required_tools() -> tuple[str, ...]:
    """The tools without which a cross-check is impossible."""
    return ("fsstat", "fls", "icat")


def version() -> str:
    """Version string of the installed Sleuth Kit, or an empty string."""
    path = tool_path("fls")
    if not path:
        return ""
    proc = subprocess.run([path, "-V"], capture_output=True, text=True, timeout=30, check=False)
    text = (proc.stdout or "") + (proc.stderr or "")
    for line in text.splitlines():
        if "The Sleuth Kit" in line:
            return line.strip()
    return text.strip().splitlines()[0] if text.strip() else ""


def run_tool(
    tool: str,
    args: list[str],
    timeout: int = DEFAULT_TIMEOUT,
) -> tuple[int, str, str]:
    """Run a Sleuth Kit tool and return ``(returncode, stdout, stderr)``.

    A missing binary is reported as return code 127 with the reason in stderr
    rather than raising, so one absent tool degrades the report instead of the
    module.
    """
    path = tool_path(tool)
    if not path:
        return 127, "", f"{tool}: nie zainstalowany"
    try:
        proc = subprocess.run(
            [path, *args],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"{tool}: przekroczono limit {timeout}s"
    except Exception as exc:  # noqa: BLE001 - a broken pipe must not kill a report
        return 126, "", f"{tool}: {exc}"
    return proc.returncode, _decode(proc.stdout), _decode(proc.stderr)


def _decode(raw: bytes) -> str:
    """Decode tool output without ever raising.

    ``fls`` prints raw file names, and a real Android volume contains plenty of
    byte sequences that are not valid UTF-8 — the SQLite FTS auxiliary tables
    alone contribute dozens.  ``surrogateescape`` keeps such a name
    byte-identical on the way back out, which ``replace`` would silently corrupt
    into U+FFFD and make two different names compare equal.
    """
    return raw.decode("utf-8", "surrogateescape")


def guid_display(uuid_hex: str) -> str:
    """Re-render an ext4 volume UUID the way The Sleuth Kit prints it.

    The superblock holds 16 raw bytes.  TSK displays them in Windows GUID
    mixed-endian order — the four 32-bit groups in reverse sequence, each group
    byte-swapped — so ``fsstat`` and our own ``image_info`` report the *same*
    volume under two different strings.  A report that prints only one of them
    looks wrong to whoever runs the other tool, so both are shown.
    """
    raw = bytes.fromhex(uuid_hex)
    if len(raw) != 16:
        return ""
    out = b""
    for index in range(3, -1, -1):
        out += raw[index * 4 : (index + 1) * 4][::-1]
    return out.hex()


def _text_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip()]


def parse_fsstat(text: str) -> dict:
    """Parse ``fsstat`` output into a flat dict of labelled values.

    The per-block-group section repeats ``Inode Range:`` and ``Block Range:``
    once for each of 206 groups, and a naive parser lets group 205 overwrite the
    volume totals.  Indentation is therefore part of the grammar: unindented
    labels are volume-level and the first occurrence wins, while the indented
    ones under a ``Group:`` header are collected into ``groups``.

    Ranges become ``*_low`` / ``*_high`` members so the caller can compare them
    with our own counts without touching the text again.
    """
    out: dict = {"raw": text, "groups": []}
    group: dict | None = None
    in_group_section = False
    for line in text.splitlines():
        if not line.strip() or set(line.strip()) == {"-"}:
            continue
        stripped = line.strip()
        if stripped.isupper() and ":" not in stripped and len(stripped) < 40:
            in_group_section = stripped.startswith("BLOCK GROUP")
            group = None
            continue
        head = _FSSTAT_GROUP.match(stripped)
        if head:
            group = {"group": int(head.group(1))}
            out["groups"].append(group)
            continue
        match = _FSSTAT_PAIR.match(line.rstrip())
        if not match:
            continue
        key, value = match.group("key").strip(), match.group("value").strip()
        slug = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
        if not slug:
            continue
        target = group if (group is not None and match.group("indent")) else out
        if target is out and slug in out:
            continue  # volume-level label already seen; a group must not win
        if value.isdigit():
            target[slug] = int(value)
            target[f"{slug}_int"] = int(value)
            continue
        rng = _FSSTAT_RANGE.match(value)
        if rng:
            target[f"{slug}_low"] = int(rng.group(1))
            target[f"{slug}_high"] = int(rng.group(2))
            target[slug] = value
            continue
        target[slug] = value
    out["group_count"] = len(out["groups"])
    out["_group_section"] = in_group_section
    return out


@dataclass
class FlsEntry:
    """One line of ``fls`` output."""

    inode: int
    name: str
    type: str
    meta: str
    inode_alloc: str
    link_deleted: bool
    note: str = ""
    size: int | None = None
    uid: int | None = None
    gid: int | None = None
    mtime: str = ""
    atime: str = ""
    ctime: str = ""
    crtime: str = ""

    @property
    def allocated(self) -> bool:
        """True when the inode itself is marked allocated in the bitmap."""
        return self.inode_alloc == "/"

    @property
    def real(self) -> bool:
        """False for TSK's virtual ``$OrphanFiles`` container, which is not on disk."""
        return self.type != "virtual"

    def as_dict(self) -> dict:
        return {
            "inode": self.inode,
            "name": self.name,
            "type": self.type,
            "meta": self.meta,
            "inode_alloc": self.inode_alloc,
            "allocated": self.allocated,
            "real": self.real,
            "link_deleted": self.link_deleted,
            "note": self.note,
            "size": self.size,
            "uid": self.uid,
            "gid": self.gid,
            "mtime": self.mtime,
            "atime": self.atime,
            "ctime": self.ctime,
            "crtime": self.crtime,
        }


def parse_fls(text: str) -> list[FlsEntry]:
    """Parse ``fls`` output.

    The name is always the second tab-separated column.  With ``-l`` seven more
    follow (atime, mtime, ctime, crtime, size, uid, gid); without ``-l`` they
    stay ``None`` and the caller must not treat them as zero.
    """
    out: list[FlsEntry] = []
    for line in text.splitlines():
        if "\t" not in line:
            continue
        columns = line.split("\t")
        match = _FLS_HEAD.match(columns[0].rstrip())
        if not match:
            continue
        entry = FlsEntry(
            inode=int(match.group("inode")),
            name=columns[1] if len(columns) > 1 else "",
            type=FLS_TYPES.get(match.group("type"), match.group("type")),
            meta=FLS_TYPES.get(match.group("meta") or "", match.group("meta") or ""),
            inode_alloc=match.group("inode_alloc"),
            link_deleted=bool(match.group("link_deleted")),
            note=match.group("note") or "",
        )
        if len(columns) >= 9:
            entry.atime, entry.mtime = columns[2], columns[3]
            entry.ctime, entry.crtime = columns[4], columns[5]
            entry.size = int(columns[6]) if columns[6].lstrip("-").isdigit() else None
            entry.uid = int(columns[7]) if columns[7].lstrip("-").isdigit() else None
            entry.gid = int(columns[8]) if columns[8].lstrip("-").isdigit() else None
        out.append(entry)
    return out


def parse_istat(text: str) -> dict:
    """Parse ``istat`` output into inode fields.

    Two details matter for a cross-check.  Times are kept as the strings TSK
    printed — it renders them in the image's own timezone and marks the zero
    time as ``0000-00-00``, so converting here would destroy what is being
    compared.  And the block list continues over several lines of eight numbers
    each, so it is accumulated rather than read from one line.
    """
    out: dict = {"raw": text}
    block_label: str | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            block_label = None
            continue
        match = _ISTAT_INODE.match(stripped)
        if match:
            out["inode"] = int(match.group(1))
            block_label = None
            continue
        if stripped == "Allocated":
            out["allocated"] = True
            block_label = None
            continue
        if stripped == "Unallocated":
            out["allocated"] = False
            block_label = None
            continue
        if block_label and _ISTAT_NUMBER.match(stripped):
            key = _slug_time(block_label) + "_blocks"
            out.setdefault(key, []).extend(int(n) for n in stripped.split())
            continue
        match = _ISTAT_FIELD.match(stripped)
        if match:
            key, value = match.group(1), match.group(2).strip()
            slug = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
            out[slug] = value
            if value.isdigit():
                out[f"{slug}_int"] = int(value)
            block_label = None
            continue
        match = _ISTAT_TIME.match(stripped)
        if match:
            out[_slug_time(match.group(1))] = match.group(2).strip()
            block_label = None
            continue
        match = _ISTAT_BLOCK.match(stripped)
        if match:
            block_label = _slug_time(match.group("label"))
            out.setdefault(block_label + "_blocks", [])
            if match.group("rest").strip():
                out[block_label + "_blocks"].extend(
                    int(n) for n in match.group("rest").split() if n.isdigit()
                )
    if out.get("extent_blocks_blocks"):
        out["extent_mapped"] = True
    out["block_total"] = sum(
        len(value)
        for key, value in out.items()
        if key.endswith("_blocks") and isinstance(value, list)
    )
    return out


def _slug_time(label: str) -> str:
    return {"Accessed": "atime", "File Modified": "mtime", "Inode Modified": "ctime", "File Created": "crtime"}.get(
        label, re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
    )


def parse_ils(text: str) -> dict:
    """Summarise ``ils`` output: how many inodes the file system has unallocated.

    Column positions come from the ``st_*`` header row rather than from fixed
    indices — the header has eleven members and getting the count wrong turns
    ``st_nlink`` into ``st_size`` and reports four bytes of deleted data on an
    image holding 752 047 deleted inodes.

    Only counts are kept.  The full listing runs to hundreds of thousands of
    rows, and the question this answers is "how much am I not seeing", not "what
    exactly".
    """
    rows = 0
    modes: dict[str, int] = {}
    with_data = 0
    total_size = 0
    max_size = 0
    columns: list[str] = []
    for line in text.splitlines():
        fields = line.split("|")
        if fields and fields[0] == "st_ino":
            columns = fields
            continue
        if len(fields) < 3 or not fields[0].isdigit():
            continue
        rows += 1
        if not columns:
            columns = [
                "st_ino", "st_alloc", "st_uid", "st_gid", "st_mtime", "st_atime",
                "st_ctime", "st_crtime", "st_mode", "st_nlink", "st_size",
            ]

        def value(name: str) -> str:
            index = columns.index(name) if name in columns else -1
            return fields[index] if 0 <= index < len(fields) else ""

        mode = value("st_mode")
        modes[mode] = modes.get(mode, 0) + 1
        size_text = value("st_size")
        if size_text.isdigit() and int(size_text) > 0:
            size = int(size_text)
            with_data += 1
            total_size += size
            max_size = max(max_size, size)
    return {
        "unallocated_inodes": rows,
        "modes": dict(sorted(modes.items(), key=lambda kv: -kv[1])),
        "with_data": with_data,
        "total_size": total_size,
        "max_size": max_size,
    }


def icat(image: str, inode: int, timeout: int = DEFAULT_TIMEOUT) -> tuple[bytes, str]:
    """Read one inode's content through TSK.  Returns ``(bytes, error)``."""
    import tempfile
    from pathlib import Path

    path = tool_path("icat")
    if not path:
        return b"", "icat: nie zainstalowany"
    with tempfile.TemporaryDirectory(prefix="forensic-icat-") as tmp:
        out = Path(tmp) / "content"
        try:
            with out.open("wb") as handle:
                proc = subprocess.run(
                    [path, image, str(inode)], stdout=handle, stderr=subprocess.PIPE, timeout=timeout, check=False
                )
        except subprocess.TimeoutExpired:
            return b"", f"icat {inode}: przekroczono limit {timeout}s"
        except Exception as exc:  # noqa: BLE001
            return b"", f"icat {inode}: {exc}"
        if proc.returncode != 0:
            return b"", (proc.stderr or b"").decode("utf-8", "replace").strip() or f"exit {proc.returncode}"
        try:
            return out.read_bytes(), ""
        except OSError as exc:
            return b"", f"icat {inode}: {exc}"


@dataclass
class ToolRun:
    """One executed tool call, kept for the export so a report can be re-read."""

    tool: str
    args: list[str]
    returncode: int
    seconds: float
    stdout_lines: int = 0
    stderr: str = ""
    values: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "command": " ".join([self.tool, *self.args]),
            "returncode": self.returncode,
            "seconds": round(self.seconds, 2),
            "stdout_lines": self.stdout_lines,
            "stderr": self.stderr,
            "values": self.values,
        }
