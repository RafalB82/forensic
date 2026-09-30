# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Read-only job plans for the external EDL toolchain.

``edlclient`` (B. Kerler's) is a *dependency*, not part of
this repository: it is never imported and no line of it is copied here.  This
module only does three things:

1. reads ``rawprogram0.xml`` — the partition geometry Qualcomm firmware ships —
   so that sector arithmetic is done from a document instead of from memory;
2. builds the argument vector for the external ``edl.py``;
3. runs that vector as a **separate process** in read mode, or, by default,
   does not run it at all and only reports what *would* be executed.

There is deliberately no verb here that writes to the phone.  Writing, erasing
and patching are not representable, so a mistake in the parameters cannot become
a destructive action.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import Iterable

from ..core.xmlsafe import safe_fromstring

from ..core import i18n

KIND_PARTITION = "partition"
KIND_SECTORS = "sectors"
KIND_GPT = "gpt"
KINDS = (KIND_PARTITION, KIND_SECTORS, KIND_GPT)

DEFAULT_EDL_SCRIPT = "edl.py"
DEFAULT_MAXPAYLOAD = "0x100000"
DEFAULT_SECTOR_SIZE = 512
SECTOR_PLACEHOLDER = re.compile(r"[^0-9]")


@dataclass
class Partition:
    """One ``<program>`` entry of ``rawprogram0.xml``."""

    label: str
    start_sector: int | None
    sectors: int
    sector_size: int
    filename: str = ""
    lun: int = 0
    start_byte: int | None = None
    note: str = ""

    @property
    def size_bytes(self) -> int:
        return self.sectors * self.sector_size

    @property
    def resolvable(self) -> bool:
        return self.start_sector is not None and self.start_sector >= 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "start_sector": self.start_sector,
            "sectors": self.sectors,
            "sector_size": self.sector_size,
            "size_bytes": self.size_bytes,
            "size_human": f"{self.size_bytes / 2**20:,.1f} MiB",
            "lun": self.lun,
            "filename": self.filename,
            "start_byte": self.start_byte,
            "note": self.note,
        }


def parse_rawprogram(path: str | Path) -> dict[str, Any]:
    """Partition geometry from a Qualcomm ``rawprogram*.xml``."""
    target = Path(path)
    out: dict[str, Any] = {"file": str(target), "exists": target.exists(), "partitions": []}
    if not target.exists():
        out["error"] = "brak pliku"
        return out
    try:
        root = safe_fromstring(target.read_text(encoding="utf-8", errors="replace"))
    except ET.ParseError as exc:
        out["error"] = f"XML: {exc}"
        return out
    entries: list[Partition] = []
    for node in root.iter("program"):
        sector_size = int(node.get("SECTOR_SIZE_IN_BYTES") or DEFAULT_SECTOR_SIZE)
        start = node.get("start_sector") or "0"
        note = ""
        if SECTOR_PLACEHOLDER.search(start):
            start_sector: int | None = None
            note = f"start_sector={start} (wyrażenie z GPT — nie rozwiązywane offline)"
        else:
            start_sector = int(start)
        start_byte_hex = node.get("start_byte_hex") or ""
        try:
            start_byte = int(start_byte_hex, 16) if start_byte_hex else None
        except ValueError:
            start_byte = None
            note = f"{note} start_byte_hex={start_byte_hex} (nie rozwiązywane offline)".strip()
        entries.append(
            Partition(
                label=node.get("label") or node.get("filename") or "?",
                start_sector=start_sector,
                sectors=int(node.get("num_partition_sectors") or 0),
                sector_size=sector_size,
                filename=node.get("filename") or "",
                lun=int(node.get("physical_partition_number") or 0),
                start_byte=start_byte,
                note=note,
            )
        )
    entries.sort(key=lambda item: (item.start_sector is None, item.start_sector or 0))
    out["partitions"] = entries
    out["count"] = len(entries)
    out["total_bytes"] = sum(item.size_bytes for item in entries)
    out["labels"] = [item.label for item in entries]
    return out


def by_label(rawprogram: dict[str, Any], label: str) -> Partition | None:
    for item in rawprogram.get("partitions", []):
        if item.label == label:
            return item
    return None


@dataclass
class EdlJob:
    """A read job, fully described before anything is executed."""

    kind: str = KIND_PARTITION
    partition: str = ""
    start_sector: int = 0
    sectors: int = 0
    sector_size: int = DEFAULT_SECTOR_SIZE
    output: str = ""
    lun: int = 0
    loader: str = ""
    maxpayload: str = DEFAULT_MAXPAYLOAD
    memory: str = ""
    serial: str = ""
    portname: str = ""
    label: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.label:
            self.label = f"{self.kind}_{self.partition or self.start_sector}"

    @property
    def planned_bytes(self) -> int:
        if self.kind == KIND_SECTORS:
            return self.sectors * self.sector_size
        if self.kind == KIND_PARTITION:
            return self.sectors * self.sector_size
        return 0

    def command(self, python: str, edl_dir: str | Path, script: str = DEFAULT_EDL_SCRIPT) -> list[str]:
        """The exact argument vector handed to the external tool."""
        argv = [python, str(Path(edl_dir) / script)]
        if self.kind == KIND_GPT:
            argv += ["printgpt", "--memory=" + (self.memory or "ufs"), f"--lun={self.lun}"]
        elif self.kind == KIND_SECTORS:
            argv += [
                "rs",
                str(self.start_sector),
                str(self.sectors),
                str(self.output),
                "--memory=" + (self.memory or "ufs"),
                f"--lun={self.lun}",
            ]
        else:
            argv += [
                "r",
                self.partition,
                str(self.output),
                "--memory=" + (self.memory or "ufs"),
                f"--lun={self.lun}",
            ]
        if self.loader:
            argv.append(f"--loader={self.loader}")
        argv.append(f"--maxpayload={self.maxpayload}")
        if self.serial:
            argv.append(f"--serial={self.serial}")
        if self.portname:
            argv.append(f"--portname={self.portname}")
        return argv

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "label": self.label,
            "partition": self.partition,
            "start_sector": self.start_sector,
            "sectors": self.sectors,
            "sector_size": self.sector_size,
            "planned_bytes": self.planned_bytes,
            "output": self.output,
            "lun": self.lun,
            "loader": self.loader,
            "maxpayload": self.maxpayload,
            "memory": self.memory,
            "read_only": True,
            "extra": self.extra,
        }


def build_job(
    kind: str,
    partition: str = "",
    output_dir: str | Path = ".",
    rawprogram: dict[str, Any] | None = None,
    start_sector: int = 0,
    sectors: int = 0,
    sector_size: int = DEFAULT_SECTOR_SIZE,
    lun: int = 0,
    loader: str = "",
    maxpayload: str = DEFAULT_MAXPAYLOAD,
    memory: str = "",
    serial: str = "",
    portname: str = "",
    filename: str = "",
) -> EdlJob:
    """Assemble a job; partition geometry is taken from the rawprogram file."""
    if kind not in KINDS:
        raise ValueError(f"rodzaj zadania musi być jednym z {KINDS}")
    geometry: Partition | None = None
    if partition and rawprogram:
        geometry = by_label(rawprogram, partition)
    if geometry is not None and kind == KIND_PARTITION:
        start_sector = geometry.start_sector or 0
        sectors = sectors or geometry.sectors
        sector_size = geometry.sector_size
        lun = geometry.lun if lun is None else lun
    name = filename or (f"{partition}.img" if partition else f"sectors_{start_sector}.img")
    return EdlJob(
        kind=kind,
        partition=partition,
        start_sector=int(start_sector),
        sectors=int(sectors),
        sector_size=int(sector_size),
        output=str(Path(output_dir).expanduser() / name),
        lun=int(lun or 0),
        loader=loader,
        maxpayload=maxpayload,
        memory=memory,
        serial=serial,
        portname=portname,
        label=partition or f"sectors@{start_sector}",
    )


def run_job(
    job: EdlJob,
    python: str,
    edl_dir: str | Path,
    log_path: str | Path | None = None,
    timeout: int = 7200,
    dry_run: bool = True,
    confirm: bool = False,
    script: str = DEFAULT_EDL_SCRIPT,
) -> dict[str, Any]:
    """Execute a read job as a subprocess and describe what happened.

    ``dry_run`` is the default and the only mode reachable without an explicit
    ``confirm``: the tool then writes the plan and the argument vector and stops.
    """
    argv = job.command(python, edl_dir, script)
    record: dict[str, Any] = {
        "job": job.as_dict(),
        "command": argv,
        "python": python,
        "edl_dir": str(edl_dir),
        "dry_run": bool(dry_run),
        "executed": False,
        "returncode": None,
        "seconds": 0.0,
        "output": job.output,
        "log": str(log_path) if log_path else "",
    }
    started = time.time()
    record["source"] = "edl"
    if dry_run or not confirm:
        record["note"] = (
            "tryb symulacji: polecenie zapisano, nic nie wykonano"
            if dry_run
            else "wykonanie wymaga potwierdzenia (confirm)"
        )
        record["seconds"] = round(time.time() - started, 3)
        # The dry run is the default path, so it is the one that most needs a
        # status on the record: "we have the plan and no data" has to be
        # readable without knowing what a dry run is.
        record["status"] = STATUS_PLANNED
        record["status_meaning"] = STATUS_MEANING[STATUS_PLANNED]
        return record
    out_path = Path(job.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(log_path, "w", encoding="utf-8") as log:
            process = subprocess.Popen(  # noqa: S603 - argv is built here, never a shell string
                argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
            )
            assert process.stdout is not None
            tail: list[str] = []
            for line in process.stdout:
                log.write(line)
                tail.append(line)
                del tail[:-200]
            process.wait(timeout=timeout)
        record["executed"] = True
        record["returncode"] = process.returncode
        record["log_tail"] = "".join(tail)[-4000:]
    except FileNotFoundError as exc:
        record["error"] = str(exc)
    except subprocess.TimeoutExpired:
        record["error"] = f"timeout po {timeout}s"
        record["returncode"] = -1
    record["seconds"] = round(time.time() - started, 2)
    size: int | None = None
    if out_path.exists():
        size = out_path.stat().st_size
        result: dict[str, Any] = {"path": str(out_path), "size": size, "sha256": _sha256(out_path)}
        # Always present, never absent: a missing key cannot be told apart from
        # "matches" or from "never checked", and a forensic record that cannot
        # be read unambiguously is not a record.
        result["size_matches_plan"] = (
            bool(size == job.planned_bytes) if job.planned_bytes else None
        )
        record["result"] = result
    record["status"] = acquisition_status(
        record["executed"], record.get("returncode"), size, job.planned_bytes
    )
    record["status_meaning"] = STATUS_MEANING.get(record["status"], "")
    return record


def _sha256(path: Path, limit: int | None = None) -> str:
    digest = hashlib.sha256()
    read = 0
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            read += len(chunk)
            if limit and read >= limit:
                break
    return digest.hexdigest()


#: Acquisition outcome, derived rather than guessed.  Four states, no more,
#: because the distinction that matters in front of a court is "we have it" vs
#: "we have part of it" — and everything else is detail of how it went.
STATUS_PLANNED = "planned"
STATUS_COMPLETED = "completed"
STATUS_PARTIAL = "partial"
STATUS_FAILED = "failed"
STATUSES = (STATUS_PLANNED, STATUS_COMPLETED, STATUS_PARTIAL, STATUS_FAILED)

STATUS_MEANING = {
    STATUS_PLANNED: "zapisano plan, nic nie wykonano",
    STATUS_COMPLETED: "plik powstał, kod wyjścia 0, rozmiar zgodny z planem",
    STATUS_PARTIAL: "plik powstał, ale kod wyjścia lub rozmiar mówi, że to niepełne",
    STATUS_FAILED: "nie powstał żaden plik",
}


def acquisition_status(
    executed: bool,
    returncode: int | None,
    size: int | None,
    planned_bytes: int = 0,
) -> str:
    """Classify an acquisition from what actually happened on disk.

    This is a pure function on purpose.  The EDL read cannot be exercised by the
    regression — it needs a phone in EDL mode — but the *classification* can be,
    and it is the classification that decides whether a report may say it holds
    the whole partition.  Getting it right is worth more than the subprocess.

    The three facts and why each is needed:

    * ``executed`` — a dry run has touched nothing, and saying "completed"
      because no error was raised would be the worst possible lie.
    * ``returncode`` — a read can die at 99% and still leave a file that looks
      complete.  Size alone will not catch it, because a partial read of a
      partition is not required to be short.
    * ``size`` vs ``planned_bytes`` — catches the ordinary truncation.  A planned
      size of zero means the plan did not state one, and then size cannot
      testify either way; the return code decides.

    A file that exists with a zero return code but the wrong size is ``partial``,
    not ``completed``: the evidence is there and it is incomplete, and both facts
    belong in the report.
    """
    if not executed:
        return STATUS_PLANNED
    if size is None:
        return STATUS_FAILED
    if returncode not in (0, None):
        return STATUS_PARTIAL
    if planned_bytes and size != planned_bytes:
        return STATUS_PARTIAL
    return STATUS_COMPLETED


def hashes_manifest(entries: Iterable[dict[str, Any]]) -> str:
    """Render the integrity manifest of an acquisition as CSV.

    Columns are ``name,source,sha256,bytes,recorded_utc``.  ``source`` is here
    from the start rather than added when a second acquisition path appears:
    a future unallocated-block dump taken with The Sleuth Kit's ``blkls`` lands
    in the same directory, and a manifest that cannot say which tool produced
    which file is a manifest that has to be rewritten at the worst moment.

    The manifest carries no row for itself, for the same reason androidqf does
    not: a file cannot contain its own hash.
    """
    rows = ["name,source,sha256,bytes,recorded_utc"]
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for entry in entries:
        digest = entry.get("sha256") or ""
        if not digest:
            continue
        rows.append(
            "{},{},{},{},{}".format(
                _csv_field(str(entry.get("name", ""))),
                _csv_field(str(entry.get("source", ""))),
                str(digest),
                int(entry.get("bytes", 0) or 0),
                str(entry.get("recorded_utc") or stamp),
            )
        )
    return "\n".join(rows) + "\n"


def _csv_field(value: str) -> str:
    """Quote a CSV field only when it needs it; paths rarely do."""
    if any(ch in value for ch in ',"\n\r'):
        return '"' + value.replace('"', '""') + '"'
    return value


def write_acquisition(
    acquire_dir: str | Path,
    producer: str,
    jobs: list[dict[str, Any]],
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Write ``acquisition.json`` and ``hashes.csv`` and return both paths.

    ``acquisition.json`` is the source of truth for *outcome*; the per-job file
    (``edl_<label>.json``) stays the record of the plan and the argument vector.
    One file answers "do we have it", the other "what exactly was asked for".

    The producer string is written into the file because the name deliberately
    matches the one androidqf uses.  If an androidqf archive and a forensic
    acquisition ever share a directory, this line is what tells them apart.
    """
    from uuid import uuid4

    target = Path(acquire_dir)
    target.mkdir(parents=True, exist_ok=True)
    status = STATUS_COMPLETED
    if any(job.get("status") == STATUS_FAILED for job in jobs):
        status = STATUS_FAILED
    elif any(job.get("status") == STATUS_PARTIAL for job in jobs):
        status = STATUS_PARTIAL
    elif all(job.get("status") == STATUS_PLANNED for job in jobs) and jobs:
        status = STATUS_PLANNED
    manifest_entries = [
        {
            "name": str(job.get("result", {}).get("path", "")),
            "source": str(job.get("source", "edl")),
            "sha256": str(job.get("result", {}).get("sha256", "")),
            "bytes": int(job.get("result", {}).get("size", 0) or 0),
        }
        for job in jobs
        if job.get("result", {}).get("sha256")
    ]
    document = {
        "producer": producer,
        "acquisition_id": str(uuid4()),
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": status,
        "status_meaning": STATUS_MEANING.get(status, ""),
        "manifest": "hashes.csv",
        "artefacts": len(manifest_entries),
        "jobs": jobs,
        "context": context or {},
    }
    json_path = write_record(document, target / "acquisition.json")
    csv_path = target / "hashes.csv"
    csv_path.write_text(hashes_manifest(manifest_entries), encoding="utf-8")
    csv_path.chmod(0o600)
    return {"acquisition": json_path, "hashes": csv_path, "status": status}


def write_record(record: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(record, indent=2, ensure_ascii=False, default=str), encoding="utf-8"
    )
    target.chmod(0o600)
    return target


def python_for(edl_dir: str | Path) -> str:
    """Prefer the toolchain's own venv, fall back to the current interpreter."""
    venv = Path(edl_dir) / "venv" / "bin" / "python"
    if venv.exists():
        return str(venv)
    import sys

    return sys.executable


def loader_candidates(edl_dir: str | Path) -> list[str]:
    """Loader files the toolchain can pick up, listed for the operator to choose."""
    loaders = Path(edl_dir) / "Loaders"
    if not loaders.is_dir():
        return []
    return sorted(str(item) for item in loaders.iterdir() if item.is_file())


def partition_summary(rawprogram: dict[str, Any], labels: Iterable[str] = ()) -> list[dict[str, Any]]:
    wanted = set(labels)
    out: list[dict[str, Any]] = []
    for item in rawprogram.get("partitions", []):
        if wanted and item.label not in wanted:
            continue
        out.append(item.as_dict())
    return out


def check_edl_dir(edl_dir: str | Path) -> dict[str, Any]:
    """Presence of the external tool and of the local ``read_sectors`` fix."""
    from .preflight import edl_info

    return edl_info(str(edl_dir))


def translation(key: str, **kwargs: object) -> str:
    return i18n.t(key, **kwargs)
