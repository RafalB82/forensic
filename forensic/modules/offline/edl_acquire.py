# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Acquisition through the external EDL toolchain: plan only, by default.

The device is reached through a program this repository does not contain, so the
module's job is to make the *plan* inspectable: the partition geometry taken from
the firmware's ``rawprogram0.xml``, the exact command line, and the conditions
under which it would be executed.  Nothing is sent to a phone unless the operator
both switches off the dry run and confirms, and the tool offers no verb that
could write.
"""

from __future__ import annotations

import time
from pathlib import Path

from ...acquisition import edl_job
from ...core.export import human_bytes
from ...core.reporting import VERSION
from ...core.findings import ModuleResult
from ...core.session import Ctx
from ..registry import BOOL, CHOICE, INT, ModuleSpec, Param, register

INTERESTING = ("userdata", "system", "persist", "misc", "keystore")

#: Written into ``acquisition.json``.  The file name deliberately matches the one
#: androidqf uses, so if an androidqf archive and a forensic acquisition ever
#: share a directory this line is what tells them apart.
PRODUCER = f"forensic/{VERSION}"


def doc_artefacts(hashes: Path) -> int:
    """Rows in the manifest, not counting its header."""
    try:
        return sum(1 for line in hashes.read_text(encoding="utf-8").splitlines()[1:] if line)
    except OSError:
        return 0


def run(ctx: Ctx, params: dict) -> ModuleResult:
    res = ctx.new_result("edl_acquire")
    edl_dir = str(params.get("edl_dir") or ctx.config.edl_dir)
    kind = str(params.get("kind") or "partition")
    partition = str(params.get("partition") or "userdata")
    out_dir = str(params.get("dest") or ctx.workdir / "acquire")
    rawprogram_path = str(
        params.get("rawprogram") or Path(edl_dir) / "rawprogram0.xml"
    )
    dry_run = bool(params.get("dry_run", True))
    confirm = bool(params.get("confirm", False))
    sectors = int(params.get("sectors") or 0)
    start_sector = int(params.get("start_sector") or 0)
    loader = str(params.get("loader") or "")
    started = time.time()
    edl = edl_job.check_edl_dir(edl_dir)
    res.add(
        "ok" if edl.get("exists") else "critical",
        f"Zależność EDL: {edl_dir}",
        detail=(
            f"{edl.get('name', 'edlclient')} {edl.get('version', '?')}, "
            f"łata streaming.read_sectors: {'obecna' if edl.get('patch_applied') else 'BRAK'}, "
            f"venv: {'gotowy' if edl.get('venv_deps') else 'niesprawdzony/niekompletny'}"
        ),
        values={
            "dir": edl_dir,
            "exists": edl.get("exists"),
            "version": edl.get("version"),
            "patch_applied": edl.get("patch_applied"),
            "patch_details": edl.get("patch_details"),
            "venv_python": edl.get("venv_python"),
            "venv_deps": edl.get("venv_deps"),
            "tools": edl.get("tools", {}),
        },
    )
    if edl.get("exists") and edl.get("patch_applied") is False:
        res.add(
            "warn",
            "Brak łaty streaming.read_sectors w lokalnym edl",
            detail=(
                "bez niej odczyty regionów niewyrównanych do strony są błędne — odcinki userdata "
                "byłyby skierowane o niewłaściwe sektory"
            ),
            values={"streaming_py": edl.get("streaming_py"), "fix": "install.sh --apply-edl-patch"},
        )
    raw = edl_job.parse_rawprogram(rawprogram_path)
    if raw.get("error"):
        res.add(
            "critical",
            f"Nie odczytano {rawprogram_path}: {raw['error']}",
            detail="geometria partycji jest nieznana — zadania z planu są niepełne",
            values=raw,
        )
        return ctx.record(res)
    res.add(
        "ok",
        f"rawprogram0.xml: {raw['count']} wpisów, {human_bytes(raw['total_bytes'])}",
        detail=(
            "sektory i rozmiary partycji z pliku firmware; wpisy z wyrażeniem GPT są "
            "oznaczone i nie rozwiązywane offline"
        ),
        values={
            "file": raw["file"],
            "partitions": raw["count"],
            "total_bytes": raw["total_bytes"],
            "total_human": human_bytes(raw["total_bytes"]),
            "unresolved": [
                item.as_dict() for item in raw["partitions"] if not item.resolvable
            ],
        },
    )
    for row in edl_job.partition_summary(raw, INTERESTING):
        res.add(
            "info",
            f"{row['label']}: {row['size_human']} od sektora {row['start_sector']}",
            detail=(
                f"{row['sectors']} × {row['sector_size']} B, LUN {row['lun']}, "
                f"plik {row['filename'] or '?'}{'; ' + row['note'] if row['note'] else ''}"
            ),
            values=row,
        )
    try:
        job = edl_job.build_job(
            kind,
            partition=partition,
            output_dir=out_dir,
            rawprogram=raw,
            start_sector=start_sector,
            sectors=sectors,
            loader=loader,
        )
    except ValueError as exc:
        res.add("critical", str(exc))
        return ctx.record(res)
    python = edl_job.python_for(edl_dir)
    log_path = Path(ctx.workdir) / "acquire" / f"edl_{job.label}.log"
    record = edl_job.run_job(
        job,
        python,
        edl_dir,
        log_path=log_path,
        dry_run=dry_run,
        confirm=confirm,
    )
    res.add(
        "info",
        f"Zadanie: {job.kind} {job.label} → {Path(job.output).name}",
        detail=record.get("note") or "wykonano",
        values={
            "job": job.as_dict(),
            "command": record["command"],
            "planned_bytes": job.planned_bytes,
            "planned_human": human_bytes(job.planned_bytes) if job.planned_bytes else "n/a",
            "executed": record["executed"],
            "returncode": record["returncode"],
            "seconds": record["seconds"],
            "output": record["output"],
            "log": record["log"],
            "result": record.get("result"),
        },
    )
    if not record["executed"]:
        res.add(
            "ok",
            "Tryb symulacji: telefon nie został w ogóle obsłużony",
            detail=(
                "domyślne zachowanie modułu; wykonanie wymaga parametrów dry_run=false oraz "
                "confirm=true, a odczyt jest operacją tylko do odczytu"
            ),
            values={
                "dry_run": True,
                "would_run": record["command"],
                "safety": [
                    "brak operacji zapisu ani kasowania w reprezentacji zadania",
                    "obraz telefonu nigdy nie jest zapisywany",
                    "wynik zapisywany w work/<case>/acquire/",
                ],
            },
        )
    else:
        severity = "ok" if record.get("returncode") == 0 else "critical"
        res.add(
            severity,
            f"Odczyt zakończony (exit {record.get('returncode')})",
            detail=record.get("log_tail", "")[-800:],
            values={
                "returncode": record.get("returncode"),
                "result": record.get("result"),
                "log": record["log"],
            },
        )
    res.add(
        "info",
        "Zasady akwizycji",
        detail=(
            "edlclient jest zależnością zewnętrzną (GPLv3) i nie jest importowany przez to "
            "narzędzie; forensic woła go jako osobny proces i czyta JSON, który sam zapisuje"
        ),
        values={
            "read_only_kinds": list(edl_job.KINDS),
            "loader_candidates": len(edl_job.loader_candidates(edl_dir)),
            "edl_dir": edl_dir,
        },
    )
    res.data = {
        "edl": edl,
        "rawprogram": {**raw, "partitions": [item.as_dict() for item in raw["partitions"]]},
        "job": job.as_dict(),
        "command": record["command"],
        "record": record,
        "dry_run": dry_run,
    }
    path = edl_job.write_record(
        {"generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"), **res.data},
        Path(ctx.workdir) / "acquire" / f"edl_{job.label}.json",
    )
    res.export(path)
    written = edl_job.write_acquisition(
        Path(ctx.workdir) / "acquire",
        producer=PRODUCER,
        jobs=[
            {
                "label": job.label,
                "kind": job.kind,
                "partition": job.partition,
                "output": job.output,
                "planned_bytes": job.planned_bytes,
                "executed": record["executed"],
                "returncode": record.get("returncode"),
                "seconds": record.get("seconds", 0.0),
                "status": record.get("status", edl_job.STATUS_PLANNED),
                "status_meaning": record.get("status_meaning", ""),
                "error": record.get("error", ""),
                "result": record.get("result", {}),
                "source": record.get("source", "edl"),
                "command": record["command"],
                "dry_run": dry_run,
            }
        ],
        context={
            "edl_dir": str(edl_dir),
            "edl_version": edl.get("version"),
            "patch_applied": edl.get("patch_applied"),
            "log": str(log_path),
        },
    )
    res.export(written["acquisition"])
    res.export(written["hashes"])
    status = written["status"]
    res.data["acquisition"] = {
        "status": status,
        "status_meaning": edl_job.STATUS_MEANING.get(status, ""),
        "producer": PRODUCER,
        "artefacts": doc_artefacts(written["hashes"]),
        "file": str(written["acquisition"]),
        "hashes": str(written["hashes"]),
        "manifest_columns": "name,source,sha256,bytes,recorded_utc",
        "statuses": list(edl_job.STATUSES),
    }
    res.add(
        {"planned": "ok", "completed": "ok", "partial": "warn", "failed": "critical"}[status],
        f"Stan akwizycji: {status} — {edl_job.STATUS_MEANING.get(status, '')}",
        detail=(
            "manifest integralności: hashes.csv (SHA-256 każdego artefaktu); "
            "stan akwizycji: acquisition.json"
            if record["executed"]
            else "nic nie wykonano — work/<case>/acquire/ zawiera plan i manifest pusty"
        ),
        values={
            "status": status,
            "status_meaning": edl_job.STATUS_MEANING.get(status, ""),
            "artefacts": res.data["acquisition"]["artefacts"],
            "acquisition": str(written["acquisition"]),
            "hashes": str(written["hashes"]),
        },
    )
    res.note(f"{time.time() - started:.1f}s")
    return ctx.record(res)


register(
    ModuleSpec(
        id="edl_acquire",
        category="tools",
        title="mod.edl_acquire.title",
        summary="mod.edl_acquire.summary",
        params=[
            Param(key="kind", label="param.acquire_kind", default="partition", kind=CHOICE, choices=edl_job.KINDS),
            Param(key="partition", label="param.partition", default="userdata", kind="str"),
            Param(key="dest", label="param.dest", default="", kind="path"),
            Param(key="rawprogram", label="param.rawprogram", default="", kind="path"),
            Param(key="start_sector", label="param.start_sector", default=0, kind=INT),
            Param(key="sectors", label="param.sectors", default=0, kind=INT),
            Param(key="loader", label="param.loader", default="", kind="str"),
            Param(key="dry_run", label="param.dry_run", default=True, kind=BOOL),
            Param(key="confirm", label="param.confirm_run", default=False, kind=BOOL),
        ],
        run=run,
        needs_image=False,
    )
)
