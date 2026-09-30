# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Environment preflight: interpreter, EDL dependency, sudo, USB, disk, image.

The EDL toolchain is an *external* dependency: forensic never imports it, it only
reports whether it is present and whether the local ``streaming.read_sectors``
fix is applied, because without that fix region reads are wrong.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

from ..core import i18n

PATCH_MARKERS = ("end_sector = sector + sectors", "page_offset = sector %")


def python_info() -> dict:
    return {
        "executable": sys.executable,
        "version": platform.python_version(),
        "implementation": platform.python_implementation(),
        "min_ok": sys.version_info >= (3, 10),
    }


def edl_info(edl_dir: str) -> dict:
    """Locate the external edl toolchain and check the local patch state."""
    # Path("") is ".", so an unconfigured edl_dir would otherwise be reported as
    # this very repository and the checks below would read its pyproject.toml.
    out: dict = {"dir": str(edl_dir), "configured": bool(str(edl_dir).strip())}
    out["exists"] = out["configured"] and Path(edl_dir).is_dir()
    if not out["exists"]:
        return out
    pyproject = Path(edl_dir) / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.strip().startswith("version"):
                out["version"] = line.split("=", 1)[1].strip().strip('"')
                break
        out["name"] = "edlclient"
    out["loaders_dir"] = str(Path(edl_dir) / "Loaders")
    out["loaders"] = len(list(Path(edl_dir).glob("Loaders/*"))) if Path(edl_dir, "Loaders").is_dir() else 0
    out["tools"] = {
        name: (Path(edl_dir) / name).exists()
        for name in ("edl.py", "qc_nand_extract.py", "qc_diag.py", "fastpwn", "autoinstall.sh")
    }
    streaming = Path(edl_dir) / "edlclient" / "Library" / "streaming.py"
    out["streaming_py"] = str(streaming)
    out["patch_applied"] = False
    out["patch_details"] = "brak pliku streaming.py"
    if streaming.exists():
        text = streaming.read_text(encoding="utf-8", errors="replace")
        hits = [marker for marker in PATCH_MARKERS if marker in text]
        out["patch_applied"] = len(hits) == len(PATCH_MARKERS)
        out["patch_details"] = (
            "obecna (read_sectors liczy end_sector/page_offset)"
            if out["patch_applied"]
            else "BRAK — odczyty regionów niewyrównanych do strony będą błędne"
        )
        try:
            out["streaming_mtime"] = streaming.stat().st_mtime
        except OSError:
            pass
    venv_python = Path(edl_dir) / "venv" / "bin" / "python"
    out["venv_python"] = str(venv_python) if venv_python.exists() else None
    if venv_python.exists():
        probe = subprocess.run(
            [
                str(venv_python),
                "-c",
                "import usb, serial, Crypto, lxml, paramiko; print('ok')",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        out["venv_deps"] = probe.returncode == 0
    return out


def usb_info() -> dict:
    out: dict = {}
    for dev in ("/dev/bus/usb", "/dev/ttyUSB0", "/dev/ttyACM0"):
        out[dev] = Path(dev).exists()
    out["lsusb"] = shutil.which("lsusb") is not None
    try:
        ids = sorted(
            entry.name for entry in Path("/sys/bus/usb/devices").glob("*-*:*.*")
        )
        out["usb_devices"] = len(ids)
    except Exception:
        out["usb_devices"] = 0
    return out


def sudo_info() -> dict:
    if os.geteuid() == 0:
        return {"root": True, "passwordless": True, "note": "running as root"}
    if not shutil.which("sudo"):
        return {"root": False, "passwordless": False, "note": "brak sudo"}
    try:
        proc = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5, check=False)
        return {
            "root": False,
            "passwordless": proc.returncode == 0,
            "note": "sudo -n działa" if proc.returncode == 0 else "sudo wymaga hasła",
        }
    except Exception as exc:
        return {"root": False, "passwordless": False, "note": str(exc)}


def tools_info() -> dict:
    from ..core.imagemount import tool_path

    names = (
        "mount",
        "umount",
        "e2fsck",
        "dumpe2fs",
        "tune2fs",
        "debugfs",
        "sqlite3",
        "file",
        "xxd",
        # Sleuth Kit — the independent second reader used by tsk_crosscheck.
        "fsstat",
        "fls",
        "istat",
        "icat",
        "ils",
    )
    return {name: tool_path(name) or "" for name in names}


def tsk_info() -> dict:
    """Sleuth Kit presence and version — the cross-check is off without it."""
    from ..core import tsk

    found = tsk.present()
    missing = [name for name in tsk.required_tools() if name not in found]
    return {
        "version": tsk.version(),
        "tools": found,
        "missing": missing,
        "available": not missing,
    }


def disk_info(paths: list[str]) -> dict:
    out: dict = {}
    for path in paths:
        target = Path(path)
        while target and not target.exists():
            target = target.parent
        if not target:
            continue
        try:
            usage = shutil.disk_usage(target)
            out[str(target)] = {
                "total": usage.total,
                "free": usage.free,
                "free_human": f"{usage.free / 2**30:.1f} GiB",
            }
        except Exception as exc:
            out[str(target)] = {"error": str(exc)}
    return out


def image_info(image: str, with_hash: bool = False) -> dict:
    out: dict = {"path": str(image), "configured": bool(str(image).strip())}
    if not out["configured"]:
        # Path("") is ".", and "." exists — without this the preflight would
        # stat the current directory and report a 4 KiB "image".
        out["exists"] = False
        return out
    path = Path(image)
    out["exists"] = path.exists() and not path.is_dir()
    if not out["exists"]:
        return out
    stat = path.stat()
    out["size"] = stat.st_size
    out["size_human"] = f"{stat.st_size / 2**30:.2f} GiB"
    out["mtime"] = stat.st_mtime
    if with_hash:
        from ..core.evidence import sha256_file

        out["sha256"] = sha256_file(path)
    return out


def collect(edl_dir: str, image: str, hash_image: bool = False) -> dict:
    from ..core.config import DATA_ROOT

    return {
        "python": python_info(),
        "edl": edl_info(edl_dir),
        "usb": usb_info(),
        "sudo": sudo_info(),
        "tools": tools_info(),
        "tsk": tsk_info(),
        "image": image_info(image, with_hash=hash_image),
        "disk": disk_info([path for path in (image, str(DATA_ROOT / "work")) if path]),
    }


def problems(report: dict) -> list[str]:
    """Human-readable list of blocking or noteworthy conditions."""
    out: list[str] = []
    if not report["python"]["min_ok"]:
        out.append(f"Python < 3.10 ({report['python']['version']})")
    if not report["image"].get("configured", True):
        out.append("nie skonfigurowano obrazu (użyj --image)")
    elif not report["image"]["exists"]:
        out.append(f"{i18n.t('msg.image_missing')}: {report['image']['path']}")
    if not report["edl"]["exists"]:
        out.append(
            "brak katalogu EDL (wymagany dla akwizycji)"
            + (f": {report['edl']['dir']}" if report["edl"]["dir"] else " — użyj --edl-dir")
        )
    else:
        if report["edl"].get("patch_applied") is False:
            out.append("uwaga: brak łaty streaming.read_sectors w lokalnym edl")
        if report["edl"].get("venv_deps") is False:
            out.append("uwaga: brak zależności Pythona w venv edl")
    if not report["sudo"]["passwordless"]:
        out.append("sudo bez hasła niedostępne — montowanie i e2fsck wyłączone")
    if not report.get("tsk", {}).get("available", True):
        missing = ", ".join(report["tsk"]["missing"])
        out.append(f"brak Sleuth Kit ({missing}) — weryfikacja krzyżowa wyłączona")
    return out
