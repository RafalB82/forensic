# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""Session context: what a module gets to work with, and what it leaves behind.

The context owns the lazily opened ext4 handle, the work directory, the masker
and the running log of module results.  It also persists itself to
``work/<case>/session.json`` so a later session can pick up where this one
stopped.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from collections.abc import Callable

from . import config as config_mod
from . import i18n
from .ext4 import Ext4, Ext4Error
from .export import json_default, write_private
from .findings import ModuleResult, utc_now
from .masking import Masker


@dataclass
class Ctx:
    """Everything a module needs, and the place it reports back to."""

    config: config_mod.Config
    fs_handle: Ext4 | None = None
    results: list[ModuleResult] = field(default_factory=list)
    started: str = field(default_factory=utc_now)
    run_id: str = field(
        default_factory=lambda: _dt.datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]
        + f"-{os.getpid()}"
    )
    color: bool = True
    progress_cb: Callable[[str], None] | None = None
    _packages: dict[int, str] | None = None
    _blockmap_cache: Any = None
    _file_scan: Any = None

    def __post_init__(self) -> None:
        i18n.set_lang(self.config.lang)
        i18n.set_reveal(self.config.reveal)

    def t(self, key: str, **kwargs: object) -> str:
        return i18n.t(key, **kwargs)

    @property
    def masker(self) -> Masker:
        return Masker()

    @property
    def image(self) -> Path:
        return self.config.path("image")

    @property
    def has_image(self) -> bool:
        """Whether an image path was configured at all.

        ``Path("")`` is ``.``, which exists, so the emptiness of the default
        cannot be discovered by asking the filesystem whether the path is there.
        """
        return bool(str(self.config.image).strip())

    @property
    def workdir(self) -> Path:
        return Path(self.config.workdir).expanduser() / self.config.case

    def work(self, *parts: str) -> Path:
        target = self.workdir.joinpath(*parts)
        target.mkdir(parents=True, exist_ok=True)
        return target

    def log(self, message: str) -> None:
        if self.progress_cb:
            self.progress_cb(message)

    def fs(self) -> Ext4:
        """Lazily open the image as ext4."""
        if self.fs_handle is not None:
            return self.fs_handle
        if not self.has_image:
            raise FileNotFoundError("nie skonfigurowano obrazu (użyj --image)")
        if not self.image.is_file():
            raise FileNotFoundError(f"{i18n.t('msg.image_missing')}: {self.image}")
        self.fs_handle = Ext4(str(self.image))
        return self.fs_handle

    def fs_info(self) -> dict:
        try:
            fs = self.fs()
        except (FileNotFoundError, Ext4Error):
            return {}
        return fs.superblock

    def packages(self) -> dict[int, str]:
        """uid -> package name, from /system/packages.xml inside the image."""
        if self._packages is not None:
            return self._packages
        try:
            self._packages = self.fs().packages()
        except Exception:
            self._packages = {}
        return self._packages

    def package_of(self, uid: int) -> str:
        return self.packages().get(uid, f"uid:{uid}")

    def file_scan(self, since: int = 0, root: str = "/") -> Any:
        """One walk of the image, shared by every module that needs file times.

        Three modules ask the same question — "which files were written after
        X" — and each answer costs a full traversal of 150 000 directory
        entries.  The result is cached for the lifetime of this context, so
        ``verify`` walks the image once instead of three times, and the cache
        key keeps a different cut-off from silently reusing the wrong answer.
        """
        from .fsscan import scan_files

        key = (root, int(since))
        if self._file_scan is None or self._file_scan.get("key") != key:
            self.log(self.t("msg.scanning"))
            self._file_scan = scan_files(self.fs(), root, int(since), progress=self.log)
            self._file_scan["key"] = key
        return self._file_scan

    def materialise(self, target: str) -> Path:
        """Local copy of a path that may live inside the image.

        The name comes from :func:`forensic.core.naming.unique_names` rather than
        from a substitution written out here, because the obvious inline version
        — replace every non-word character with an underscore — maps ``/a/b`` and
        ``/a_b`` to one file, and this method was that inline version.

        Streamed, not read into memory and written out.  Every caller of this
        wants a *file on disk* to hand to SQLite or another parser, so holding the
        whole artifact in RAM on the way there was a copy of the whole file for no
        reason — and a 10 GB database is a realistic thing to ask this tool about.
        The hash comes out of the same pass, so it is of the bytes actually
        written rather than of a buffer that was then written.

        A truncated image raises rather than returning a short buffer, and the
        write is atomic: a ``.part`` file that fails part-way is removed, so
        nothing half-written sits at the path the next run would reuse.
        """
        from .evidence import DEFAULT_STREAM_LIMIT, copy_stream
        from .naming import safe_name

        local = Path(target)
        if local.exists() and local.is_file():
            return local
        fs = self.fs()
        node = fs.resolve(target)
        out = self.work("extracted") / safe_name(target)
        copy_stream(
            lambda offset, length: fs.read_at(node, offset, length),
            out,
            size=node.size,
            limit=DEFAULT_STREAM_LIMIT,
        )
        return out

    def new_result(self, module_id: str) -> ModuleResult:
        return ModuleResult(module_id=module_id)

    def record(self, result: ModuleResult) -> ModuleResult:
        """Store a finished module result and refresh the session file."""
        self.results.append(result)
        self.save()
        return result

    def session_path(self) -> Path:
        return self.workdir / "session.json"

    def save(self) -> Path:
        path = self.session_path()
        runs = self._previous_runs()
        runs = [run for run in runs if run.get("run_id") != self.run_id]
        runs.append(self._current_run())
        payload = {
            "case": self.config.case,
            "updated": utc_now(),
            "config": self.config.as_dict(),
            "block_size": self.fs_info().get("block_size"),
            "runs": runs,
        }
        write_private(
            path,
            json.dumps(payload, indent=2, ensure_ascii=False, default=json_default),
        )
        return path

    def _previous_runs(self) -> list[dict]:
        path = self.session_path()
        if not path.exists():
            return []
        try:
            return list(json.loads(path.read_text(encoding="utf-8")).get("runs", []))
        except Exception:
            return []

    def _current_run(self) -> dict:
        return {
            "run_id": self.run_id,
            "started": self.started,
            "saved_at": utc_now(),
            "results": [
                {
                    "module": r.module_id,
                    "started": r.started,
                    "seconds": round(r.seconds, 2),
                    "worst": r.worst,
                    "counts": r.counts(),
                    "findings": [f.as_dict() for f in r.findings],
                    "exports": [str(e) for e in r.exports],
                    "notes": r.notes,
                }
                for r in self.results
            ],
        }

    def load_session(self) -> dict:
        """Read the session file written by an earlier run (unmasked values)."""
        path = self.session_path()
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}

    def prior_runs(self) -> list[dict]:
        return [run for run in self._previous_runs() if run.get("run_id") != self.run_id]

    def prior_findings(self) -> list:
        """Findings from earlier runs as :class:`Finding` objects."""
        from .findings import Finding

        out: list[Finding] = []
        for run in self.prior_runs():
            for entry in run.get("results", []):
                for item in entry.get("findings", []):
                    out.append(
                        Finding(
                            severity=item.get("severity", "info"),
                            title=item.get("title", ""),
                            detail=item.get("detail", ""),
                            values=item.get("values", {}),
                            artifacts=item.get("artifacts", []),
                            module=item.get("module", entry.get("module", "")),
                        )
                    )
        return out

    def close(self) -> None:
        if self.fs_handle is not None:
            self.fs_handle.close()
            self.fs_handle = None

    def __enter__(self) -> Ctx:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def timed(result: ModuleResult) -> Callable:
    def decorator(func: Callable) -> Callable:
        import functools

        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:
            start = time.time()
            try:
                return func(*args, **kwargs)
            finally:
                result.seconds = time.time() - start

        return wrapper

    return decorator
