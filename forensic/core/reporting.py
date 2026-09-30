# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 Rafał Bielawski

"""The report: a document an analyst can read, assembled from what was measured.

A report that lists 300 findings is a log, not a document.  This module turns
the machine output the modules already wrote into a structured answer sheet:
what the device was, whether it was unlocked, whether it had a network, when
each account was last authenticated, what the last session looked like, and
which conclusions rest on which file.

Two rules keep the document honest:

* every fact carries the export it came from and when that export was written,
  so a stale value is visible rather than silently quoted;
* a source that was never produced is listed as missing instead of being
  replaced by a plausible default.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path
from typing import Any

from . import i18n
from .export import human_bytes
from .masking import Masker
from .session import Ctx

VERSION = "0.12.0"
#: SPDX expression, and the identifier every source file carries in its header.
#: Kept next to the version because both are what ``--version`` and the built
#: wheel have to agree on.
LICENSE = "GPL-3.0-or-later"


def _case_sha256(ctx: Ctx) -> str:
    """Fall back to the hash recorded in the case file.

    Hashing 27 GB takes minutes; the case file already carries the value, and a
    report that says "nieobliczony" when the number is known is just noise.
    """
    from .config import CASES_DIR

    for suffix in (".public.json", ".local.json"):
        path = CASES_DIR / f"{ctx.config.case}{suffix}"
        if not path.exists():
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8")).get("image_sha256")
        except (OSError, ValueError) as exc:
            # A case file that exists but does not parse is worth saying out
            # loud: the report below then carries no hash and the reader has to
            # know whether that is because nobody computed one or because the
            # recorded one is unreadable.
            ctx.log(f"case {path.name}: {exc}")
            continue
        if value:
            return str(value)
    return ""


def _num(value: Any, default: int = 0) -> int:
    """Format a count safely: exports may legitimately hold ``None``."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


class Builder:
    """Collects facts from the exports of one case and renders the document."""

    def __init__(self, ctx: Ctx) -> None:
        self.ctx = ctx
        self.exports = ctx.work("exports")
        self.sources: dict[str, dict] = {}
        self.verdicts: list[dict] = []
        self.accounts: list[dict] = []
        self.credentials: list[dict] = []
        self.session: dict = {}
        self.clock: dict = {}
        self.missing: list[str] = []
        self.skipped: list[dict] = []

    def read_export(self, filename: str) -> dict:
        """Load one export by path, without the per-module cache.

        :meth:`source` remembers one file per module, which is what the verdict
        tables want: a module is a source, and a module's exports are the same
        thing seen twice.  It stops being true the moment one module writes more
        than one file, and ``edl_acquire`` now does — the plan detail in
        ``edl_<label>.json`` and the outcome in ``acquisition.json`` are different
        documents with different jobs.  This reads a second file from the same
        module, so it neither pollutes the cache nor the missing-sources list
        with a file that was never looked for.
        """
        path = self.exports / filename
        if not path.exists():
            return {}
        return _load(path)

    def source(self, module: str, filename: str) -> dict:
        """Load one export and remember when it was written."""
        if module in self.sources:
            return self.sources[module]
        path = self.exports / filename
        if not path.exists():
            self.sources[module] = {}
            self.missing.append(f"{module} ({filename})")
            return {}
        data = _load(path)
        try:
            written = _dt.datetime.fromtimestamp(
                path.stat().st_mtime, _dt.timezone.utc
            ).isoformat(timespec="seconds")
        except OSError:
            written = ""
        self.sources[module] = {
            "file": str(path),
            "written_utc": written,
            "bytes": path.stat().st_size,
            "data": data,
        }
        return self.sources[module]

    def verdict(self, topic: str, answer: str, evidence: str = "", source: str = "") -> None:
        self.verdicts.append(
            {"topic": topic, "answer": answer, "evidence": evidence, "source": source}
        )

    def account(self, service: str, last_auth: str, last_touch: str, source: str, note: str = "") -> None:
        self.accounts.append(
            {
                "service": service,
                "last_auth_utc": last_auth or "—",
                "last_activity_utc": last_touch or "—",
                "source": source,
                "note": note,
            }
        )

    def credential(self, kind: str, what: str, where: str, state: str) -> None:
        self.credentials.append(
            {"kind": kind, "what": what, "where": where, "state": state}
        )

    # ------------------------------------------------------------------ build

    def build(self) -> dict:
        self._image()
        self._unlock()
        self._network()
        self._accounts()
        self._session()
        self._clock()
        self._applications()
        self._system_session()
        self._acquisition()
        self._skipped()
        return self._document()

    def _skipped(self) -> None:
        """Records a module stepped over, and why.

        A count is not the same as nothing happened.  A directory that would not
        list, an inode that would not read, a block that would not come off the
        image: each of them shortens the result silently unless it is written
        down, and a shorter result reads exactly like a device that had less on
        it.  Every module that can skip something reports it under ``skipped``
        or ``walk_errors`` in its export, and this collects those.
        """
        for module, filename, section, keys in (
            ("fs_timeline", "fs_timeline.json", "scan", ("walk_errors", "walk_error_detail")),
            ("blockmap", "blockmap.json", "index", ("skipped", "skipped_detail")),
            ("carve", "carve.json", "", ("carve_blocks_unreadable", None)),
        ):
            data = self.source(module, filename).get("data", {})
            if section:
                data = data.get(section, {})
            if not isinstance(data, dict) or not data:
                continue
            count_key, detail_key = keys
            count = _num(data.get(count_key))
            if not count:
                continue
            detail: list[dict] = []
            if detail_key:
                detail = [item for item in data.get(detail_key, []) if isinstance(item, dict)]
            self.skipped.append(
                {
                    "module": module,
                    "count": count,
                    "kind": count_key,
                    "detail": detail[:5],
                    "source": f"{module}/{filename}",
                }
            )

    def _image(self) -> None:
        source = self.source("image_info", "image_info.json")
        data = source.get("data", {})
        geometry = data.get("geometry", {})
        state = data.get("state", {})
        self.image = {
            "path": str(self.ctx.image),
            "size_bytes": geometry.get("size_bytes") or data.get("size_bytes", 0),
            "size_human": human_bytes(geometry.get("size_bytes") or 0),
            "block_size": geometry.get("block_size"),
            "blocks_count": geometry.get("blocks_count"),
            "groups": geometry.get("groups"),
            "uuid": state.get("uuid"),
            "state": state.get("state_name"),
            "features": data.get("flags", {}).get("features", []),
            "recover_needed": data.get("flags", {}).get("recover_needed"),
            "errors": state.get("errors"),
            "last_mounted": state.get("last_mounted"),
            "packages": data.get("packages"),
            "partition": data.get("partition", {}),
            "sha256": data.get("sha256") or _case_sha256(self.ctx),
            "source": source.get("file", ""),
        }
        dirty = self.source("fs_check", "e2fsck.log")
        if dirty:
            self.image["consistency"] = "e2fsck -fn: patrz log (exit 4 = obraz po nieczystym odmontowaniu)"

    def _unlock(self) -> None:
        source = self.source("unlock_proof", "unlock_proof.json")
        data = source.get("data", {})
        evidence = data.get("evidence", {})
        state = data.get("state", {})
        if not data:
            return
        self.verdict(
            "Odblokowanie",
            {"unlocked": "TAK", "unproven": "nie da się potwierdzić"}.get(
                data.get("verdict", ""), data.get("verdict", "?")
            ),
            f"{evidence.get('files', 0)} plików ({human_bytes(evidence.get('bytes', 0))}) "
            f"zapisanych w katalogach szyfrowanych FBE po {evidence.get('since_utc', '?')}",
            "unlock_proof",
        )
        self.verdict(
            "PIN ekranu blokady",
            f"{state.get('password_type_name', '?')} ({state.get('password_type', '?')}), "
            + ("niezmieniony" if data.get("unchanged", {}).get("identical") else "ZMienIONY"),
            f"locksettings.db przepisany {state.get('mtime_utc', '?')}; "
            f"lockoutattemptdeadline = {state.get('lockout_attempt_deadline', '?')}; "
            f"trust agent: {state.get('trust_agents') or 'brak'}",
            "unlock_proof",
        )
        self.credential(
            "PIN",
            f"odzyskany ({data.get('password_key', {}).get('length', 0)} znaków password.key)",
            "/system/password.key + locksettings.db",
            "maskowany; wartość w work/<case>/exports/unlock_proof.json",
        )

    def _network(self) -> None:
        source = self.source("net_state", "net_state.json")
        data = source.get("data", {})
        if not data:
            return
        ages = data.get("signal_ages_days", {})
        counters = data.get("counters", {})
        self.verdict(
            "Sesja sieciowa w chwili dumpu",
            data.get("verdict_pl", "?"),
            "; ".join(
                f"{name}: {value.get('utc', '?')} ({value.get('days_before_floor', 0):.0f} dni przed progiem)"
                for name, value in ages.items()
            )
            + (
                f"; liczniki ruchu: {counters.get('verdict')} "
                f"(interfejs {', '.join(counters.get('ifaces', [])) or '—'}) — zliczanie działało, "
                "ale lease DHCP nie został odświeżony"
                if counters.get("files")
                else f"; brak liczników ruchu ({counters.get('verdict', '?')})"
            ),
            "net_state",
        )
        wifi = self.source("wifi_creds", "wifi_creds.json")
        wifi_data = wifi.get("data", {})
        if wifi_data:
            self.credential(
                "Klucze WPA",
                f"{wifi_data.get('with_psk', 0)} zapisanych sieci z kluczem w jawnej postaci",
                "wifi_settings.db + wpa_supplicant.conf",
                "SSID: " + ", ".join(item["ssid"] for item in wifi_data.get("networks", []) if item.get("psk")),
            )

    def _accounts(self) -> None:
        login = self.source("login_timeline", "login_timeline.json")
        data = login.get("data", {})
        if data:
            for service, entry in data.get("per_service", {}).items():
                self.account(
                    service,
                    entry.get("last_auth_utc", ""),
                    entry.get("last_utc", ""),
                    entry.get("last_auth_evidence") or entry.get("last_source", ""),
                    entry.get("note", ""),
                )
            grant = data.get("gmail_mail_grant", {})
            if grant:
                self.account(
                    "gmail (grant z prawem czytania poczty)",
                    grant.get("last_grant_utc", ""),
                    "",
                    "accounts.db extras EXP",
                    grant.get("note", ""),
                )
        accounts = self.source("accounts_db", "accounts_db.json")
        payload = accounts.get("data", {})
        if payload:
            for item in payload.get("accounts", []):
                if item.get("password"):
                    self.credential(
                        "Hasło konta",
                        f"{item.get('type')}: jawnie w accounts.db",
                        f"{item.get('name')}",
                        "maskowane",
                    )
        journal = self.source("authtoken_journal", "authtokens_from_journal.json")
        tokens = journal.get("data", {})
        if tokens:
            other = int(tokens.get("other_providers") or 0)
            self.credential(
                "Tokeny OAuth2",
                f"{tokens.get('google_oauth2', 0)} tokenów Google"
                + (f" + {other} innych autentykatorów" if other else "")
                + " (odzyskane z journala)",
                "accounts.db-journal (nagłówek wyzerowany)",
                "maskowane; ważność zapisana w accounts.db extras",
            )
        login_data = self.source("login_data", "login_data.json")
        plaintext = login_data.get("data", {})
        if plaintext:
            self.credential(
                "Hasła w przeglądarce",
                f"{plaintext.get('plaintext_passwords', 0)} zapisanych haseł w jawnej postaci",
                ", ".join(Path(item["target"]).name for item in plaintext.get("targets", []) if isinstance(item, dict))
                or "Login Data",
                "maskowane",
            )
        fb = self.source("fb_tokens", "fb_tokens.json")
        fb_data = fb.get("data", {})
        if fb_data:
            self.credential(
                "Tokeny dostępu Facebooka",
                f"{fb_data.get('token_count', 0)} unikalnych tokenów EAA "
                f"({fb_data.get('occurrences', 0)} wystąpień)",
                "prefs_db, jego journal, PropertiesStore_v02",
                "maskowane",
            )

    def _session(self) -> None:
        source = self.source("fs_timeline", "fs_timeline.json")
        data = source.get("data", {})
        if not data:
            return
        usage = data.get("usage", {})
        shutdown = data.get("shutdown", {})
        crashes = data.get("crashes", [])
        self.session = {
            "first_utc": data.get("first_utc", ""),
            "last_utc": data.get("last_utc", ""),
            "first_local": data.get("first_local", ""),
            "last_local": data.get("last_local", ""),
            "span": data.get("span_human", ""),
            "files": data.get("count", 0),
            "bytes": data.get("bytes_written", 0),
            "bytes_human": human_bytes(data.get("bytes_written", 0)),
            "packages": data.get("by_package", {}),
            "days": data.get("by_day", {}),
            "bursts": len(data.get("bursts", [])),
            "usage_packages": usage.get("packages", 0),
            "usage_first_utc": usage.get("first_utc", ""),
            "usage_last_utc": usage.get("last_utc", ""),
            "shutdown": {
                "files": shutdown.get("files", 0),
                "first_utc": shutdown.get("first_utc", ""),
                "last_utc": shutdown.get("last_utc", ""),
                "services": shutdown.get("services_stopped", []),
            },
            "crashes": [
                {
                    "path": item.get("path", ""),
                    "utc": item.get("utc", ""),
                    "process": item.get("process", ""),
                    "signal": item.get("signal", ""),
                }
                for item in crashes
            ],
            "notable": [
                {"path": item.get("path", ""), "utc": item.get("utc", ""), "why": item.get("why", "")}
                for item in data.get("notable", [])[:12]
            ],
        }
        self.verdict(
            "Ostatnia sesja pracy urządzenia",
            f"{self.session['first_utc']} → {self.session['last_utc']} ({self.session['span']})",
            f"{self.session['files']} plików, {self.session['bytes_human']}, "
            f"{self.session['bursts']} burstów, {self.session['usage_packages']} pakietów w "
            f"package-usage.list; końcowe zapisy {self.session['shutdown'].get('last_utc', '?')}",
            "fs_timeline",
        )
        if crashes:
            self.verdict(
                "Awarie w sesji",
                f"{len(crashes)} zrzutów procesu",
                "; ".join(
                    f"{item['process']} {item['signal']} o {item['utc']}" for item in crashes
                ),
                "fs_timeline",
            )

    def _clock(self) -> None:
        source = self.source("clock_anomaly", "clock_anomaly.json")
        data = source.get("data", {})
        if not data:
            return
        counts = data.get("counts", {})
        installer = data.get("installer_clock", {})
        self.clock = {
            "counts": counts,
            "coherent_range": data.get("coherent_range", []),
            "installer_agreement": installer.get("agreement"),
            "installer_matched": installer.get("matched_either"),
            "installer_compared": installer.get("compared"),
            "session_verdict": data.get("session_cluster", {}).get("verdict", ""),
            "verdict": data.get("verdict", {}).get("verdict", ""),
        }
        self.verdict(
            "Wiarygodność dat",
            f"{counts.get('coherent_2016_2022', 0)} plików z datami spójnymi, "
            f"{counts.get('epoch_or_rom', 0) + counts.get('installer_constant', 0)} z datami pozornymi",
            f"epoka ROM: {counts.get('epoch_or_rom', 0)}; stała instalatora (1979): "
            f"{counts.get('installer_constant', 0)}; zegar potwierdzony na "
            f"{installer.get('matched_either', 0)}/{installer.get('compared', 0)} katalogach /app",
            "clock_anomaly",
        )

    def _applications(self) -> None:
        messenger = self.source("messenger", "messenger.json")
        data = messenger.get("data", {})
        if data:
            threads = data.get("threads", {})
            self.verdict(
                "Messenger — treść rozmów",
                f"{threads.get('messages_total', 0)} wiadomości w bazie lokalnej",
                f"{threads.get('with_text', 0)} z tekstem, okno {threads.get('plausible_range_utc', ['', ''])[0]} → "
                f"{threads.get('plausible_range_utc', ['', ''])[-1]}; "
                f"{threads.get('zero_timestamps', 0)} rekordów bez znacznika czasu",
                "messenger",
            )
            for store in data.get("msys", []):
                if store.get("identities"):
                    for identity in store["identities"]:
                        self.credential(
                            "Klucze E2EE Messengera",
                            f"local_registration_id {identity.get('local_registration_id')}",
                            store.get("target", ""),
                            "para kluczy prywatnych obecna lokalnie (maskowana)"
                            if identity.get("private_key_present")
                            else "bez kluczy prywatnych",
                        )
        whatsapp = self.source("whatsapp", "whatsapp.json")
        wa = whatsapp.get("data", {})
        if wa:
            axolotl = wa.get("axolotl", {}).get("counts", {})
            self.verdict(
                "WhatsApp — hasło",
                "brak mechanizmu hasła (numer telefonu + SMS)",
                f"msgstore: {wa.get('msgstore', {}).get('messages_total', 0)} wiadomości; "
                f"axolotl: {axolotl.get('sessions', 0)} sesji, "
                f"{axolotl.get('message_base_key', 0)} message_base_key; "
                f"brak kluczy keystore dla "
                f"{', '.join(str(item.get('uid')) for item in wa.get('keystore', {}).get('missing', []))}",
                "whatsapp",
            )
        snapchat = self.source("snapchat", "snapchat.json")
        sc = snapchat.get("data", {})
        if sc:
            found = (sc.get("play", {}).get("found") or [{}])[0]
            self.verdict(
                "Snapchat",
                "aplikacja odinstalowana; brak danych konta",
                f"Sklep Play: pobranie {found.get('first_download_utc', '?')}, wersja "
                f"{found.get('last_notified_version', '?')}, konto {found.get('account', '?')}; "
                f"jedno uruchomienie w galerii MIUI",
                "snapchat",
            )
        install = self.source("app_install_timeline", "app_install_timeline.json")
        timeline = install.get("data", {})
        if timeline:
            self.verdict(
                "Sklep Play — stan instalacji",
                f"{timeline.get('rows', 0)} aplikacji w localappstate.db",
                f"{timeline.get('data_dir_present', 0)} z katalogiem danych, "
                f"{timeline.get('without_data_dir', 0)} bez; konta: "
                f"{', '.join(timeline.get('accounts', []))}",
                "app_install_timeline",
            )

    def _system_session(self) -> None:
        source = self.source("session_system", "session_system.json")
        data = source.get("data", {})
        if not data:
            return
        verdict = data.get("verdict", {})
        reboots = data.get("kernel_reboots", {})
        crashes = data.get("crashes", {})
        debug = data.get("debug_logs", {}).get("logs", [])
        self.system = {
            "verdict": verdict.get("verdict", ""),
            "verdict_pl": verdict.get("verdict_pl", ""),
            "reasons": verdict.get("reasons", []),
            "files": len(data.get("files", [])),
            "by_category": data.get("by_category", {}),
            "kernel_reboots": reboots.get("records", []),
            "crash_history": crashes.get("history_range", ""),
            "crashes_in_session": data.get("session_crashes", []),
            "procstats": len(data.get("procstats", {}).get("snapshots", [])),
            "debug_logs": [
                {"app": item.get("app", ""), "count": item.get("count", 0), "mtime_utc": item.get("mtime_utc", "")}
                for item in debug
            ],
            "batterystats": data.get("batterystats", {}),
        }
        times = [item.get("utc", "") for item in reboots.get("records", [])]
        self.verdict(
            "Strona systemowa sesji 2026",
            verdict.get("verdict_pl", "?"),
            "; ".join(verdict.get("reasons", []))
            + (
                f"; restarty jądra o {', '.join(times)}"
                if times
                else ""
            )
            + (
                f"; {self.system['procstats']} migawek procesów; "
                f"historia awari sięga {crashes.get('history_range', '?')}"
                if self.system["procstats"]
                else ""
            ),
            "session_system",
        )

    def _acquisition(self) -> None:
        """Acquisition outcome, and the two manifests named as two things.

        There are two integrity manifests in a case and they cover different
        ground, so the report says which is which rather than letting a reader
        add them up: ``acquire/hashes.csv`` is what was *acquired* (the input),
        ``exports/extract_manifest.json`` is what was *extracted for analysis*
        (derived from the input).  A file can appear in both and must not be
        counted twice.

        ``acquisition.json`` is the source of truth for outcome; the per-job
        ``edl_<label>.json`` remains the record of the plan and the argv.
        """
        document = self.read_export("../acquire/acquisition.json")
        detail = self.source("edl_acquire", "../acquire/edl_userdata.json")
        if not document and not detail:
            return
        status = document.get("status")
        job = detail.get("data", {}).get("job", {}) or (document.get("jobs") or [{}])[0]
        produced = document.get("producer", "")
        acquired = document.get("artefacts", 0)
        extracted = 0
        manifest = self.source("extract_file", "extract_manifest.json")
        if manifest:
            extracted = int(manifest.get("data", {}).get("count", 0) or 0)
        self.verdict(
            "Akwizycja",
            (
                f"stan {status} — {job.get('partition', '?')} "
                f"({human_bytes(job.get('planned_bytes', 0))})"
                if status
                else f"plan odczytu {job.get('kind', '?')} {job.get('partition', '?')} "
                f"({human_bytes(job.get('planned_bytes', 0))})"
            ),
            (
                f"producent: {produced}; "
                f"akwizytowane artefakty: {acquired} (manifest acquire/hashes.csv); "
                f"wyekstrahowane do analizy: {extracted} (manifest exports/extract_manifest.json) — "
                "to dwa różne manifesty, plik może wystąpić w obu i nie wolno zliczać go podwójnie"
            ),
            "edl_acquire",
        )
        if status == "partial":
            self.verdict(
                "Akwizycja",
                "akwizycja niepełna — zgłoszony plik nie jest całą partycją",
                "status=partial: kod wyjścia lub rozmiar wskazują, że odczyt urwał się "
                "albo jest ucięty; dalsza analiza operuje na pliku niepełnym",
                "edl_acquire",
            )

    def _document(self) -> dict:
        session = self.ctx.load_session()
        return {
            "tool": {"name": "forensic", "version": VERSION, "language": i18n.get_lang()},
            "case": self.ctx.config.case,
            "generated_utc": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
            "image": getattr(self, "image", {}),
            "verdicts": self.verdicts,
            "accounts": self.accounts,
            "credentials": self.credentials,
            "session": self.session,
            "system_session": getattr(self, "system", {}),
            "clock": self.clock,
            "missing_sources": self.missing,
            "skipped_total": sum(item["count"] for item in self.skipped),
            "skipped": self.skipped,
            "sources": {
                module: {k: v for k, v in info.items() if k != "data"}
                for module, info in self.sources.items()
                if info
            },
            "runs": len(session.get("runs", [])),
            "findings_total": sum(
                len(entry.get("findings", []))
                for run in session.get("runs", [])
                for entry in run.get("results", [])
            ),
        }


def build(ctx: Ctx) -> dict:
    return Builder(ctx).build()


# ------------------------------------------------------------------ rendering

ICONS = {"yes": "✓", "no": "✖", "warn": "⚠", "info": "ℹ"}


def to_markdown(doc: dict, masker: Masker | None = None) -> str:
    """Render the document; secrets stay masked unless reveal is switched on."""
    show = masker.as_json if masker else (lambda value: value)
    image = doc.get("image", {})
    title = doc.get("title") or f"forensic — {doc.get('case', 'case')}"
    lines = [
        f"# {title}",
        "",
        f"_{doc.get('generated_utc', '')} · forensic {doc.get('tool', {}).get('version', '?')} · "
        f"{doc.get('tool', {}).get('language', 'pl')} · {doc.get('runs', 0)} przebiegów, "
        f"{doc.get('findings_total', 0)} findings_",
        "",
    ]
    if image:
        lines += [
            "## Obraz",
            "",
            "| pole | wartość |",
            "|---|---|",
            f"| plik | `{image.get('path', '')}` |",
            f"| rozmiar | {image.get('size_human') or '?'} "
            f"({_num(image.get('size_bytes')):,} B)".replace(",", " "),
            f"| geometria | blok {image.get('block_size') or '?'} B · "
            f"{_num(image.get('blocks_count')):,} bloków · {image.get('groups') or '?'} grup |".replace(",", " "),
            f"| UUID | `{image.get('uuid', '?')}` |",
            f"| stan fs | {image.get('state') or '?'} · recover: {image.get('recover_needed')} · "
            f"errors: {image.get('errors', '?')} · ostatni mount: {image.get('last_mounted') or '?'} |",
            f"| cechy | {', '.join(image.get('features', [])) or '—'} |",
            f"| SHA-256 | `{image.get('sha256') or 'nieobliczony'}` |",
            "",
        ]
    if doc.get("verdicts"):
        lines += ["## Werdykty", "", "| kwestia | odpowiedź | dowód | źródło |", "|---|---|---|---|"]
        for item in doc["verdicts"]:
            lines.append(
                f"| {item['topic']} | **{show(item['answer'])}** | {show(item['evidence'])} | `{item['source']}` |"
            )
        lines.append("")
    if doc.get("accounts"):
        lines += [
            "## Konta — uwierzytelnienie i aktywność",
            "",
            "| konto | ostatnie uwierzytelnienie | ostatnia aktywność | źródło |",
            "|---|---|---|---|",
        ]
        for item in doc["accounts"]:
            lines.append(
                f"| {item['service']} | {item['last_auth_utc']} | {item['last_activity_utc']} | "
                f"{show(item['source'])} |"
            )
        lines.append("")
    if doc.get("credentials"):
        lines += [
            "## Znalezione sekrety (maskowane)",
            "",
            "| rodzaj | co | gdzie | stan |",
            "|---|---|---|---|",
        ]
        for item in doc["credentials"]:
            lines.append(
                f"| {item['kind']} | {show(item['what'])} | `{item['where']}` | {item['state']} |"
            )
        lines.append("")
    session = doc.get("session", {})
    if session:
        lines += [
            "## Ostatnia sesja pracy urządzenia",
            "",
            f"- okno: **{session.get('first_utc', '?')} → {session.get('last_utc', '?')}** "
            f"({session.get('first_local', '?')} → {session.get('last_local', '?')} czasem lokalnym), "
            f"długość {session.get('span', '?')}",
            f"- zapisano {session.get('files', 0)} plików, {session.get('bytes_human', '?')}, "
            f"{session.get('bursts', 0)} burstów aktywności",
            f"- `package-usage.list`: {session.get('usage_packages', 0)} pakietów "
            f"({session.get('usage_first_utc', '?')} → {session.get('usage_last_utc', '?')})",
            f"- końcowe zapisy (wyłączenie): {session.get('shutdown', {}).get('last_utc', '?')} "
            f"— {', '.join(session.get('shutdown', {}).get('services', [])[:8])}",
        ]
        if session.get("crashes"):
            lines.append("- awarie:")
            for item in session["crashes"]:
                lines.append(f"  - {item['utc']} `{item['path']}` — {item['process']}, {item['signal']}")
        if session.get("packages"):
            top = list(session["packages"].items())[:10]
            lines.append("- najczęściej zapisywane pakiety: " + ", ".join(f"{k} ({v})" for k, v in top))
        lines.append("")
    system = doc.get("system_session", {})
    if system:
        lines += [
            "## Sesja od strony systemu",
            "",
            f"- werdykt: **{system.get('verdict_pl', '?')}** — {'; '.join(system.get('reasons', []))}",
            f"- zapisy poza `/data`: {system.get('files', 0)} plików "
            f"({', '.join(f'{k} ({v})' for k, v in list(system.get('by_category', {}).items())[:6])})",
        ]
        if system.get("kernel_reboots"):
            lines.append(
                "- restarty jądra (czas lokalny): "
                + ", ".join(item.get("local", "?") for item in system["kernel_reboots"])
            )
        for item in system.get("crashes_in_session", []):
            lines.append(
                f"- awarie w sesji: `{item.get('package', '?')}` ×{len(item.get('occurrences', []))} "
                f"({', '.join(item.get('occurrences_utc', []))})"
            )
        if system.get("procstats"):
            lines.append(f"- migawki procesów: {system['procstats']}")
        for item in system.get("debug_logs", []):
            lines.append(
                f"- log diagnostyczny `{item.get('app', '?')}`: {item.get('count', 0)} wpisów "
                f"({item.get('mtime_utc', '?')})"
            )
        battery = system.get("batterystats") or {}
        if battery:
            lines.append(
                f"- statystyki baterii: {battery.get('size_human', '?')} — {battery.get('verdict', '')}"
            )
        lines.append("")
    clock = doc.get("clock", {})
    if clock:
        lines += [
            "## Wiarygodność dat",
            "",
            f"- daty spójne: **{_num(clock.get('counts', {}).get('coherent_2016_2022')):,}** plików "
            f"({clock.get('coherent_range', ['', ''])[0]} → {clock.get('coherent_range', ['', ''])[-1]})".replace(",", " "),
            f"- daty pozorne: {clock.get('counts', {}).get('epoch_or_rom', 0)} z epoki ROM, "
            f"{clock.get('counts', {}).get('installer_constant', 0)} zapisanych przez instalatora (1979)",
            f"- zegar potwierdzony na {clock.get('installer_matched', '?')}/{clock.get('installer_compared', '?')} "
            f"katalogach aplikacji względem dat Sklepu Play",
            f"- sesja z {clock.get('counts', {}).get('after_2026', 0)} plików: {clock.get('session_verdict', '?')}",
            "",
        ]
    if doc.get("missing_sources"):
        lines += [
            "## Brakujące źródła",
            "",
            "Następujące eksporty nie istnieją, więc raport jest niekompletny:",
            "",
        ]
        lines += [f"- {item}" for item in doc["missing_sources"]]
        lines.append("")
    if doc.get("skipped"):
        lines += [
            f"## Pominięte rekordy: {doc.get('skipped_total', 0)}",
            "",
            "Rekordy, których nie dało się odczytać. Każdy z nich to luka w dowodzie, "
            "nie brak danych w urządzeniu — liczby poniżej są dolnym oszacowaniem.",
            "",
            "| moduł | co pominięto | liczba | przykład |",
            "|---|---|---|---|",
        ]
        for item in doc["skipped"]:
            example = "; ".join(
                f"{row.get('path', '?')}: {row.get('error', '?')}" for row in item.get("detail", [])
            )
            lines.append(
                f"| `{item['module']}` | {item['kind']} | {item['count']} | {example or '—'} |"
            )
        lines.append("")
    lines += ["## Źródła", "", "| moduł | eksport | zapisany (UTC) |", "|---|---|---|"]
    for module, info in sorted(doc.get("sources", {}).items()):
        lines.append(
            f"| `{module}` | `{Path(info.get('file', '')).name}` | {info.get('written_utc', '?')} |"
        )
    lines.append("")
    return "\n".join(lines)
