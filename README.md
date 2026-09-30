# forensic

Offline forensics toolkit for Android partition images. Reads ext4, F2FS and
EROFS volumes directly, without mounting them, and answers the questions an
analyst asks about a dumped device: whose accounts were on it, when it was last
unlocked, what was deleted before seizure, and what is still recoverable.

* **Offline.** No network calls, no telemetry, no external service. Works on a
  workstation with no connectivity.
* **Read-only.** The image is never modified. Every artefact is written to a
  separate work directory.
* **Bilingual.** Polish and English throughout, switchable at runtime.
* **Secrets masked** by default, revealed only on request.

## Contents

- [What it gives you](#what-it-gives-you)
- [Requirements](#requirements)
- [Installation](#installation)
- [Running it](#running-it)
- [Configuration](#configuration)
- [Modules](#modules)
- [A typical session](#a-typical-session)
- [Case files and verification](#case-files-and-verification)
- [Tests](#tests)
- [Where the results are](#where-the-results-are)
- [Formats and limits](#formats-and-limits)
- [Acquisition](#acquisition)
- [Licence](#licence)

## What it gives you

**A picture of the device that outlived the seizure.** Accounts and when each
was last authenticated and last active, saved browser logins, cookies, browsing
and search history, WiFi networks with their keys, the lock-screen PIN state,
proof of unlock, and the network state at the moment of the dump.

**Application data as the applications actually store it.** Messenger, WhatsApp,
Facebook, Snapchat: which database still holds the message text, which tokens and
keys exist, and where an app left nothing behind at all. The report says which of
those is the case rather than listing an empty table.

**A timeline of the last session.** Every file written after a cut-off moment,
grouped into bursts, plus the system side of the same session — crash dumps,
kernel restart records, process snapshots, traffic counters. A verdict on which
timestamps can be trusted, because device clocks lie.

**Deleted data, as far as it still exists.** Inodes whose entries were removed,
with the size they declared; names of deleted files recovered from directory
blocks; an inventory of unallocated space; and content candidates carved out of
it, each graded and each marked with how far it could be validated.

**A report that says where every number came from.** The image and its geometry,
verdicts on the open questions with the evidence for each, an accounts table
separating last authentication from last activity, the secrets found (masked),
the last session, date reliability, and the sources with their write times —
including the sources that are missing.

**A standard export other tools accept.** The whole filesystem as a body file, the
inventory format every timeline tool in the field reads, so results can go
straight into `mactime`, a spreadsheet or another case tool.

**An answer to "which file is at this offset".** The reverse question, in both
directions: image offset to owning file and position within it, and file to image
offsets. This is what the whole tool is built around, and it is what mounting the
image does not give you.

## Requirements

* Linux, Python 3.10 or newer. No third-party Python packages.
* Python 3.10+ means expat 2.4.1 or newer, which is what makes parsing XML out
  of an image safe from entity expansion: expat does not resolve external or
  recursively defined entities, and the builds that were vulnerable to the
  "billion laughs" shape are all older than the floor this project requires. On
  top of that every XML parse is refused above 5 MiB
  (`forensic/core/xmlsafe.py`), which bounds the work an oversized preference
  file can cause.
* Optional, used when present and skipped with a warning when not:
  `e2fsprogs` (`e2fsck`, `dumpe2fs`, `debugfs`, and `mke2fs` for the
  self-test), The Sleuth Kit (`apt install sleuthkit`, for the independent
  cross-check), `sqlite3`, `file`, `xxd`.
* Optional: an external EDL toolchain, only for acquisition. Not part of this
  project and not required for any analysis.

Check what is present:

```bash
./forensic.py --preflight
```

It reports the interpreter, the optional tools, the EDL dependency, sudo, USB and
free disk space, and which case and image are configured. With no image
configured it says so — `nie skonfigurowano obrazu (użyj --image)` — rather than
complaining about a file that does not exist.

## Installation

```bash
./install.sh                 # venv + the package itself
./install.sh --no-venv       # install into the current interpreter
```

Or install the package on its own:

```bash
pip install .
forensic --version
```

Either way you get a `forensic` command; the repository also ships
`./forensic.py`, which runs without installing anything and is what the examples
below use.

## Running it

```bash
./forensic.py                      # menu, or the curses TUI on a capable terminal
./forensic.py --ui menu            # force the plain-text menu
./forensic.py --ui curses          # force the full-screen TUI (falls back to the menu)
./forensic.py --list               # list all modules
./forensic.py --preflight          # environment check
./forensic.py --cli <module>       # run one module and exit
./forensic.py --lang en            # English interface
./forensic.py --reveal             # show secrets in the clear
```

The two frontends have the same shape. Categories are digits, actions are
letters, `?` opens help and `q` quits:

```
CATEGORIES   37 modules
  1  Image and file system
  2  Accounts and credentials
  3  Applications
  4  Timeline and session
  5  Tools
  6  Report and verification

ACTIONS
  v  Verify the case file (full run)
  r  Session report
  s  Results of this session
  l  Language
  m  Secrets
  ?  Help
  q  Exit
```

Enter a category number to see its modules, then choose one. The plain-text menu
works over SSH and in any terminal; the curses one adds arrow-key navigation and
a detail pane. Both adapt to the terminal width, and both fall back to ASCII
where a character cannot be drawn.

### Running a single module

Any module runs non-interactively, which is what you want for repeatability or
for scripting a sequence:

```bash
./forensic.py --cli free_space
./forensic.py --cli carve --param scan=full
./forensic.py --cli blockmap --param block=1074732
./forensic.py --cli report
```

`--param KEY=VALUE` may be repeated. Run a module without its required parameter
and it tells you which one is missing. `find_string` in particular needs
something to search for:

```bash
./forensic.py --cli find_string --param text=nazwisko --param limit=50
```

## Configuration

`config.toml` is created on first run, next to the data, and holds the image
path, mount point, work directory, EDL directory, case name, language and the
reveal switch:

```toml
image = "/path/to/userdata.img"
mountpoint = "/mnt/forensic"
workdir = "/path/to/work"
edl_dir = "/path/to/edl"
case = "redmi3"
lang = "pl"
```

`image` and `edl_dir` are **empty in a fresh checkout** — a repository must not
carry a path to somebody else's evidence. Fill them in here, or pass `--image`
and `--edl-dir` per invocation. `case` defaults to `default`; the case file for
the reference device is `redmi3`.

Any of it can be overridden per invocation with `--image`, `--mountpoint`,
`--workdir`, `--edl-dir`, `--case` and `--lang`.

## Modules

37 modules in six categories. Each one reads the image, writes its findings to
the work directory and prints a summary; none of them writes to the image.

**`mount_ro` is the exception, and it is worth knowing why.** Every other module
reads the image with this project's own ext4 parser
(`forensic/core/ext4.py`), which is why the whole toolkit works as an ordinary
user with no privileges at all. `mount_ro` hands the image to the *kernel*
instead, which makes it the one place where untrusted data is parsed by code that
was not written for this job. It therefore needs root or passwordless sudo, and
it mounts with `ro,loop,norecovery,nodev,nosuid,noexec` — the three extra flags
cost a read-only mount nothing and close the ways a mounted evidence image could
be used against the machine examining it. Leave it off unless you need a second
opinion from the kernel's own view; `ext4_selftest` and `decoder_audit` give you
cross-checks without root.

### Image and file system

| module | what it gives you |
|---|---|
| `image_info` | superblock, geometry, feature flags, filesystem state, UUID, SHA-256, partition table detection, extended-attribute census |
| `mount_ro` | optional read-only mount of the image, unmounted automatically afterwards |
| `fs_check` | consistency check (`e2fsck -fn`); never repairs |
| `tsk_crosscheck` | a second opinion from The Sleuth Kit: geometry, file tree, inode metadata, file contents byte for byte, and what it sees that this tool does not |
| `ext4_selftest` | builds ext2/ext4 images and checks the reader against them, so a volume family the reader mishandles shows up as a refusal rather than as wrong data |
| `blockmap` | image byte offset → owning file and offset within it, in both directions |
| `find_string` | search the whole image for a string, with offsets, hexdump and the file that owns the hit |
| `extract_file` | copy a file out of the image, together with its `-wal`, `-journal` and `-shm` companions, into a manifest |
| `sqlite_info` | database header, integrity check, tables, row counts, companion files |
| `deleted_files` | inodes with a deletion timestamp: what was deleted, when, how large — and why the bytes are out of reach |
| `free_space` | unallocated block space: size, how many runs, how long the longest gap, how much of it is not zeros |
| `carve` | names of deleted files from directory blocks, plus content candidates from unallocated space, graded by how far each was validated |

### Accounts and credentials

| module | what it gives you |
|---|---|
| `accounts_db` | device accounts, the stored credential per authenticator, token expiry timestamps |
| `authtoken_journal` | OAuth2 tokens recovered from a rollback journal whose header was wiped |
| `login_data` | browser password store, plus a verdict on whether a stored blob is genuinely encrypted or merely opaque |
| `cookies_webview` | cookie stores, session cookies that are readable in the clear, Facebook session cookies decoded |
| `chrome_history` | URLs, visits, browsing sessions, typed queries, account identifiers appearing in URLs |
| `pin_recovery` | lock-screen settings: salt, key format, and an offline PIN search |

### Applications

| module | what it gives you |
|---|---|
| `messenger` | which store still holds the message text, saved accounts, E2EE identity and auth token |
| `whatsapp` | message store, account data, Signal session state, keystore keys that are missing — and the fact that there is no password mechanism to attack |
| `fb_tokens` | Facebook access tokens from every store the app keeps them in, with unrelated base64 noise separated out |
| `snapchat` | an app that left almost nothing: Play Store record, system backup, gallery history, empty media directory |
| `app_install_timeline` | application install and update timeline, joined against usage records and against what is actually on disk |

### Timeline and session

| module | what it gives you |
|---|---|
| `fs_timeline` | every file written after a cut-off: the write session, its bursts, crash dumps, the last writes before shutdown |
| `login_timeline` | last authentication *and* last activity per account, from token grants, application markers and store logs |
| `unlock_proof` | proof the device was unlocked, the lock state, and whether the credential changed |
| `session_system` | the system side of the session: crash history, kernel restarts, process snapshots, traffic counters, debug logs |
| `net_state` | whether the device had a network: DHCP lease, traffic counters, push-service state, token age |
| `wifi_creds` | saved networks and WPA keys from both stores Android keeps them in, compared |
| `clock_anomaly` | which timestamps can be trusted: filesystem-epoch artefacts, installer constants, coherent date ranges |
| `mactime_export` | the image as a body file, the inventory format every timeline tool reads |

### Tools

| module | what it gives you |
|---|---|
| `edl_acquire` | read plan for the external acquisition toolchain: partition geometry and the exact command line |
| `find_string` | see above — full-image search with owner attribution |
| `mount_ro` | see above — optional read-only mount |

### Report and verification

| module | what it gives you |
|---|---|
| `report` | builds the document: image, verdicts with evidence, accounts table, secrets found, last session, date reliability, sources and missing sources |
| `verify` | runs a case file and compares the findings against values confirmed beforehand |
| `newcase` | writes a case for an unfamiliar image, with the checks left as `TODO` so the first verification reports what is missing |
| `secret_audit` | scans every artefact for credentials in the clear, and checks the masking policy actually held |
| `decoder_audit` | checks the hand-written parsers against reference implementations, so their output is not merely self-consistent |

## A typical session

Work through the categories in order. Each module reads the image and adds its
findings to the case; nothing has to be repeated.

```bash
./install.sh
./forensic.py --preflight
./forensic.py --image /path/to/userdata.img --case redmi3
```

1. **Image and file system** — start with `image_info` to get the geometry, then
   `fs_check` for consistency. `tsk_crosscheck` if you want a second reader's
   opinion before you rely on the first one.
2. **Accounts and credentials** — `accounts_db`, `login_data`, `cookies_webview`,
   `chrome_history`. This is where you learn whose device it was.
3. **Applications** — the modules for the apps that matter on the case. A module
   that finds nothing still reports *that* it found nothing, which is a finding.
4. **Timeline and session** — `unlock_proof`, `login_timeline`, `fs_timeline`,
   `net_state`, `wifi_creds`, `clock_anomaly`. This is where you learn when the
   device was last in use and whether the dates can be believed.
5. **Deleted data** — `deleted_files`, `free_space`, `carve`, and `find_string`
   when you know what to look for.
6. **Report** — `report` assembles everything into
   `work/<case>/reports/report.md`, and `verify` re-reads the image and checks the
   findings against the case file.

`edl_acquire` fits before step 1 if the image still has to be acquired from a
device in EDL mode; it plans the read rather than performing it.

Secrets are masked in every output. Press `m` in the menu, or start with
`--reveal`, to see them in the clear — and `secret_audit` afterwards will tell you
which artefacts still contain them.

## Case files and verification

A case is a JSON file describing the image plus a list of checks. Each check runs
one module and asserts values against its findings, so a rerun on the same image
has to reproduce the same numbers:

```json
{ "path": "data.geometry.block_size", "equals": 4096 }
{ "path": "#0.size", "equals": 282624 }
{ "path": "lookups.0.path", "equals": "/data/…/Login Data" }
```

`data.` addresses the module's structured payload, a bare key is looked up across
all findings, and `#N` pins the lookup to the N-th finding. Operators:
`equals`, `contains`, `not_contains`, `matches`, `gte`, `lte`, `in`, `tolerance`.

```bash
./forensic.py --cli newcase --param name=xyz      # cases/xyz.public.json
./forensic.py --cli verify --param scope=image     # image and file system
./forensic.py --cli verify --param scope=accounts  # accounts and credentials
./forensic.py --cli verify --param scope=apps      # applications and acquisition
./forensic.py --cli verify --param scope=timeline  # timeline, session, network, clock
./forensic.py --cli verify --param scope=full      # everything, plus the local case
```

One check, `apps.edl_acquire`, reads the external EDL toolchain and therefore
needs `--edl-dir`; a checkout ships no path to it. Everything else runs on the
image alone.

`cases/<case>.local.json` sits next to the public one and is not tracked, so
checks *about* secrets can stay out of version control. `scope=full` includes it.

**The committed case file carries no personal data.** Where a value identifies a
person — an account UID, a profile name, a phone number, a JID, an e-mail
address — the public file pins the *shape* of the value with a `matches`
assertion, and the exact value lives in `cases/<case>.local.json` under
`scope=full`. So the public case still fails when a module starts returning a
malformed account id, and the true value is still regression-tested on the
machine that holds the case:

```json
{ "path": "data.prefs.accounts.1.uid", "matches": "^[0-9]{15}$" }
{ "path": "data.play.found.0.account", "matches": "^[^\\s@]+@[^\\s@]+\\.[A-Za-z]{2,}$" }
```

## Tests

```bash
pip install pytest
apt install e2fsprogs          # the ext4 self-test builds its own images
python -m pytest tests/ -q
```

`tests/` covers the SQLite URI escaping, the `shared_prefs` XML parser, the
extracted-file naming, the configuration defaults, and the carver's validators.
`tests/test_ext4_selftest.py` calls the `ext4_selftest` module itself, so the
self-test you can run from the menu is the same code the test suite runs. CI runs
`ruff check`, `mypy forensic/core` (blocking) and `pytest`; `mypy forensic` over
the whole package is reported but does not fail the build yet.

## Where the results are

Everything is written under `work/<case>/`, never inside the image and never
inside the installed package:

```
work/<case>/
  exports/     findings as JSON and CSV, one file per module
  reports/     report.md — the assembled document
  extracted/   files copied out of the image, with extract_manifest.json
  acquire/     acquisition plan, outcome and hashes.csv
  cache/       block index and other rebuildable data
  session.json accumulated findings, mode 0600
  secrets.json registry of every secret the tool handled, mode 0600
```

Two integrity manifests exist and they cover different ground:
`acquire/hashes.csv` is what was *acquired*, `exports/extract_manifest.json` is
what was *extracted for analysis*. A file can appear in both, and the report
names both so nothing is counted twice.

Findings accumulate in `session.json` across runs, so a report can be built over
several sittings rather than in one.

## Formats and limits

| format | what you get |
|---|---|
| ext2/3/4 | full read: tree, metadata, file contents, extended attributes |
| F2FS | full read: tree, metadata, uncompressed file contents. Refused with a reason for encrypted volumes, compressed files and files above roughly 7.9 GiB |
| EROFS | tree, metadata and uncompressed contents. Contents of compressed files are refused with the reason |
| squashfs | identified and refused |

When a volume cannot be read, the message names the format. "This is EROFS, which
this tool does not read" and "this file is compressed, so its contents are not
available" are answers; "unsupported" is not, because it sends the analyst
looking for a problem that is not there.

Other limits worth knowing before you rely on a result:

* An encrypted WhatsApp backup is reported as encrypted, with its version and
  header read without the key. The payload stays closed and the report says so.
* Content carved out of unallocated space is graded: `validated` when the
  structure behind it was walked or checksummed, `magic` when only the signature
  is present, `weak` otherwise, and `truncated` when the data ran out. A
  candidate is never a recovered file, and nothing pairs a carved name with a
  carved candidate.
* A deleted file's declared size is reported, but ext4 drops the block map on
  unlink, so its content is not reachable through the inode. Carving is the only
  route, and the report distinguishes the two.
* Times are normalised to UTC and the assumed source unit is reported, because
  applications mix seconds, milliseconds and microseconds-since-1601 within a
  single file.

## Acquisition

`edl_acquire` plans the acquisition; it does not perform it. It produces the
partition geometry from the programmer XML and the exact command line for the
external toolchain, dry-run by default, and the job model has no verb that can
express a write, an erase or a patch — a wrong parameter cannot become a
destructive action. Running the read for real requires both `dry_run=false` and
`confirm=true`.

Every run leaves three files under `work/<case>/acquire/`:

| file | what it answers |
|---|---|
| `edl_<label>.json` | what was asked for: plan, geometry, arguments |
| `acquisition.json` | what happened: `planned` / `completed` / `partial` / `failed`, timings, producer |
| `hashes.csv` | what is held: name, source, SHA-256, size, timestamp |

The four states are derived from what actually happened rather than declared by
the caller. The case that matters is a read that fails but leaves a file of the
planned size: by size alone that looks complete, and it is reported as `partial`.

The toolchain itself (`edlclient`) is a separate project and is not part of this
one. It is invoked as an external program, not imported, and `--preflight`
reports whether it is present and whether a known local fix to its sector-reading
code is applied.

## Licence

**GPL-3.0-or-later.** The full text is in [`LICENSE`](LICENSE); every source
file carries an SPDX header saying so, and `pyproject.toml` declares the same
expression, so the licence travels with a built wheel rather than only living in
this file.

This is the project's own code. The tools it depends on stay outside it:

* **The Sleuth Kit** is GPL-3.0 as well, and is *invoked as a separate process*
  by `tsk_crosscheck` and by the `carve` cross-check — its sources are never
  vendored here and no line of them is copied. That is the whole reason the
  cross-check layer shells out instead of linking.
* **`edlclient`** is external, and is used the same way.
* Format knowledge came from reading specifications and from the behaviour of
  the tools, not from copying their code. Nothing under `tsk-sources/` or
  `sleuthkit*/` is ever committed, and `.gitignore` keeps it that way.

If you fork this, keep the headers: they are what makes the licence travel with
a file rather than with a repository.

## Layout

```
forensic.py              launcher
forensic/cli.py          argument parsing, frontend selection
forensic/controller.py   session lifecycle, module dispatch
forensic/core/           filesystem readers, SQLite, Chromium, AOSP, timeline,
                         secrets, reporting, config, i18n
forensic/modules/        one module per task
forensic/ui/             menu, curses frontend, shared rendering
forensic/verify/         case runner
forensic/acquisition/    preflight, read-plan builder
cases/                   case files; *.local.json stays untracked
work/<case>/             results, see above
```

`CHANGELOG.md` records what changed between versions.
