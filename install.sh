#!/usr/bin/env sh
# Install the forensic toolkit and wire up the external EDL dependency.
#
#   ./install.sh                 install into .venv and check the environment
#   ./install.sh --no-venv       install into the current interpreter
#   ./install.sh --edl-dir=DIR   point at the external edlclient checkout
#   ./install.sh --apply-edl-patch   also apply the edl streaming.read_sectors fix
#
# The EDL toolchain is a plain external dependency, pointed at with --edl-dir or
# the EDL_DIR environment variable: this repository only links to its sources
# through a .pth file, nothing is copied and no file inside the toolchain is
# modified unless you ask for the patch.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
EDL_DIR="${EDL_DIR:-}"
PY="${PYTHON:-python3}"
USE_VENV=1
APPLY_PATCH=0

for arg in "$@"; do
    case "$arg" in
        --no-venv) USE_VENV=0 ;;
        --apply-edl-patch) APPLY_PATCH=1 ;;
        --edl-dir=*) EDL_DIR="${arg#--edl-dir=}" ;;
        -h|--help)
            sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) printf 'Nieznana opcja: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

say() { printf '\033[36m==>\033[0m %s\n' "$1"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$1"; }
die() { printf '\033[31m[x]\033[0m %s\n' "$1" >&2; exit 1; }

if [ "$USE_VENV" = "1" ]; then
    say "Tworzę virtualenv .venv"
    "$PY" -m venv "${HERE}/.venv"
    # shellcheck disable=SC1091
    . "${HERE}/.venv/bin/activate"
    PY="${HERE}/.venv/bin/python"
fi

"$PY" -m pip install --upgrade pip >/dev/null

say "Sprawdzam stdlib (bez zależności zewnętrznych)"
"$PY" - <<'EOF'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("wymagany Python >= 3.10")
import curses, sqlite3, tomllib, hashlib  # noqa: F401
print("   Python", sys.version.split()[0], "OK")
EOF

say "Instaluję pakiet forensic"
"$PY" -m pip install -e "$HERE" --quiet

if [ -n "$EDL_DIR" ] && [ -d "$EDL_DIR" ]; then
    say "Podłączam źródła edlclient z $EDL_DIR (bez kopiowania)"
    SITE="$("$PY" -c 'import site;print(site.getsitepackages()[0])')"
    printf '%s\n' "$EDL_DIR" > "${SITE}/edl-sources.pth"
    if [ -x "${EDL_DIR}/venv/bin/python" ]; then
        EXTRA_SITE="$("${EDL_DIR}/venv/bin/python" -c 'import site;print(site.getsitepackages()[0])' 2>/dev/null || true)"
        if [ -n "${EXTRA_SITE}" ]; then
            printf '%s\n' "${EXTRA_SITE}" > "${SITE}/edl-deps.pth"
        fi
    fi
    if [ "$APPLY_PATCH" = "1" ] && [ -f "${HERE}/acquisition/patches/edclient-streaming-read_sectors.patch" ]; then
        say "Nakładam łatkę streaming.read_sectors (za pytaniem)"
        printf 'Zastosować łatkę w %s ? [t/N] ' "$EDL_DIR"
        read -r reply
        case "$reply" in
            [tTyY1]*)
                (cd "$EDL_DIR" && patch -p1 --dry-run < "${HERE}/acquisition/patches/edclient-streaming-read_sectors.patch" \
                    && patch -p1 < "${HERE}/acquisition/patches/edclient-streaming-read_sectors.patch")
                ;;
            *) say "Pominięto" ;;
        esac
    fi
else
    warn "Brak katalogu EDL (${EDL_DIR:-nie podano}) — akwizycja EDL będzie niedostępna (analiza offline działa)"
fi

mkdir -p "${HERE}/cases" "${HERE}/work"
if [ ! -f "${HERE}/config.toml" ]; then
    say "Tworzę config.toml"
    "$PY" -c 'from forensic.core.config import ensure_config; print(ensure_config())'
fi

say "Preflight"
"$PY" "${HERE}/forensic.py" --preflight || true

cat <<'EOF'

Gotowe. Uruchomienie:

  ./forensic.py                     menu (lub curses TUI w terminalu)
  ./forensic.py --list              lista modułów
  ./forensic.py --preflight         check środowiska i zależności EDL
  ./forensic.py --cli verify        weryfikacja wyników (--case <nazwa>, --param scope=all|full)
  ./forensic.py --lang en           angielski interfejs
  ./forensic.py --reveal            pokaż sekrety w jawnej postaci

EOF
