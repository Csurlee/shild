#!/usr/bin/env bash
# shild-py installer -- fetches the repo, sets up a venv, runs the
# interactive setup wizard, and generates the Limnoria config.
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/Csurlee/shild/main/install.sh)"
#
# Deliberately thin: its only job is to get to a working Python venv and
# hand off to scripts/install_wizard.py (the actual interactive logic) and
# scripts/bootstrap_runtime.py (the actual config generator). Every real
# decision lives in those two Python scripts, which are tested; this file
# is just plumbing, kept short enough to read before you run it -- which
# you should, especially for anything piped into `bash`.
#
# Flags:
#   --dir PATH         Install into PATH instead of ~/shild (default).
#   --branch NAME       Clone this branch/tag instead of the default.
#   --with-training      Also install torch (CPU wheel) for shildml.train.
#   --non-interactive      Skip the wizard; requires PATH/runtime/install.json
#                            to already exist (e.g. copied in beforehand).
#   --dry-run                Print what would happen; touch nothing.
#   -h, --help                 Show this help.
#
# Never run this (or anything) as `curl | sudo bash`. It never invokes
# sudo itself except to install ONE named system package, and only after
# printing the exact command and asking first.
set -euo pipefail

REPO_URL="https://github.com/Csurlee/shild.git"
INSTALL_DIR="$HOME/shild"
BRANCH=""
WITH_TRAINING=0
NON_INTERACTIVE=0
DRY_RUN=0

usage() {
    sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dir) INSTALL_DIR="$2"; shift 2 ;;
        --branch) BRANCH="$2"; shift 2 ;;
        --with-training) WITH_TRAINING=1; shift ;;
        --non-interactive) NON_INTERACTIVE=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

run() {
    if [ "$DRY_RUN" = "1" ]; then
        echo "+ $*"
    else
        "$@"
    fi
}

say() { echo "==> $*"; }

# --------------------------------------------------------------------
# 1. Preflight
# --------------------------------------------------------------------
# Note on scope: this installs Limnoria itself (the IRC bot framework
# shild's plugins run under), NOT just shild's own code -- via
# `pip install -e ".[bot]"` in section 3 below, which pulls the
# `limnoria` package as a pinned dependency (see pyproject.toml's `bot`
# extra). Everything lands inside this install's own .venv, never a
# system-wide Limnoria package, so it can't collide with anything else
# on the box and always matches the exact version shild's plugins were
# tested against.
say "Checking prerequisites..."

# Try newest-first so a distro that ships an old default `python3` (e.g.
# Ubuntu 22.04's 3.10) but also offers an installable newer interpreter
# (python3.11/3.12/3.13, common on Debian/Ubuntu/Fedora/openSUSE/Arch)
# still works without the user having to know which binary to name.
PYTHON_BIN=""
for candidate in python3.13 python3.12 python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1; then
        ver_ok=$("$candidate" -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)' 2>/dev/null || echo 0)
        if [ "$ver_ok" = "1" ]; then
            PYTHON_BIN="$candidate"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo "No Python 3.11+ interpreter found (checked python3.13, python3.12, python3.11, python3)." >&2
    echo "Install one via your distro's package manager, then re-run:" >&2
    echo "  Debian/Ubuntu:    sudo apt install python3.12 python3.12-venv" >&2
    echo "  Fedora/RHEL/Rocky: sudo dnf install python3.12" >&2
    echo "  Arch/Manjaro:      sudo pacman -S python" >&2
    echo "  openSUSE:          sudo zypper install python312" >&2
    echo "  Alpine:            sudo apk add python3" >&2
    exit 1
fi
PY_VERSION=$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')
say "Using $PYTHON_BIN ($PY_VERSION)"

# Detect the system package manager -- covers, in order, Debian/Ubuntu
# and derivatives (apt), Fedora/current RHEL/Rocky/Alma (dnf), older
# RHEL/CentOS 7 (yum), Arch/Manjaro (pacman), openSUSE (zypper), and
# Alpine (apk). Each needs a different name for "give me venv support
# for this specific Python" (or, on several of them, venv is already
# bundled with the interpreter package and there's nothing extra to
# install at all) -- PKG_VENV is intentionally left blank in those
# cases rather than guessing a package name that doesn't exist.
PKG_MANAGER=""
PKG_INSTALL=""
PKG_VENV=""
PY_MINOR="${PY_VERSION#*.}"
if command -v apt >/dev/null 2>&1; then
    PKG_MANAGER="apt"; PKG_INSTALL="sudo apt install -y"
    PKG_VENV="${PYTHON_BIN}-venv"   # Debian/Ubuntu split venv out per-version
elif command -v dnf >/dev/null 2>&1; then
    PKG_MANAGER="dnf"; PKG_INSTALL="sudo dnf install -y"   # venv bundled in python3
elif command -v yum >/dev/null 2>&1; then
    PKG_MANAGER="yum"; PKG_INSTALL="sudo yum install -y"   # venv bundled in python3
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"; PKG_INSTALL="sudo pacman -S --needed --noconfirm"   # bundled
elif command -v zypper >/dev/null 2>&1; then
    PKG_MANAGER="zypper"; PKG_INSTALL="sudo zypper install -y"   # bundled
elif command -v apk >/dev/null 2>&1; then
    PKG_MANAGER="apk"; PKG_INSTALL="sudo apk add"
    PKG_VENV="py3-virtualenv"   # Alpine's python3 package doesn't bundle venv
fi

MISSING_PKGS=()
command -v git >/dev/null 2>&1 || MISSING_PKGS+=("git")
command -v curl >/dev/null 2>&1 || MISSING_PKGS+=("curl")
if ! "$PYTHON_BIN" -c "import venv" >/dev/null 2>&1 && [ -n "$PKG_VENV" ]; then
    MISSING_PKGS+=("$PKG_VENV")
fi

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    say "Missing: ${MISSING_PKGS[*]}"
    if [ -z "$PKG_MANAGER" ]; then
        echo "Couldn't detect a supported package manager (apt/dnf/yum/pacman/zypper/apk)." >&2
        echo "Please install manually: ${MISSING_PKGS[*]}" >&2
        exit 1
    fi
    CMD="$PKG_INSTALL ${MISSING_PKGS[*]}"
    echo "About to run:"
    echo "    $CMD"
    read -r -p "Proceed? [y/N] " REPLY
    case "$REPLY" in
        [yY]*) run bash -c "$CMD" ;;
        *) echo "Aborted -- install the package(s) above yourself and re-run." >&2; exit 1 ;;
    esac
fi

# --------------------------------------------------------------------
# 2. Fetch
# --------------------------------------------------------------------
if [ -d "$INSTALL_DIR/.git" ]; then
    say "Existing checkout found at $INSTALL_DIR -- updating."
    run git -C "$INSTALL_DIR" fetch origin
    if [ -n "$BRANCH" ]; then
        run git -C "$INSTALL_DIR" checkout "$BRANCH"
        run git -C "$INSTALL_DIR" pull origin "$BRANCH"
    else
        run git -C "$INSTALL_DIR" pull
    fi
elif [ -d "$INSTALL_DIR" ] && [ -f "$INSTALL_DIR/pyproject.toml" ]; then
    say "Found an existing (non-git) checkout at $INSTALL_DIR -- using it as-is."
elif [ -d "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]; then
    # INSTALL_DIR exists and has something in it (e.g. a pre-seeded
    # runtime/install.json for --non-interactive, per this script's own
    # documented flow above) but isn't a real checkout yet -- `git clone`
    # refuses to clone into any non-empty directory regardless of what's
    # in it, so clone into a temp dir first and merge the repo tree in
    # without touching what's already there.
    say "Cloning into a temp dir and merging into existing $INSTALL_DIR..."
    TMP_CLONE=$(mktemp -d)
    if [ -n "$BRANCH" ]; then
        run git clone --branch "$BRANCH" "$REPO_URL" "$TMP_CLONE"
    else
        run git clone "$REPO_URL" "$TMP_CLONE"
    fi
    if [ "$DRY_RUN" != "1" ]; then
        cp -a "$TMP_CLONE/." "$INSTALL_DIR/"
        rm -rf "$TMP_CLONE"
    fi
else
    say "Cloning into $INSTALL_DIR..."
    if [ -n "$BRANCH" ]; then
        run git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    else
        run git clone "$REPO_URL" "$INSTALL_DIR"
    fi
fi

if [ "$DRY_RUN" = "1" ] && [ ! -d "$INSTALL_DIR" ]; then
    say "(dry run: $INSTALL_DIR doesn't exist yet, stopping here -- everything past this point would run inside it)"
    exit 0
fi
cd "$INSTALL_DIR"

# --------------------------------------------------------------------
# 3. Venv + dependencies
# --------------------------------------------------------------------
say "Setting up the virtual environment ($PYTHON_BIN)..."
if [ ! -d .venv ]; then
    run "$PYTHON_BIN" -m venv .venv
fi
# shellcheck disable=SC1091
if [ "$DRY_RUN" != "1" ]; then
    source .venv/bin/activate
fi

say "Installing shild + Limnoria (the IRC bot framework) into the venv..."
say "(this does NOT install torch by default -- pass --with-training if you want it)"
run pip install --upgrade pip
run pip install -e ".[bot]"

if [ "$DRY_RUN" != "1" ]; then
    if ! python -c "import supybot" >/dev/null 2>&1; then
        echo "Limnoria (supybot) failed to import after install -- something went wrong above." >&2
        exit 1
    fi
    say "Limnoria installed: $(python -c 'import supybot.conf as conf; print(conf.version)')"
fi

if [ "$WITH_TRAINING" = "1" ]; then
    say "Installing torch (CPU wheel) for shildml.train..."
    run pip install torch --index-url https://download.pytorch.org/whl/cpu
fi

# --------------------------------------------------------------------
# 4. Configure
# --------------------------------------------------------------------
mkdir -p runtime
if [ "$NON_INTERACTIVE" = "1" ]; then
    if [ ! -f runtime/install.json ]; then
        echo "--non-interactive given but runtime/install.json is missing." >&2
        echo "Copy one in first (see docs/INSTALL.md for the schema)." >&2
        exit 1
    fi
    say "Non-interactive: using existing runtime/install.json as-is."
else
    say "Running the setup wizard..."
    run python scripts/install_wizard.py
fi

# --------------------------------------------------------------------
# 5. Generate the Limnoria config
# --------------------------------------------------------------------
say "Generating runtime/shildpy.conf..."
run python scripts/bootstrap_runtime.py

# --------------------------------------------------------------------
# 6. Optional systemd unit
# --------------------------------------------------------------------
if [ "$DRY_RUN" != "1" ] && [ "$NON_INTERACTIVE" != "1" ]; then
    read -r -p "Install a systemd service so shild starts on boot? [y/N] " REPLY
    case "$REPLY" in
        [yY]*)
            UNIT_PATH="/etc/systemd/system/shild.service"
            TMP_UNIT=$(mktemp)
            sed \
                -e "s#__INSTALL_DIR__#$INSTALL_DIR#g" \
                -e "s#__USER__#$(whoami)#g" \
                contrib/shild.service.template > "$TMP_UNIT"
            echo "About to run:"
            echo "    sudo cp $TMP_UNIT $UNIT_PATH && sudo systemctl daemon-reload && sudo systemctl enable shild"
            read -r -p "Proceed? [y/N] " REPLY2
            case "$REPLY2" in
                [yY]*)
                    sudo cp "$TMP_UNIT" "$UNIT_PATH"
                    sudo systemctl daemon-reload
                    sudo systemctl enable shild
                    say "Installed. Start with: sudo systemctl start shild"
                    ;;
                *) say "Skipped -- use scripts/botctl.sh to start/stop instead." ;;
            esac
            rm -f "$TMP_UNIT"
            ;;
        *) say "Skipped -- use scripts/botctl.sh to start/stop instead." ;;
    esac
fi

# --------------------------------------------------------------------
# 7. Summary
# --------------------------------------------------------------------
cat <<EOF

=== Done ===

  Start:    cd $INSTALL_DIR && scripts/botctl.sh start
  Status:   scripts/botctl.sh status
  Panel:    (if enabled) http://<bind-address>:<port>/panel/

Manual steps this script cannot do for you:
  - Register the bot's nick with each network's services (NickServ/X) and
    grant it channel op -- see docs/INSTALL.md's "Getting the bot opped".
  - Add any API keys you skipped in the wizard to runtime/secrets.json
    later -- see runtime/secrets.json.example for what each one unlocks.

No classifier model is bundled. Shild's DNSBL/reputation evidence gate
and SpamGuard both work fully without one; train your own once you have
real shadow-mode data (scripts/install with --with-training, then see
docs/SHILD.md's "Working with the classifier").
EOF
