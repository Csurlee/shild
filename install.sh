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
say "Checking prerequisites..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 not found. Install Python 3.11+ first." >&2
    exit 1
fi

PY_VERSION=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 11) else 0)')
if [ "$PY_OK" != "1" ]; then
    echo "python3 is $PY_VERSION; shild-py needs 3.11 or newer." >&2
    exit 1
fi
say "python3 $PY_VERSION OK"

MISSING_PKGS=()
command -v git >/dev/null 2>&1 || MISSING_PKGS+=("git")
command -v curl >/dev/null 2>&1 || MISSING_PKGS+=("curl")
if ! python3 -c "import venv" >/dev/null 2>&1; then
    MISSING_PKGS+=("python3-venv")
fi

if [ ${#MISSING_PKGS[@]} -gt 0 ]; then
    say "Missing: ${MISSING_PKGS[*]}"
    if command -v apt >/dev/null 2>&1; then
        CMD="sudo apt install -y ${MISSING_PKGS[*]}"
    elif command -v dnf >/dev/null 2>&1; then
        CMD="sudo dnf install -y ${MISSING_PKGS[*]/python3-venv/python3}"
    elif command -v pacman >/dev/null 2>&1; then
        CMD="sudo pacman -S --needed ${MISSING_PKGS[*]/python3-venv/python}"
    else
        echo "Please install manually: ${MISSING_PKGS[*]}" >&2
        exit 1
    fi
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
say "Setting up the virtual environment..."
if [ ! -d .venv ]; then
    run python3 -m venv .venv
fi
# shellcheck disable=SC1091
if [ "$DRY_RUN" != "1" ]; then
    source .venv/bin/activate
fi

say "Installing shild-py (this does NOT install torch by default)..."
run pip install --upgrade pip
run pip install -e ".[bot]"

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
