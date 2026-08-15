#!/usr/bin/env bash
# Robust stop/start/restart/status for the shild-py bot process --
# written 2026-08-10 after `sudo systemctl stop shildpy.service`
# silently did nothing (TWICE) because the actually-running process was
# a manually-started `nohup` instance systemd never knew about.
#
# ROOT CAUSE (found while fixing this the second time): scripts/
# daily_checkin.sh's own restart-if-not-running logic (see its header
# comment) uses a manual `nohup supybot shildpy.conf &`, NOT `systemctl
# start` -- because this server has no passwordless sudo for systemctl
# (see CLAUDE.md), and an unattended cron job has no interactive
# terminal for sudo to prompt on. So every single time the 08:00 cron
# fires while the bot happens to be down, it silently re-creates the
# exact "process running outside systemd's supervision" state that
# makes a later `systemctl stop` a no-op. This is not a one-off mistake
# -- it will keep happening as long as daily_checkin.sh exists in its
# current form, so the fix here is a script that works correctly
# EITHER way, rather than trying to eliminate the manual-start path
# entirely (which would require passwordless sudo, a real security
# tradeoff -- see the "repair this properly" note at the bottom).
#
# `stop`/`restart` NEVER trust systemctl's state alone: they always
# cross-check the real process table via `pgrep -f "supybot shildpy.conf"`
# and kill directly (no sudo needed -- the process is owned by the
# invoking user, not root) regardless of what systemd thinks. `start`
# tries `sudo -n systemctl start` first (non-interactive: fails
# instantly with a clear message if no cached/passwordless sudo,
# confirmed 2026-08-10 -- never hangs waiting on a password prompt),
# falling back to the same manual nohup daily_checkin.sh uses, but
# ALWAYS says out loud which path it took so "is this systemd-managed
# right now" is never a mystery again.
#
# Usage:
#   scripts/botctl.sh status
#   scripts/botctl.sh stop
#   scripts/botctl.sh start
#   scripts/botctl.sh restart
set -uo pipefail

SHILD_PY="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="$SHILD_PY/runtime"
PROC_PATTERN="supybot shildpy.conf"

_pids() { pgrep -f "$PROC_PATTERN" || true; }

_status() {
    echo "--- systemd's view ---"
    systemctl status shildpy.service --no-pager 2>&1 | head -5
    echo "--- real process table ---"
    local pids
    pids=$(_pids)
    if [ -n "$pids" ]; then
        echo "running: PID(s) $pids"
        ps -o pid,etimes,cmd -p $(echo "$pids" | tr '\n' ',' | sed 's/,$//')
    else
        echo "not running"
    fi
}

_stop() {
    local pids
    pids=$(_pids)
    if [ -z "$pids" ]; then
        echo "Not running (nothing found in the real process table)."
        # Still tell systemd, in case its own bookkeeping disagrees --
        # harmless either way, best-effort, never blocks on this.
        sudo -n systemctl stop shildpy.service >/dev/null 2>&1 || true
        return 0
    fi

    echo "Found real process(es): $pids"
    echo "Trying 'sudo systemctl stop' first (best-effort, non-interactive)..."
    if sudo -n systemctl stop shildpy.service 2>&1; then
        echo "systemctl stop succeeded."
    else
        echo "systemctl stop unavailable/no-op here (expected if this instance"
        echo "isn't systemd-managed, or no cached sudo) -- killing directly instead."
    fi

    # ALWAYS re-check and kill directly, regardless of what systemctl
    # reported -- this is the actual fix: never trust systemd's state
    # as the sole source of truth for "is it still running."
    pids=$(_pids)
    if [ -n "$pids" ]; then
        echo "Sending SIGTERM to: $pids"
        echo "$pids" | xargs -r kill
        sleep 3
        pids=$(_pids)
        if [ -n "$pids" ]; then
            echo "Still alive after SIGTERM, sending SIGKILL to: $pids"
            echo "$pids" | xargs -r kill -9
            sleep 1
        fi
    fi

    pids=$(_pids)
    if [ -n "$pids" ]; then
        echo "ERROR: still running after stop attempt: $pids" >&2
        return 1
    fi
    echo "Confirmed stopped."
}

_start() {
    local pids
    pids=$(_pids)
    if [ -n "$pids" ]; then
        echo "ERROR: already running (PID $pids) -- refusing to start a second" >&2
        echo "instance (see daily_checkin.sh's header comment for why: two" >&2
        echo "instances fighting over the same nick caused a real Libera G-line" >&2
        echo "on 2026-08-03). Run 'stop' first if you really want to restart." >&2
        return 1
    fi

    echo "Trying 'sudo systemctl start' first (best-effort, non-interactive)..."
    if sudo -n systemctl start shildpy.service 2>&1; then
        sleep 3
        if [ -n "$(_pids)" ]; then
            echo "Started under systemd. PID $(_pids)"
            return 0
        fi
        echo "systemctl reported success but no process found -- falling back."
    else
        echo "systemctl start unavailable here (expected without cached/passwordless"
        echo "sudo, e.g. from cron or this harness) -- falling back to manual start."
    fi

    echo "Starting manually (nohup) -- NOT under systemd supervision. Run"
    echo "'sudo systemctl start shildpy.service' yourself later (from a real"
    echo "terminal) to bring this instance under systemd, or it'll need this"
    echo "same manual-fallback path again next time it needs restarting."
    cd "$RUNTIME_DIR" || return 1
    # Full interpreter path, NOT bare `supybot` -- this script's own
    # caller (cron, this harness's Bash tool, a fresh non-interactive
    # shell) has no guarantee the venv is sourced, and `supybot` isn't on
    # PATH otherwise. Found live 2026-08-10: the bare-name version failed
    # silently (0-byte stdout.log, no process, no visible error) the
    # first time this fallback path was actually exercised end-to-end.
    nohup "$SHILD_PY/.venv/bin/supybot" shildpy.conf > stdout.log 2>&1 &
    disown
    sleep 3
    pids=$(_pids)
    if [ -z "$pids" ]; then
        echo "ERROR: manual start also failed -- check $RUNTIME_DIR/stdout.log" >&2
        return 1
    fi
    echo "Started manually. PID $pids"
}

case "${1:-}" in
    status)  _status ;;
    stop)    _stop ;;
    start)   _start ;;
    restart) _stop && _start ;;
    *)
        echo "Usage: $0 {status|stop|start|restart}" >&2
        exit 1
        ;;
esac
