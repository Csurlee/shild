#!/usr/bin/env bash
# Daily health-check + retrain-when-ready for the shild-py bot.
# Installed as a local cron job (NOT a Claude Code cloud routine -- this
# needs direct access to the running Limnoria process and the local
# shadow data file, neither of which a cloud sandbox with its own fresh
# git checkout could see).
#
# Logs to runtime/daily_checkin.log. Does not notify anyone -- a human
# (or a future Claude session) reads the log when checking back in.
#
# Both Eggdrop bots are permanently retired (verified 2026-08-02: no
# processes, no pid files), so the comparison this script used to run
# against ~/eggdrop/logs/classifier_training.jsonl (scripts/compare_eggdrop.py)
# can never produce another matched event and has been removed. Validation
# is now scripts/gate_report.py's pre-gate-vs-post-gate A/B report (see
# Phase 1.5 plan) instead of an external ground truth, and the retrain
# threshold below is shadow-row volume alone.
set -uo pipefail

SHILD_PY=/home/Csurlee/shild
LOG="$SHILD_PY/runtime/daily_checkin.log"

# ~588 rows/day was observed historically on the (now-retired) Eggdrop
# side; ~1 week of shadow data is the same rough bar for a meaningful
# retrain here.
MIN_SHADOW_ROWS=4000

log() { echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') $*" >> "$LOG"; }

cd "$SHILD_PY" || exit 1
source .venv/bin/activate

log "=== daily check-in start ==="

# 1. Is the bot still running? Restart if not.
#
# Checked directly via pgrep against the real process table, NOT via a
# self-written runtime/shildpy.pid file -- the bot is now started by
# systemd (shildpy.service, added 2026-08-02) which never writes that
# file, so the old pid-file check always saw "not running" and launched
# a SECOND instance on top of the systemd-managed one every cron run.
# Confirmed as the actual cause of the 2026-08-03 Libera G-line: the two
# instances fought over the nick, GHOSTing/reconnecting/rejoining all
# channels repeatedly, which Libera's flood detector read as the client
# "flooding lots of channels". Never spawn a new instance here without
# checking the real process table first.
# 2026-08-10: delegates to scripts/botctl.sh instead of duplicating the
# manual-nohup-fallback logic inline. Root cause of a real, TWICE-
# repeated incident: this cron job has no interactive terminal for sudo
# to prompt on (no passwordless sudo configured), so it could never
# start the bot via `systemctl start` -- every time it fired while the
# bot happened to be down, IT was what silently converted a
# systemd-managed instance into a manually-started one, which is why a
# later `sudo systemctl stop shildpy.service` (run by a human, expecting
# it to work) kept silently doing nothing. botctl.sh's `start` still
# does the identical fallback (tries systemd first, non-interactively;
# falls back to nohup) -- the fix isn't a different restart mechanism,
# it's that the fallback is now the SAME well-logged, single place
# `stop`/`status` also know about, instead of a second copy of this
# logic living only here.
PID_FILE="$SHILD_PY/runtime/shildpy.pid"
RUNNING=0
EXISTING_PID=$(pgrep -f "supybot shildpy.conf" | head -1)
if [ -n "$EXISTING_PID" ]; then
    RUNNING=1
    PID="$EXISTING_PID"
    echo "$PID" > "$PID_FILE"
fi

if [ "$RUNNING" -eq 0 ]; then
    log "Bot not running -- restarting via scripts/botctl.sh start"
    BOTCTL_OUTPUT=$("$SHILD_PY/scripts/botctl.sh" start 2>&1)
    log "botctl.sh start output: $BOTCTL_OUTPUT"
    NEW_PID=$(pgrep -f "supybot shildpy.conf" | tail -1)
    echo "$NEW_PID" > "$PID_FILE"
    log "Restarted with PID $NEW_PID"
else
    log "Bot running (PID $PID)"
fi

# 2. Data volume.
SHADOW_ROWS=0
if [ -f data/shadow_decisions.jsonl ]; then
    SHADOW_ROWS=$(wc -l < data/shadow_decisions.jsonl)
fi
log "Shadow decisions collected: $SHADOW_ROWS (target: $MIN_SHADOW_ROWS)"

# 3. Gate A/B report -- how many decisions the evidence gate downgraded,
# by rule and evidence signal. This is the validation signal now that
# compare_eggdrop.py (Eggdrop-based) is retired -- see header comment.
GATE_OUTPUT=$(python scripts/gate_report.py --json 2>&1)
log "gate_report.py output: $GATE_OUTPUT"

# 4. Retrain once the shadow-row threshold is met -- see shildml/train.py's
# module docstring for why training on too little / leak-tainted data
# produces a model stamped deployable:false, which isn't useful to
# produce repeatedly.
if [ "$SHADOW_ROWS" -ge "$MIN_SHADOW_ROWS" ]; then
    log "Threshold met -- retraining on shadow data"
    RETRAIN_MTIME_BEFORE=""
    [ -f models/shild_v2_retrained.npz ] && RETRAIN_MTIME_BEFORE=$(stat -c %Y models/shild_v2_retrained.npz)
    TRAIN_OUTPUT=$(python -m shildml.train --data data/shadow_decisions.jsonl \
        --model models/shild_v2_retrained.npz 2>&1)
    log "train output: $TRAIN_OUTPUT"
    # train.py refuses (ValueError, no file written) when a class has too
    # few examples -- confirmed live 2026-08-06 (zero warn/ban examples in
    # the corpus so far). Only claim a model was written if its mtime
    # actually changed, so this log line stays trustworthy either way.
    RETRAIN_MTIME_AFTER=""
    [ -f models/shild_v2_retrained.npz ] && RETRAIN_MTIME_AFTER=$(stat -c %Y models/shild_v2_retrained.npz)
    if [ -n "$RETRAIN_MTIME_AFTER" ] && [ "$RETRAIN_MTIME_AFTER" != "$RETRAIN_MTIME_BEFORE" ]; then
        EVAL_OUTPUT=$(python -m shildml.evaluate --data data/shadow_decisions.jsonl \
            --model models/shild_v2_retrained.npz 2>&1)
        log "evaluate output: $EVAL_OUTPUT"
        log "NOTE: new model saved as models/shild_v2_retrained.npz, NOT auto-promoted to "
        log "shild_v2.npz (the live path) -- a human should review evaluate's per-class "
        log "metrics before swapping it in."
    else
        log "NOTE: train.py did not write a model this run (see train output above for why) -- "
        log "models/shild_v2_retrained.npz is unchanged, nothing to evaluate or review."
    fi
else
    log "Threshold not yet met -- no retrain this run"
fi

log "=== daily check-in end ==="
