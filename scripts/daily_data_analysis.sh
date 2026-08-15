#!/usr/bin/env bash
# Scheduled qualitative review of the day's shadow data, via a headless
# Claude Code session -- installed as a local cron job (see CLAUDE.md's
# "Automated daily check-in" section for why this must run locally, not
# as a cloud routine: it needs the real, local data/shadow_decisions.jsonl).
#
# Added 2026-08-06 when Ollama was turned off (plugins/Shild/config.py's
# ollama.enabled): Ollama never once produced an acting decision across
# 4,479 shadow rows and was the dominant cause of unusable data, so this
# replaces "live LLM second opinion" with "scheduled deeper read" instead
# -- not real-time protection, but a way to catch what a same-day human
# (or op) might otherwise miss, one day later.
#
# Deliberately narrow blast radius for an UNATTENDED run: the invoked
# session gets Read + Write only (no Bash, no Edit, no git, no service
# control) and can write exactly one report file. scripts/daily_data_summary.py
# does the actual data crunching in plain, deterministic Python first --
# the agent's only job is the part a script can't do: judging whether a
# near-miss/repeat-host candidate actually looks concerning, in plain
# English, for a human to act on.
set -uo pipefail

SHILD_PY=/home/Csurlee/shild
LOG="$SHILD_PY/runtime/daily_checkin.log"
OUT_DIR="$SHILD_PY/runtime/daily_analysis"
DATE_TAG=$(date -u +'%Y-%m-%d')
SUMMARY_JSON="$OUT_DIR/${DATE_TAG}-summary.json"
REPORT_MD="$OUT_DIR/${DATE_TAG}-report.md"

log() { echo "$(date -u +'%Y-%m-%dT%H:%M:%SZ') $*" >> "$LOG"; }

mkdir -p "$OUT_DIR"
cd "$SHILD_PY" || exit 1
source .venv/bin/activate

log "=== daily data analysis start ==="

python scripts/daily_data_summary.py --data data/shadow_decisions.jsonl \
    --hours 24 --out "$SUMMARY_JSON" >> "$LOG" 2>&1

PROMPT="Read $SUMMARY_JSON (a pre-computed summary of the last 24h of
shild-py's shadow_decisions.jsonl -- action/source/degraded-reason
distributions, and the top near-miss classifier reads by raw p_ban/p_warn
probability, each with nick/host/ident/channel/network/account).

Your job: write a report to $REPORT_MD using EXACTLY this structure (the
live bot parses the '## Flagged hosts' section verbatim to build the
one-line IRC announcement and the !shildreport reply -- an unrecognized
format falls back to a generic excerpt, so stick to it precisely):

# Shild daily review -- <date>

## Flagged hosts
One line per host that plausibly needs a human's attention, in EXACTLY
this format (the leading '- FLAG:' is a literal parse token, keep it as
written, one host per line, most concerning first):
- FLAG: <host> (<nick>) -- <one-sentence reason a human should look>
If nothing today looks concerning, write exactly one line:
- FLAG: none
Be conservative: only flag something you would actually want a human to
look at today, not every near-miss in the summary. A trusted user/*
cloak or registered account should almost never be flagged -- see
CLAUDE.md's 'Trust bypass' section for why that pattern already burned us
once with Ollama (classifier twitchiness on an otherwise-ordinary user,
not real risk). Explain those in the next section instead of flagging
them.

## Volume and health
2-3 sentences: row count, degraded rate, channel split.

## Why the rest weren't flagged
Of the remaining near-miss candidates (top_near_miss_ban/top_near_miss_warn)
and repeat_hosts that did NOT make the Flagged hosts list, explain briefly
why -- e.g. a trusted cloak/account, or a nick-shape pattern the classifier
is known to be twitchy about. Name specific nick/host pairs, don't just
repeat the raw numbers.

## Operational notes
Anything else worth noting operationally (e.g. a channel/network with an
unusually high degraded rate, a repeat host appearing across multiple
days if you can tell from context) that is not itself a host to flag.

Read-only with respect to the live system: you have Read and Write tools
only. Do NOT attempt to run commands, edit code, touch git, or take any
enforcement action -- this is a report for a human to read, nothing more.
Write ONLY to $REPORT_MD."

claude -p "$PROMPT" \
    --allowedTools "Read Write" \
    --permission-mode bypassPermissions \
    --model sonnet \
    --max-budget-usd 1.00 \
    --output-format text \
    >> "$LOG" 2>&1
CLAUDE_EXIT=$?

if [ -f "$REPORT_MD" ]; then
    log "Report written: $REPORT_MD"
else
    log "WARNING: claude exited $CLAUDE_EXIT but $REPORT_MD was not created -- see log above for details"
fi

log "=== daily data analysis end ==="
