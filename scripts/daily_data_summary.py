"""Deterministic pre-pass for scripts/daily_data_analysis.sh -- computes
the boring, reliable numbers (counts, distributions, near-miss rankings)
in plain Python so the scheduled Claude Code session that reads this
doesn't have to re-derive them (or worse, get them wrong) and can spend
its budget on the part a script can't do: judging whether a repeat
near-miss host actually looks concerning.

This exists because Ollama was turned off 2026-08-06 (see
plugins/Shild/config.py's ollama.enabled docstring) -- it never once
produced an acting decision across 4,479 shadow rows, while being the
dominant cause of unusable data, so a scheduled qualitative review
replaces it as the "second opinion" layer instead of a live LLM call.

Usage:
    source .venv/bin/activate
    python scripts/daily_data_summary.py --data data/shadow_decisions.jsonl --hours 24
"""
from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict

# Row-major, Monday=0..Sunday=6, 24 hours -- see summarize_rows' docstring
# for why this lives inside the same pass as everything else rather than
# a second scan.
_HEATMAP_DAYS = 7
_HEATMAP_HOURS = 24

from shildml import schema


def _classifier_probs(record: dict) -> tuple[float, float, float] | None:
    c = record.get("classifier")
    if not c:
        return None
    probs = c.get("probs")
    if not probs or len(probs) != 3:
        return None
    return tuple(probs)  # (p_allow, p_warn, p_ban) -- see shildml.features.ACTIONS order


def summarize_rows(rows: list[dict], hours: float) -> dict:
    """The actual computation, over an already-filtered row list.
    `hours` is used ONLY for the `window_hours` field in the result --
    this function does no time filtering of its own, so a caller with a
    pre-bounded row list (e.g. plugins/WebPanel/stats.py's SummaryCache,
    which reads a byte-bounded tail of the file rather than the whole
    thing -- see that module's docstring for why) can call this
    directly instead of summarize() below, which always reads and
    time-filters the ENTIRE file. Split out 2026-08-06 for exactly that
    reuse; summarize()'s own behavior is unchanged.
    """
    fused_action = Counter()
    fused_source = Counter()
    degraded_reason = Counter()
    label_quality = Counter()
    event_type = Counter()
    net_chan = Counter()

    near_miss_ban: list[dict] = []
    near_miss_warn: list[dict] = []
    host_hits: Counter[str] = Counter()
    heatmap = [[0] * _HEATMAP_HOURS for _ in range(_HEATMAP_DAYS)]

    for r in rows:
        fused = r.get("fused") or {}
        fused_action[fused.get("action")] += 1
        fused_source[fused.get("source")] += 1
        label_quality[r.get("label_quality")] += 1
        event_type[r.get("event_type")] += 1
        net_chan[f"{r.get('network')}/{r.get('channel')}"] += 1
        ollama = r.get("ollama") or {}
        if ollama.get("degraded_reason"):
            degraded_reason[ollama["degraded_reason"]] += 1

        ts = r.get("ts")
        if ts:
            # localtime, not gmtime -- matches this deployment's existing
            # "cron/timestamps are read in the server's local timezone"
            # convention (CLAUDE.md's cron-timezone note), since a human
            # looking at this grid is checking it against their own clock.
            lt = time.localtime(ts)
            heatmap[lt.tm_wday][lt.tm_hour] += 1

        probs = _classifier_probs(r)
        if probs is None:
            continue
        p_allow, p_warn, p_ban = probs
        entry = {
            "ts": r.get("ts"), "nick": r.get("nick"), "host": r.get("host"),
            "ident": r.get("ident"), "channel": r.get("channel"), "network": r.get("network"),
            "account": r.get("account"), "event_type": r.get("event_type"),
            "p_ban": p_ban, "p_warn": p_warn, "fused_action": fused.get("action"),
        }
        near_miss_ban.append(entry)
        near_miss_warn.append(entry)
        host_hits[f"{r.get('network')}:{r.get('host')}"] += 1

    near_miss_ban.sort(key=lambda x: -x["p_ban"])
    near_miss_warn.sort(key=lambda x: -x["p_warn"])

    return {
        "window_hours": hours,
        "total_rows": len(rows),
        "fused_action": dict(fused_action),
        "fused_source": dict(fused_source),
        "degraded_reason": dict(degraded_reason),
        "label_quality": dict(label_quality),
        "event_type": dict(event_type),
        "network_channel": dict(net_chan),
        "top_near_miss_ban": near_miss_ban[:20],
        "top_near_miss_warn": near_miss_warn[:20],
        "repeat_hosts": [
            {"network_host": k, "count": v} for k, v in host_hits.most_common(15) if v > 1
        ],
        # 7x24, row-major by weekday (Monday=0..Sunday=6), each cell an
        # event count for that (weekday, hour) bucket, server-local time.
        # Mostly reflects JOIN timing today since messageAnalysis defaults
        # off -- see plugins/WebPanel/render.py's activity_heatmap for how
        # this renders (a CSS-classed grid, not raw JSON -- WebPanel's CSP
        # has no script-src and only style-src 'self', so it can't use
        # inline style= colors).
        "activity_heatmap": heatmap,
    }


def summarize(path: str, hours: float) -> dict:
    cutoff = time.time() - hours * 3600
    rows = [r for r in schema.read_jsonl(path) if (r.get("ts") or 0) >= cutoff]
    return summarize_rows(rows, hours)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", default="data/shadow_decisions.jsonl")
    p.add_argument("--hours", type=float, default=24.0,
                    help="how far back to look (default: last 24h)")
    p.add_argument("--out", default=None,
                    help="write JSON here instead of stdout")
    args = p.parse_args(argv)

    result = summarize(args.data, args.hours)
    text = json.dumps(result, indent=2)
    if args.out:
        with open(args.out, "w") as f:
            f.write(text)
        print(f"Wrote {args.out} ({result['total_rows']} rows in the last {args.hours}h)")
    else:
        print(text)


if __name__ == "__main__":
    main()
