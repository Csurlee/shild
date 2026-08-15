"""Records a human's manual review verdict on a shadow-mode decision --
e.g. from the daily flagged-hosts review, or an ad-hoc check like the
2026-08-09 undernet/#bookz cluster.

Deliberately a SEPARATE, append-only file (`data/human_reviews.jsonl` by
default) rather than rewriting the matching line in
data/shadow_decisions.jsonl in place: the live bot appends to that file
continuously, and a read-modify-write over the whole file would risk
clobbering a concurrent append. Same reasoning as why
data/observed_moderation.jsonl and data/enforcement_actions.jsonl are
their own files rather than fields bolted onto shadow_decisions.jsonl.
Uses shildml.schema.write_jsonl_line, the same safe append-only primitive
plugins/Shild/collector.py itself uses.

This does NOT feed shildml.train automatically -- it's a durable record
of what a human decided and why, for a future retrain to incorporate
deliberately, not a silent label rewrite.

Usage:
    python scripts/record_human_review.py \
        --target-ts 1786290586.0 --network undernet --channel '#bookz' \
        --nick sinsal --ident '~sinsal' --host 146.70.237.38 \
        --verdict ban --original-action ban --reviewer csurlee \
        --note "M247 datacenter/VPN, confirmed spam pattern"
"""
from __future__ import annotations

import argparse
import time

from shildml import schema


def main(argv=None) -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target-ts", type=float, required=True,
                    help="ts of the shadow_decisions.jsonl record being reviewed")
    p.add_argument("--network", required=True)
    p.add_argument("--channel", required=True)
    p.add_argument("--nick", required=True)
    p.add_argument("--ident", default=None)
    p.add_argument("--host", required=True)
    p.add_argument("--verdict", required=True, choices=["ban", "warn", "allow"],
                    help="the human-confirmed ground truth")
    p.add_argument("--original-action", default=None, choices=["ban", "warn", "allow", None],
                    help="what fused.action said at the time, for quick diffing")
    p.add_argument("--reviewer", required=True)
    p.add_argument("--note", default="")
    p.add_argument("--out", default="data/human_reviews.jsonl")
    args = p.parse_args(argv)

    record = {
        "ts": time.time(),
        "target_ts": args.target_ts,
        "network": args.network,
        "channel": args.channel,
        "nick": args.nick,
        "ident": args.ident,
        "host": args.host,
        "verdict": args.verdict,
        "original_fused_action": args.original_action,
        "reviewer": args.reviewer,
        "note": args.note,
    }
    schema.write_jsonl_line(args.out, record)
    print(f"Recorded: {args.nick} ({args.host}) -> {args.verdict} in {args.out}")


if __name__ == "__main__":
    main()
