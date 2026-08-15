"""Pre-gate vs post-gate A/B report -- replaces scripts/compare_eggdrop.py
now that both Eggdrop bots are permanently retired (verified 2026-08-02:
no processes, no pid files) and can never produce another comparison
event again.

Every shadow-mode record written since Phase 1.5 carries BOTH the raw
fused decision (`fused_raw`, from fusion.decide_raw -- classifier/Ollama
alone) and the evidence-gated one (`fused`, from fusion.decide -- see
shildml/evidence.py + shildml/fusion.py). This script diffs the two
across the whole corpus and reports how many decisions the gate actually
changed, broken down by which rule fired and what evidence drove it --
directly measuring the false-positive reduction this phase exists to
produce, without needing an external ground truth to compare against.

2026-08-09: the gate is no longer downgrade-only -- `gate_rule` can now
also be "evidence_corroborated_escalation" (allow -> ban/warn, see
shildml/fusion.py's `_apply_escalation`), so `rule_counts`/
`downgrade_pairs` below may include an escalation alongside the
downgrades. The report splits the two out explicitly rather than lumping
an "allow -> ban" escalation into a rate that's only meant to describe
downgrades.

2026-08-10: two more gate_rule values exist -- "evidence_corroborated_
escalation_soft_capped" (an escalation that would have been `ban` but
had only geo_proxy corroborating, so landed on `warn` instead) and
"soft_evidence_only" (the same cap applied on the downgrade-gate side,
currently unreachable in production). The capped variant still counts as
an escalation (it's still allow -> something, from _apply_escalation),
tracked separately via `escalations_capped` so the report shows how often
the 2026-08-10 fix actually prevented a full ban.

Records written before Phase 1.5 have no `fused_raw`/`gate` key and are
counted separately (`pre_phase_1_5_rows`) rather than silently skipped or
miscounted, so the report is honest about how much of the corpus it
actually covers.

Usage:
    source .venv/bin/activate
    python scripts/gate_report.py --data data/shadow_decisions.jsonl
"""
from __future__ import annotations

import argparse
import json
from collections import Counter

from shildml import schema


def analyze(path: str) -> dict:
    total = 0
    pre_phase_1_5 = 0
    gated = 0
    rule_counts: Counter[str] = Counter()
    downgrade_pairs: Counter[str] = Counter()  # "ban->warn", "ban->allow", "warn->allow"
    evidence_signal_counts: Counter[str] = Counter()  # what evidence drove each gated decision

    for raw in schema.read_jsonl(path):
        fused = raw.get("fused")
        if fused is None:
            continue
        total += 1

        fused_raw = raw.get("fused_raw")
        gate = raw.get("gate")
        if fused_raw is None or gate is None:
            pre_phase_1_5 += 1
            continue

        if gate.get("applied"):
            gated += 1
            rule = gate.get("rule", "unknown")
            rule_counts[rule] += 1
            downgrade_pairs[f"{fused_raw['action']}->{fused['action']}"] += 1

            ev = raw.get("evidence") or {}
            if ev.get("trust_tier") not in (None, "none"):
                evidence_signal_counts[f"trust_tier={ev.get('trust_tier')}"] += 1
            if ev.get("account_present"):
                evidence_signal_counts["account_present"] += 1
            if ev.get("dnsbl_hits"):
                evidence_signal_counts["dnsbl_hit"] += 1
            if ev.get("dronebl_type"):
                evidence_signal_counts["dronebl_hit"] += 1
            if ev.get("blocklist_hits"):
                evidence_signal_counts["blocklist_hit"] += 1
            if not ev.get("checks_run") and not ev.get("cloak"):
                evidence_signal_counts["no_evidence_available"] += 1

    escalations_full = rule_counts.get("evidence_corroborated_escalation", 0)
    escalations_capped = rule_counts.get("evidence_corroborated_escalation_soft_capped", 0)
    escalations = escalations_full + escalations_capped
    downgrades_soft_capped = rule_counts.get("soft_evidence_only", 0)
    downgrades = gated - escalations

    covered = total - pre_phase_1_5
    return {
        "total_rows": total,
        "pre_phase_1_5_rows": pre_phase_1_5,
        "covered_rows": covered,
        "gated": gated,
        "gate_rate": gated / covered if covered else 0.0,
        "escalations": escalations,
        "escalations_capped": escalations_capped,
        "downgrades": downgrades,
        "downgrades_soft_capped": downgrades_soft_capped,
        "rule_counts": dict(rule_counts),
        "downgrade_pairs": dict(downgrade_pairs),
        "evidence_signal_counts": dict(evidence_signal_counts),
    }


def _print_report(result: dict) -> None:
    print(f"total_rows={result['total_rows']}  "
          f"pre_phase_1.5={result['pre_phase_1_5_rows']}  "
          f"covered={result['covered_rows']}")
    if result["covered_rows"] == 0:
        print("\nNo Phase 1.5 records yet (no fused_raw/gate keys found) -- "
              "run the bot with evidence.enabled after this deploy before "
              "drawing conclusions.")
        return
    print(f"\nGated (adjusted by evidence): {result['gated']} "
          f"({result['gate_rate']:.1%} of covered rows) -- "
          f"{result['downgrades']} downgraded, {result['escalations']} escalated")
    if result["escalations_capped"] or result["downgrades_soft_capped"]:
        print(f"  of which: {result['escalations_capped']} escalation(s) capped ban->warn "
              f"(geo_proxy-only, no hard evidence), "
              f"{result['downgrades_soft_capped']} gate downgrade(s) for the same reason")
    print("\nBy rule:")
    for rule, n in sorted(result["rule_counts"].items()):
        print(f"  {rule}: {n}")
    print("\nBy direction (downgrades AND the evidence-corroborated escalation):")
    for pair, n in sorted(result["downgrade_pairs"].items()):
        print(f"  {pair}: {n}")
    print("\nEvidence signal present on gated decisions:")
    for signal, n in sorted(result["evidence_signal_counts"].items()):
        print(f"  {signal}: {n}")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", default="data/shadow_decisions.jsonl")
    p.add_argument("--json", action="store_true", help="print raw JSON instead of a report")
    args = p.parse_args(argv)

    result = analyze(args.data)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        _print_report(result)


if __name__ == "__main__":
    main()
