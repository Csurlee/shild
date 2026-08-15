"""Offline replay: drive shildml.fusion.decide() over recorded data using
the exact same function the live plugin calls (plugins/Shild/plugin.py,
built in M4). This is what makes "replay reproduces >=99% of the live
plugin's decisions" a meaningful test rather than two independent
implementations that happen to agree today.

Two input shapes are handled:
  - v2 shadow records (written by plugins/Shild/collector.py once M4/M5
    exist) carry their own recorded `classifier` and `ollama` sub-results,
    so replay reconstructs those and re-runs decide(), then compares the
    result to the record's own `fused` field -- this is the real parity
    check.
  - v1 Eggdrop records have no such structure (Ollama's reasoning was
    never recorded in a form fusion.decide can consume). For these,
    replay only exercises the classifier -> fusion path (ollama=None),
    which is still a real end-to-end smoke test of feature extraction +
    model loading + fusion, just not a live-vs-offline parity check.
    This is the mode used for M3's "runs clean over the full existing
    corpus" gate, before any live shadow data exists.
"""
from __future__ import annotations

import argparse
from collections import Counter

from . import features as _features
from . import fusion as _fusion
from . import infer as _infer
from . import schema as _schema
from .train import DEFAULT_DATA


def replay_v1_row(row: _schema.TrainingRow, clf: _infer.Classifier) -> _fusion.FusedDecision:
    pred = clf.predict(
        row.nick, row.ident, row.host,
        join_rate=row.join_rate, account_present=row.account_present,
        cross_chan_count=row.cross_chan_count,
    )
    cr = _fusion.ClassifierResult(pred.action, pred.confidence, pred.probs) if clf.available else None
    return _fusion.decide(cr, None)


def replay_v2_record(record: dict) -> tuple[_fusion.FusedDecision, str | None]:
    """Returns (recomputed_decision, recorded_action_or_None)."""
    c = record.get("classifier")
    o = record.get("ollama")
    cr = _fusion.ClassifierResult(c["action"], c["confidence"], c.get("probs", [])) if c else None
    orr = None
    if o is not None:
        orr = _fusion.OllamaResult(
            ok=o.get("raw_ok", True) and o.get("action") in _fusion.VALID_ACTIONS,
            action=o.get("action"), confidence=o.get("confidence"),
            reason=o.get("reason", ""), degraded_reason=o.get("degraded_reason", ""),
        )
    decision = _fusion.decide(cr, orr)
    recorded = (record.get("fused") or {}).get("action")
    return decision, recorded


def replay(data_paths: list[str], model_path: str) -> dict:
    clf = _infer.Classifier(model_path)
    total = 0
    errors = 0
    action_counts = Counter()
    degraded_counts = Counter()
    v2_agree = 0
    v2_total = 0

    for path in data_paths:
        for raw in _schema.read_jsonl(path):
            total += 1
            try:
                if "fused" in raw:
                    decision, recorded = replay_v2_record(raw)
                    if recorded is not None:
                        v2_total += 1
                        if decision.action == recorded:
                            v2_agree += 1
                else:
                    row = _schema.upcast_v1(raw)
                    if row is None:
                        continue
                    decision = replay_v1_row(row, clf)
                action_counts[decision.action] += 1
                if decision.degraded:
                    degraded_counts[decision.degraded_reason] += 1
            except Exception as e:  # noqa: BLE001 -- replay must not crash on one bad row
                errors += 1
                print(f"replay error on row {total}: {e}")

    result = {
        "total_rows": total,
        "errors": errors,
        "classifier_available": clf.available,
        "action_distribution": dict(action_counts),
        "degraded_reasons": dict(degraded_counts),
    }
    if v2_total:
        result["v2_parity"] = v2_agree / v2_total
        result["v2_compared_rows"] = v2_total
    return result


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", nargs="+", default=[DEFAULT_DATA])
    p.add_argument("--model", default="models/shild_v2.npz")
    args = p.parse_args(argv)

    result = replay(args.data, args.model)
    print(f"total_rows={result['total_rows']}  errors={result['errors']}")
    print(f"classifier_available={result['classifier_available']}")
    print(f"action_distribution={result['action_distribution']}")
    print(f"degraded_reasons={result['degraded_reasons']}")
    if "v2_parity" in result:
        print(f"v2_parity={result['v2_parity']:.3f} over {result['v2_compared_rows']} rows")

    if result["errors"] > 0:
        raise SystemExit(f"replay had {result['errors']} errors -- gate failed")


if __name__ == "__main__":
    main()
