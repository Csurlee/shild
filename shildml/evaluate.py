"""CLI evaluator: confusion matrix, per-class metrics, and a leak
ablation (do the context features -- join_rate/account_present/
cross_chan_count -- actually carry signal, or is the model just reading
noise the way the old in_global_bad feature was pure leak?).
"""
from __future__ import annotations

import argparse
from collections import Counter

import numpy as np

from . import features as _features
from . import infer as _infer
from . import schema as _schema
from .train import DEFAULT_DATA, rows_to_arrays


def confusion_matrix(y_true, y_pred, n_classes):
    cm = np.zeros((n_classes, n_classes), dtype=int)
    for t, p in zip(y_true, y_pred):
        cm[t, p] += 1
    return cm


def per_class_metrics(y_true, y_pred, actions):
    metrics = {}
    for idx, action in enumerate(actions):
        tp = int(((y_pred == idx) & (y_true == idx)).sum())
        fp = int(((y_pred == idx) & (y_true != idx)).sum())
        fn = int(((y_pred != idx) & (y_true == idx)).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        metrics[action] = {"precision": precision, "recall": recall, "f1": f1,
                            "support": int((y_true == idx).sum())}
    macro_f1 = sum(m["f1"] for m in metrics.values()) / len(metrics)
    return metrics, macro_f1


def evaluate(data_paths: list[str], model_path: str, include_leaked: bool = False) -> dict:
    rows = _schema.load_training_rows(*data_paths, include_leaked=include_leaked)
    X, y_true = rows_to_arrays(rows)

    clf = _infer.Classifier(model_path)
    if not clf.available:
        raise RuntimeError(f"model at {model_path} failed to load: {clf.last_error}")

    y_pred = np.array([
        _features.ACTION_IDX[clf.predict(
            r.nick, r.ident, r.host, join_rate=r.join_rate,
            account_present=r.account_present, cross_chan_count=r.cross_chan_count,
        ).action]
        for r in rows
    ])

    cm = confusion_matrix(y_true, y_pred, len(_features.ACTIONS))
    metrics, macro_f1 = per_class_metrics(y_true, y_pred, _features.ACTIONS)

    # Leak ablation: zero out the context features (indices 19-21: join_rate,
    # account_present, cross_chan_count) and see whether macro-F1 collapses.
    # If it *doesn't* change much, the model wasn't relying on them much
    # either way; if removing them tanks accuracy, they're carrying real
    # signal (good). What we're specifically checking is the OPPOSITE of
    # the old system's failure mode: macro-F1 should NOT come entirely
    # from a leak feature, because there isn't one anymore -- this is a
    # sanity check for that fact, not a feature-importance ranking.
    X_ablated = X.copy()
    context_start = len(_features.FEATURE_NAMES) - 3
    X_ablated[:, context_start:] = 0.0
    y_pred_ablated = []
    for row_features in X_ablated:
        logits = clf._forward(row_features) if clf.available else None
        if logits is None:
            y_pred_ablated.append(_features.ACTION_IDX["allow"])
            continue
        y_pred_ablated.append(int(np.argmax(logits)))
    y_pred_ablated = np.array(y_pred_ablated)
    _, macro_f1_ablated = per_class_metrics(y_true, y_pred_ablated, _features.ACTIONS)

    result = {
        "n_rows": len(rows),
        "label_distribution": dict(Counter(r.action for r in rows)),
        "confusion_matrix": cm.tolist(),
        "actions": _features.ACTIONS,
        "per_class": metrics,
        "macro_f1": macro_f1,
        "macro_f1_context_ablated": macro_f1_ablated,
    }
    return result


def _print_report(result: dict) -> None:
    print(f"n_rows={result['n_rows']}  label_distribution={result['label_distribution']}")
    print(f"\nConfusion matrix (rows=true, cols=pred), actions={result['actions']}:")
    for i, row in enumerate(result["confusion_matrix"]):
        print(f"  {result['actions'][i]:>6}: {row}")
    print("\nPer-class metrics:")
    for action, m in result["per_class"].items():
        print(f"  {action:>6}: precision={m['precision']:.2f} recall={m['recall']:.2f} "
              f"f1={m['f1']:.2f} (n={m['support']})")
    print(f"\nMacro F1:                    {result['macro_f1']:.3f}")
    print(f"Macro F1 (context ablated):  {result['macro_f1_context_ablated']:.3f}")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", nargs="+", default=[DEFAULT_DATA])
    p.add_argument("--model", default="models/shild_v2.npz")
    p.add_argument("--include-leaked", action="store_true")
    args = p.parse_args(argv)

    result = evaluate(args.data, args.model, include_leaked=args.include_leaked)
    _print_report(result)


if __name__ == "__main__":
    main()
