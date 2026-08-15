"""CLI trainer for the SHILD classifier.

Ported from ~/shild-ai/train.py with four changes:
  - class-weighted CrossEntropyLoss (the corpus is heavily imbalanced)
  - a fixed --seed for reproducibility
  - a host-grouped train/val split instead of a random row-level split
    (174+ unique hosts across ~325 rows means a random split lets
    near-duplicate events from the same host land on both sides of the
    boundary, inflating validation accuracy on numbers that look real
    but aren't)
  - 3-class taxonomy (allow/warn/ban) instead of 4 — see features.ACTIONS;
    `kick` is folded into `ban` by schema.upcast_v1/v2, handled downstream
    as rule-based warn-count escalation rather than an ML class

IMPORTANT: as of the first Phase-1 training run, the only training data
available is ~/eggdrop/logs/classifier_training.jsonl, which the user
explicitly chose not to fix at the source (see project plan). Excluding
leak-tainted rows (schema.py) leaves ZERO ban examples in that file today
-- the leak (in_global_bad marking a host bad before the same decision's
training row is written) accounts for essentially all of the historical
ban/kick labels. This means:
  - the default (--include-leaked not passed) will refuse to train a
    3-class model if the ban class has too few examples
  - --include-leaked trains on everything anyway, producing a MODEL THAT
    IS NOT DEPLOYABLE -- it exists only to prove train -> export -> load
    -> infer works end-to-end before real (leak-free) shadow-mode data
    exists. train.py prints a loud warning and stamps the artifact
    metadata with `deployable: false` when this flag is used.
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import artifact as _artifact
from . import features as _features
from . import schema as _schema

DEFAULT_DATA = "/home/csurlee/eggdrop/logs/classifier_training.jsonl"
MIN_ROWS_PER_CLASS = 5


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).parent, capture_output=True, text=True, timeout=2,
        )
        return out.stdout.strip() if out.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def host_grouped_split(rows, val_frac: float = 0.15, seed: int = 42):
    """Split by host, not by row, so no host's events appear on both
    sides. Returns (train_rows, val_rows)."""
    hosts = sorted({r.host_group for r in rows})
    rng = random.Random(seed)
    rng.shuffle(hosts)
    n_val_hosts = max(1, int(len(hosts) * val_frac))
    val_hosts = set(hosts[:n_val_hosts])
    train_rows = [r for r in rows if r.host_group not in val_hosts]
    val_rows = [r for r in rows if r.host_group in val_hosts]
    return train_rows, val_rows


def rows_to_arrays(rows):
    import numpy as np

    X = np.array([
        _features.extract(
            r.nick, r.ident, r.host,
            join_rate=r.join_rate,
            account_present=r.account_present,
            cross_chan_count=r.cross_chan_count,
        )
        for r in rows
    ], dtype="float32")
    y = np.array([_features.ACTION_IDX[r.action] for r in rows], dtype="int64")
    return X, y


def train(
    data_paths: list[str],
    model_out: str,
    epochs: int = 150,
    seed: int = 42,
    val_frac: float = 0.15,
    include_leaked: bool = False,
) -> dict:
    import numpy as np
    import torch
    from torch.utils.data import DataLoader, TensorDataset

    from .model import ShildNet

    torch.manual_seed(seed)
    random.seed(seed)

    rows = _schema.load_training_rows(*data_paths, include_leaked=include_leaked)
    dist = Counter(r.action for r in rows)
    print(f"Loaded {len(rows)} rows: {dict(dist)}", file=sys.stderr)

    if include_leaked:
        print(
            "WARNING: training with --include-leaked. This model is NOT "
            "DEPLOYABLE -- ban/kick labels in the source data are tainted "
            "by the in_global_bad leak (see schema.py). This run exists "
            "only to prove the pipeline works end-to-end.",
            file=sys.stderr,
        )

    for action in _features.ACTIONS:
        if dist.get(action, 0) < MIN_ROWS_PER_CLASS:
            raise ValueError(
                f"only {dist.get(action, 0)} '{action}' examples "
                f"(need >= {MIN_ROWS_PER_CLASS}); "
                + ("try --include-leaked to prove the pipeline, or wait for "
                   "more shadow-mode data" if not include_leaked else
                   "not enough data at all yet")
            )

    train_rows, val_rows = host_grouped_split(rows, val_frac=val_frac, seed=seed)
    print(f"Split: {len(train_rows)} train rows / {len(val_rows)} val rows "
          f"({len({r.host_group for r in train_rows})} / "
          f"{len({r.host_group for r in val_rows})} unique hosts)", file=sys.stderr)

    X_train, y_train = rows_to_arrays(train_rows)
    X_val, y_val = rows_to_arrays(val_rows)

    # Inverse-frequency class weights -- the corpus is heavily imbalanced
    # (e.g. warn >> ban in the clean subset).
    counts = np.bincount(y_train, minlength=len(_features.ACTIONS)).astype("float32")
    counts[counts == 0] = 1.0  # avoid div-by-zero for a class absent from train split
    weights = (1.0 / counts)
    weights = weights / weights.sum() * len(_features.ACTIONS)
    class_weights = torch.tensor(weights, dtype=torch.float32)

    net = ShildNet()
    optimizer = torch.optim.Adam(net.parameters(), lr=1e-3, weight_decay=1e-4)
    criterion = torch.nn.CrossEntropyLoss(weight=class_weights)

    train_ds = TensorDataset(torch.from_numpy(X_train), torch.from_numpy(y_train))
    train_loader = DataLoader(train_ds, batch_size=32, shuffle=True)
    X_val_t = torch.from_numpy(X_val)
    y_val_t = torch.from_numpy(y_val)

    best_val_loss = float("inf")
    best_state = None

    for epoch in range(epochs):
        net.train()
        for xb, yb in train_loader:
            optimizer.zero_grad()
            loss = criterion(net(xb), yb)
            loss.backward()
            optimizer.step()

        net.eval()
        with torch.no_grad():
            val_logits = net(X_val_t)
            val_loss = criterion(val_logits, y_val_t).item()
        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_state = {k: v.clone() for k, v in net.state_dict().items()}

    assert best_state is not None
    net.load_state_dict(best_state)

    # Per-class validation metrics on the best checkpoint.
    net.eval()
    with torch.no_grad():
        val_pred = net(X_val_t).argmax(dim=1).numpy()
    val_metrics = {}
    for idx, action in enumerate(_features.ACTIONS):
        tp = int(((val_pred == idx) & (y_val == idx)).sum())
        fp = int(((val_pred == idx) & (y_val != idx)).sum())
        fn = int(((val_pred != idx) & (y_val == idx)).sum())
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        val_metrics[action] = {"precision": precision, "recall": recall, "f1": f1,
                                "support": int((y_val == idx).sum())}
    macro_f1 = sum(m["f1"] for m in val_metrics.values()) / len(val_metrics)
    val_metrics["macro_f1"] = macro_f1
    print(f"Best val loss: {best_val_loss:.4f}, macro F1: {macro_f1:.3f}", file=sys.stderr)
    for action, m in val_metrics.items():
        if action != "macro_f1":
            print(f"  {action}: precision={m['precision']:.2f} recall={m['recall']:.2f} "
                  f"f1={m['f1']:.2f} (n={m['support']})", file=sys.stderr)

    layer_spec = _artifact.layer_spec_from_torch_state_dict(
        net.state_dict(), ShildNet.ACTIVATIONS
    )
    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": _git_commit(),
        "trainer_version": "shildml.train v1",
        "train_rows": len(train_rows),
        "val_rows": len(val_rows),
        "label_distribution": dict(dist),
        "split_strategy": "group-by-host",
        "seed": seed,
        "val_metrics": val_metrics,
        "include_leaked": include_leaked,
        "deployable": not include_leaked,
        "source_files": [str(p) for p in data_paths],
    }
    _artifact.save(model_out, layer_spec, metadata)
    print(f"Saved artifact to {model_out}", file=sys.stderr)
    return metadata


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", nargs="+", default=[DEFAULT_DATA],
                    help="one or more training JSONL files (v1 or v2, auto-detected)")
    p.add_argument("--model", default="models/shild_v2.npz")
    p.add_argument("--epochs", type=int, default=150)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--val-frac", type=float, default=0.15)
    p.add_argument("--include-leaked", action="store_true",
                    help="include leak-tainted v1 rows; produces a NON-DEPLOYABLE model, "
                         "for pipeline validation only")
    args = p.parse_args(argv)

    train(args.data, args.model, epochs=args.epochs, seed=args.seed,
          val_frac=args.val_frac, include_leaked=args.include_leaked)


if __name__ == "__main__":
    main()
