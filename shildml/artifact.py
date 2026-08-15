"""Model artifact format — a single .npz containing weight arrays PLUS an
embedded __meta__ JSON blob, so metadata can never get separated from the
weights. (The original ~/shild-ai/export.py produced weights-only .npz
files with zero versioning — no ACTIONS list, no feature count, no
schema/version info at all — which is why a features.py change there
could silently break inference with no error.)
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

import numpy as np

from . import features as _features

ARTIFACT_FORMAT_VERSION = 1


class SchemaMismatch(RuntimeError):
    """Raised when an artifact's schema_hash doesn't match the running
    features.py. Callers should treat this as "no model available" (defer
    everything to the LLM fallback) rather than crash — see infer.Classifier.
    """


def save(path: str | Path, layer_spec: list[dict], metadata: dict) -> None:
    """layer_spec: ordered list of {"w": ndarray, "b": ndarray,
    "act": "relu"|None}, one entry per Linear layer, in forward-pass
    order. metadata: training provenance (trained_at, git_commit,
    train_rows, label_distribution, val_metrics, split_strategy, ...) —
    schema/feature/action info is filled in automatically from the
    running features.py so it's always self-consistent with whatever
    produced this file.
    """
    arrays: dict[str, Any] = {}
    activations = []
    for i, layer in enumerate(layer_spec):
        arrays[f"w{i}"] = np.asarray(layer["w"], dtype=np.float32)
        arrays[f"b{i}"] = np.asarray(layer["b"], dtype=np.float32)
        activations.append(layer.get("act"))

    meta = dict(metadata)
    meta["format_version"] = ARTIFACT_FORMAT_VERSION
    meta["n_layers"] = len(layer_spec)
    meta["layer_activations"] = activations
    meta["feature_version"] = _features.FEATURE_VERSION
    meta["feature_names"] = _features.FEATURE_NAMES
    meta["actions"] = _features.ACTIONS
    meta["schema_hash"] = _features.schema_hash()

    arrays["__meta__"] = np.array(json.dumps(meta, sort_keys=True))
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez(path, **arrays)


def load(path: str | Path, *, strict: bool = True) -> tuple[list[dict], dict]:
    """Returns (layer_spec, metadata). If strict (default) and the
    artifact's schema_hash doesn't match the currently-running
    features.schema_hash(), raises SchemaMismatch rather than silently
    running a mismatched feature contract through the weights.
    """
    data = np.load(path, allow_pickle=False)
    meta = json.loads(str(data["__meta__"]))

    if strict and meta.get("schema_hash") != _features.schema_hash():
        raise SchemaMismatch(
            f"artifact schema_hash={meta.get('schema_hash')!r} does not "
            f"match running features.schema_hash()={_features.schema_hash()!r} "
            "-- features.py has changed since this model was trained"
        )

    layer_spec = []
    for i, act in enumerate(meta["layer_activations"]):
        layer_spec.append({"w": data[f"w{i}"], "b": data[f"b{i}"], "act": act})
    return layer_spec, meta


def layer_spec_from_torch_state_dict(
    state_dict: dict, activations: list[Optional[str]]
) -> list[dict]:
    """Build a layer_spec from a torch nn.Sequential's state_dict by the
    *numeric position* of each Linear layer's index, not by a hardcoded
    key name. This is the direct fix for the bug in the old
    ~/shild-ai/server.py, which hardcoded net.0/net.3/net.6 while the
    actual Sequential produced net.0/net.3/net.5 — a silent mismatch that
    would only surface (as an unhandled 500) the moment a real model was
    deployed. Renumbering or restructuring the Sequential can no longer
    silently break inference, because nothing here hardcodes a layer index.
    """
    indices = sorted(
        {
            int(m.group(1))
            for k in state_dict
            for m in [re.match(r"net\.(\d+)\.weight", k)]
            if m
        }
    )
    if len(indices) != len(activations):
        raise ValueError(
            f"found {len(indices)} Linear layers in state_dict "
            f"({indices}) but {len(activations)} activations were given"
        )
    layer_spec = []
    for idx, act in zip(indices, activations):
        w = state_dict[f"net.{idx}.weight"].detach().cpu().numpy()
        b = state_dict[f"net.{idx}.bias"].detach().cpu().numpy()
        layer_spec.append({"w": w, "b": b, "act": act})
    return layer_spec
