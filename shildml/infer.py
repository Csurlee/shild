"""Pure-numpy inference — no torch import, so the running bot process only
ever needs numpy (torch stays in the [train] extra, used only by
train.py/model.py). Metadata-driven: doesn't hardcode layer count or
names, so an architecture change doesn't require an infer.py change.
"""
from __future__ import annotations

from pathlib import Path
from typing import NamedTuple, Optional

import numpy as np

from . import artifact as _artifact
from . import features as _features


def _softmax(x: np.ndarray) -> np.ndarray:
    x = x - np.max(x)
    e = np.exp(x)
    return e / e.sum()


def _relu(x: np.ndarray) -> np.ndarray:
    return np.maximum(x, 0.0)


_ACTIVATIONS = {"relu": _relu, None: lambda x: x}


class Prediction(NamedTuple):
    action: str
    confidence: float
    probs: list[float]
    reason: str


class Classifier:
    """Loads a model artifact and serves predictions synchronously. The
    forward pass is microseconds (22 -> 64 -> 32 -> 3), so this is safe
    to call directly from Limnoria's single-threaded main loop (doJoin) —
    unlike the Ollama client, which does need a worker thread (see
    plugins/Shild/worker.py, built in M4).
    """

    def __init__(self, model_path: str | Path):
        self.model_path = Path(model_path)
        self._layer_spec: Optional[list[dict]] = None
        self._meta: dict = {}
        self._mtime: float = 0.0
        self.last_error: str = ""
        self.reload()

    @property
    def available(self) -> bool:
        return self._layer_spec is not None

    def reload(self) -> bool:
        """(Re)load the artifact if its mtime changed since last load.
        Returns True if a (re)load happened. Never raises: on any failure
        (missing file, schema mismatch, corrupt npz) the classifier just
        becomes unavailable, which routes every decision to the Ollama
        fallback via fusion.decide(classifier=None, ...) — never a crash.
        """
        if not self.model_path.exists():
            if self._layer_spec is not None:
                self._layer_spec = None
                self._meta = {}
            return False
        mtime = self.model_path.stat().st_mtime
        if self._layer_spec is not None and mtime == self._mtime:
            return False
        try:
            layer_spec, meta = _artifact.load(self.model_path, strict=True)
        except _artifact.SchemaMismatch as e:
            self._layer_spec = None
            self._meta = {}
            self.last_error = str(e)
            return False
        except Exception as e:  # corrupt file, permission error, etc.
            self._layer_spec = None
            self._meta = {}
            self.last_error = f"{type(e).__name__}: {e}"
            return False
        self._layer_spec = layer_spec
        self._meta = meta
        self._mtime = mtime
        self.last_error = ""
        return True

    def _forward(self, x: np.ndarray) -> np.ndarray:
        assert self._layer_spec is not None
        for layer in self._layer_spec:
            x = x @ layer["w"].T + layer["b"]
            x = _ACTIVATIONS[layer["act"]](x)
        return x

    def predict(
        self,
        nick: str,
        ident: str,
        host: str,
        join_rate: float = 0.0,
        account_present: bool = False,
        cross_chan_count: int = 0,
    ) -> Prediction:
        actions = self._meta.get("actions", _features.ACTIONS)
        if not self.available:
            n = len(actions)
            return Prediction("allow", 0.0, [1.0 / n] * n, "no model loaded")

        vec = _features.extract(
            nick, ident, host,
            join_rate=join_rate,
            account_present=account_present,
            cross_chan_count=cross_chan_count,
        )
        x = np.asarray(vec, dtype=np.float32)
        logits = self._forward(x)
        probs = _softmax(logits)
        idx = int(np.argmax(probs))
        action = actions[idx]
        confidence = float(probs[idx])
        reason = f"classifier({confidence:.0%}): {action}"
        return Prediction(action, confidence, [float(p) for p in probs], reason)
