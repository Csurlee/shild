"""Thin binding between the plugin's config and shildml.infer.Classifier
-- converts shildml's Prediction into a shildml.fusion.ClassifierResult,
keeping that translation out of plugin.py.

The hot-reload-on-mtime-change behavior lives in shildml.infer.Classifier
itself (reload() checks the file's mtime); this module's job is just to
be the thing plugin.py calls predict()/reload_if_needed() on.
"""
from __future__ import annotations

from shildml import fusion, infer


class ClassifierWrapper:
    def __init__(self, model_path: str):
        self._clf = infer.Classifier(model_path)

    @property
    def available(self) -> bool:
        return self._clf.available

    @property
    def last_error(self) -> str:
        return self._clf.last_error

    @property
    def model_version(self) -> str:
        return self._clf._meta.get("trained_at", "unknown") if self._clf.available else "none"

    @property
    def schema_hash(self) -> str:
        return self._clf._meta.get("schema_hash", "") if self._clf.available else ""

    def reload_if_needed(self) -> bool:
        """Call periodically (see plugin.py's scheduled event) to pick up
        a newly-trained model dropped into models/ without a plugin
        reload."""
        return self._clf.reload()

    def predict(
        self, nick: str, ident: str, host: str,
        join_rate: float = 0.0, account_present: bool = False, cross_chan_count: int = 0,
    ) -> fusion.ClassifierResult | None:
        if not self.available:
            return None
        pred = self._clf.predict(
            nick, ident, host, join_rate=join_rate,
            account_present=account_present, cross_chan_count=cross_chan_count,
        )
        return fusion.ClassifierResult(pred.action, pred.confidence, pred.probs)
