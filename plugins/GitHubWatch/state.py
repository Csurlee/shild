"""Persisted polling cursor: the highest GitHub event id already
announced per repo, so a bot restart doesn't re-announce (or silently
skip) events -- same atomic-write-then-replace pattern as
plugins/Shild/budget.py, for the same reason (a crash mid-write must
never leave a corrupt/partial state file).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional


class SeenStateStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self._state: dict[str, int] = self._load()

    def _load(self) -> dict[str, int]:
        if self.path.exists():
            try:
                return {k: int(v) for k, v in json.loads(self.path.read_text()).items()}
            except (json.JSONDecodeError, OSError, ValueError):
                pass
        return {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._state, indent=2, sort_keys=True))
            tmp.replace(self.path)
        except OSError:
            pass  # state tracking must never crash the poll loop

    def last_seen(self, repo: str) -> Optional[int]:
        return self._state.get(repo)

    def mark_seen(self, repo: str, event_id: int) -> None:
        if event_id > self._state.get(repo, -1):
            self._state[repo] = event_id
            self._save()
