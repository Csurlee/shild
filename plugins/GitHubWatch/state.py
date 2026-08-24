"""Persisted polling cursor: the highest GitHub event id already
announced per repo PER EVENT TYPE, so a bot restart doesn't re-announce
(or silently skip) events -- same atomic-write-then-replace pattern as
plugins/Shild/budget.py, for the same reason (a crash mid-write must
never leave a corrupt/partial state file).

Per-type, not a single scalar per repo (2026-08-24 fix): see
github.py's relevant_events() docstring for the real, live-confirmed
reason -- GitHub's event ids are allocated from structurally different
ranges per event type, so a single combined cursor gets permanently
poisoned the first time a high-id-range type (PushEvent) is seen,
silently blocking every future lower-id-range type (Issues/
PullRequest) forever.
"""
from __future__ import annotations

import json
from pathlib import Path


class SeenStateStore:
    def __init__(self, path: str):
        self.path = Path(path)
        self._state: dict = self._load()

    def _load(self) -> dict:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                out: dict = {}
                for repo, value in raw.items():
                    if isinstance(value, dict):
                        out[repo] = {str(etype): int(eid) for etype, eid in value.items()}
                    # An old-format flat int (pre-2026-08-24, one combined
                    # cursor per repo -- the exact bug this fix closes) is
                    # deliberately DISCARDED here, not migrated: it was
                    # already wrong (poisoned by whichever type happened
                    # to have the highest id), and treating it as a seed
                    # for any one type would just carry the bug forward.
                    # Falls back to "never seen this repo" -- fails safe
                    # (seeds forward per type on the next poll, replays no
                    # history), same convention as the corrupt-file case
                    # below.
                return out
            except (json.JSONDecodeError, OSError, ValueError, TypeError, AttributeError):
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

    def last_seen(self, repo: str) -> dict:
        """Per-event-type cursor for `repo` -- a plain dict copy, empty
        if this repo (or a given type within it) has never been seen.
        Never a single int -- see this module's own docstring."""
        return dict(self._state.get(repo, {}))

    def mark_seen(self, repo: str, event_type: str, event_id: int) -> None:
        repo_state = self._state.setdefault(repo, {})
        if event_id > repo_state.get(event_type, -1):
            repo_state[event_type] = event_id
            self._save()
