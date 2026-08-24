"""Pure, locked, append-only audit log for WebPanel's write routes
(2026-08-24). No supybot import -- unit-testable with plain pytest.

One JSONL record per successful write action (who, what, when, from
where) -- log only, no IRC relay line (a deliberate choice: a web-
originated kill-switch flip is visible here and in the panel itself,
without adding a new relay-line class for every future write action).

Never raises, by design -- a broken audit write must never fail the
admin's actual write (the registry/TermStore change that record is
*about* has, in every caller, already happened by the time `record` is
called). Locked with a plain `threading.Lock`, same reasoning as every
other cross-thread-written state in this deployment (decision_cache.py,
ban_ids.py, terms.py) -- this file is written only from the HTTP server
thread today, but the lock costs nothing and removes any future need to
re-derive that this is safe if a second writer is ever added.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Optional


class AuditLog:
    def __init__(self, path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, *, action: str, actor: str, client_ip: str,
               detail: Optional[dict] = None) -> None:
        entry = {
            "ts": time.time(),
            "action": action,
            "actor": actor,
            "client_ip": client_ip,
            "detail": detail or {},
        }
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a") as f:
                    # default=str (2026-08-24 fix, found via code review):
                    # json.dumps raises TypeError for a non-JSON-serializable
                    # detail value, which the bare `except OSError` below
                    # never caught -- violating this method's own "never
                    # raises" contract for any future caller that passes
                    # something json.dumps can't handle natively. Every
                    # current caller already passes safe types (str/bool/
                    # int), so this was latent, not yet triggered -- but
                    # default=str means even a future bad value still gets
                    # logged (stringified) rather than silently dropped or
                    # raising into the caller's real write.
                    f.write(json.dumps(entry, default=str) + "\n")
        except (OSError, TypeError, ValueError):
            pass  # audit logging must never fail the write it's about
