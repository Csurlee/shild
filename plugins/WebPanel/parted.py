"""Tracks when a channel with existing ChannelLogger logs was first
observed as no longer joined ("parted"). Feeds two things: the
"Parted -- deletes <date>" annotation shown next to a channel's name on
/panel/logs and /panel/live, and the retention cleanup that deletes a
parted channel's log directory once enough days have passed (see
http.py's run_parted_maintenance).

No supybot import -- only the DETECTION here is supybot-free (takes
plain (network, channel) pairs the caller already extracted from live
irc.state); this module still does its own file I/O for the persisted
JSON, same atomic-write-then-replace pattern as
plugins/GitHubWatch/state.py's SeenStateStore, for the same reason (a
crash mid-write must never leave a corrupt/partial state file).

Deliberately conservative: a channel is only ever marked parted when we
have a LIVE connection to its network and it's genuinely absent from
that network's joined-channel set -- a network we're not currently
connected to at all (a temporary disconnect, a network name that
doesn't match) is left completely untouched, never treated as "every
channel on it just parted." mark_parted() only records the FIRST time
a channel is seen parted (a no-op on every later re-detection), so
repeated periodic checks don't keep resetting the retention clock.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


class PartedTracker:
    def __init__(self, path):
        self.path = Path(path)
        self._parted: Dict[str, Dict[str, float]] = self._load()

    def _load(self) -> Dict[str, Dict[str, float]]:
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text())
                if isinstance(raw, dict):
                    return {
                        str(net): {
                            str(chan): float(ts) for chan, ts in chans.items()
                        }
                        for net, chans in raw.items()
                        if isinstance(chans, dict)
                    }
            except (json.JSONDecodeError, OSError, ValueError, TypeError):
                pass
        return {}

    def _save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._parted, indent=2, sort_keys=True))
            tmp.replace(self.path)
        except OSError:
            pass  # state tracking must never crash the maintenance pass

    def parted_at(self, network: str, channel: str) -> Optional[float]:
        """Epoch seconds this (network, channel) was first observed
        parted, or None if it's currently tracked as joined/unknown."""
        return self._parted.get(network, {}).get(channel)

    def mark_parted(self, network: str, channel: str, when: Optional[float] = None) -> None:
        if channel in self._parted.get(network, {}):
            return
        self._parted.setdefault(network, {})[channel] = (
            when if when is not None else time.time()
        )
        self._save()

    def clear(self, network: str, channel: str) -> None:
        """Removes tracking -- called when a channel is rejoined (no
        longer parted, so the retention clock cancels) or its logs have
        just been deleted (nothing left to track)."""
        chans = self._parted.get(network)
        if chans and channel in chans:
            del chans[channel]
            if not chans:
                del self._parted[network]
            self._save()

    def sync(
        self,
        logged_channels: Iterable[Tuple[str, str]],
        joined_channels: Iterable[Tuple[str, str]],
        known_networks: Iterable[str],
    ) -> None:
        """Reconciles tracked state against live reality in one pass.
        `logged_channels`: every (network, channel) with a log file on
        disk (from logs.enumerate_logs). `joined_channels`: every
        (network, channel) the bot is CURRENTLY sitting in, across all
        connected networks. `known_networks`: the set of networks we
        currently hold a live connection to at all -- a logged channel
        on a network NOT in this set is left untouched either way,
        since we have no way to tell "parted" from "network currently
        down" without a live connection to ask.
        """
        joined = set(joined_channels)
        known = set(known_networks)
        for network, channel in logged_channels:
            if network not in known:
                continue
            if (network, channel) in joined:
                self.clear(network, channel)
            else:
                self.mark_parted(network, channel)

    def due_for_deletion(self, retention_secs: float) -> List[Tuple[str, str]]:
        """Every tracked (network, channel) whose retention window has
        elapsed, as of now."""
        now = time.time()
        return [
            (network, channel)
            for network, chans in self._parted.items()
            for channel, ts in chans.items()
            if now - ts >= retention_secs
        ]
