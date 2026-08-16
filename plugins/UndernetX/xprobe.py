"""Pure logic for the X-capability probe (2026-08-16): classifying an
X `ACCESS <#channel> =<botnick>` reply into "can we actually kick/ban
here via X" and caching that verdict per (network, channel). No supybot
import -- same "pure module + thin plugin.py" split as xcommands.py.

Built for one hard requirement: NEVER attempt an X-routed kick/ban on a
channel X doesn't actually manage, or where the bot's own X access is
too low to do anything -- a channel with no X presence at all must
behave EXACTLY like today (log-only, no action), not silently fail
mid-enforcement. See plugins/Shild/enforcement.py's/plugins/SpamGuard/
enforcement.py's own module docstrings for why "attempt and hope" is
never acceptable here.

FAILS CLOSED BY CONSTRUCTION: `USABLE` is only ever produced when a
reply line contains BOTH the bot's own X username (word-boundary
match) AND a bare integer access level that clears the configured
minimum. Every other case -- a negative marker, someone else's access
row, an unrecognized reply, total silence, a timeout with nothing
collected -- resolves UNUSABLE. There is no "assume yes" path anywhere
in this module.

IMPORTANT CAVEAT, same convention already established in xcommands.py's
own module docstring for xban's "access" parameter: most of the
patterns below started as a best-guess from general X documentation,
NOT verified against a live reply. As of 2026-08-16, real live
verification (against this deployment's own account/channels) has
confirmed: the "No Match!" negative marker (2026-08-14, xaccess against
a nick with no matching X username); the "doesn't appear to be
registered" negative marker (2026-08-16, "#windrop" on Undernet --
genuinely NOT X-registered despite an earlier, never-server-confirmed
assumption otherwise, see CLAUDE.md); and the positive access-row shape
itself (2026-08-16, "#erdely": reply text
"USER: WinDropChan ACCESS: 100 L" -- confirms the username-then-a-
plain-integer pattern _ACCESS_LEVEL_RE/classify_access_line already
assumed, with NO code change needed). TERMINATOR_MARKERS remains
UNVERIFIED -- neither live reply observed so far included one, which is
itself a useful data point (a target-scoped "ACCESS #chan =nick" query
appears to reply with exactly one line, not a multi-line list needing a
terminator -- the multi-line collection machinery in plugin.py's
_maybe_probe_channel still degrades correctly for a single-line reply
via its timeout-driven fallback, just with the full
commands.replyTimeoutSecs latency for a negative verdict rather than
resolving instantly on a terminator). This is all safe regardless of
what's still unverified, precisely because the design fails closed: an
unrecognized reply -- positive OR negative -- always resolves UNUSABLE,
so a wrong guess here only ever costs "the feature stays inert on this
channel", never a wrongly-attempted action. See docs/UNDERNETX.md's
"X-routed enforcement fallback" section for the remaining verification
steps before ever arming plugins.UndernetX.enforcement.xFallbackEnabled
on a real deployment.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

UNKNOWN = "unknown"
USABLE = "usable"
UNUSABLE = "unusable"

# Definitive "X cannot help here" signals. Case-insensitive substring match.
# Only the first entry is confirmed live -- see module docstring.
NEGATIVE_MARKERS = (
    "No Match!",                        # CONFIRMED LIVE 2026-08-14 (xaccess,
                                         # a nick with no matching X username)
    "doesn't appear to be registered",  # CONFIRMED LIVE 2026-08-16 (real
                                         # reply for "#windrop", an Undernet
                                         # channel with no actual X
                                         # registration -- exact text: "The
                                         # channel #windrop doesn't appear to
                                         # be registered")
    "is not registered",         # UNVERIFIED -- other wording variants seen
    "not registered with",       # in general X docs, kept as a fallback
    "unknown channel",           # UNVERIFIED
    "invalid channel",           # UNVERIFIED
    "you lack enough access",    # UNVERIFIED
    "insufficient access",       # UNVERIFIED
    "you must be authenticated", # UNVERIFIED
)

# End-of-multi-line-reply markers. UNVERIFIED -- see module docstring.
TERMINATOR_MARKERS = (
    "end of access list",
    "end of access",
)

# A bare 1-3 digit number anywhere in the line -- the access level column,
# per general X ACCESS reply documentation. UNVERIFIED against a real
# successful reply; see module docstring.
_ACCESS_LEVEL_RE = re.compile(r"\b(\d{1,3})\b")


def looks_like_denial(text: str) -> bool:
    """True if `text` matches one of NEGATIVE_MARKERS. Shared by the probe
    classifier and enforce_ban_via_x's post-hoc cache demotion (a denial
    arriving in response to a real BAN/KICK attempt means the cached
    USABLE verdict was wrong or has since gone stale -- self-correcting).
    """
    lowered = text.lower()
    return any(marker.lower() in lowered for marker in NEGATIVE_MARKERS)


def is_terminator(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in TERMINATOR_MARKERS)


@dataclass(frozen=True)
class ProbeVerdict:
    state: str  # USABLE | UNUSABLE | UNKNOWN
    access_level: Optional[int] = None
    reason: str = ""
    matched_marker: Optional[str] = None


def classify_access_line(text: str, *, username: str, min_access: int) -> ProbeVerdict:
    """Verdict for a SINGLE reply line. UNKNOWN means "no opinion yet,
    keep collecting" -- never treated as a positive by any caller.
    """
    if not text:
        return ProbeVerdict(UNKNOWN, reason="empty line")

    if looks_like_denial(text):
        lowered = text.lower()
        marker = next((m for m in NEGATIVE_MARKERS if m.lower() in lowered), None)
        return ProbeVerdict(UNUSABLE, reason=f"denial marker: {text.strip()}",
                             matched_marker=marker)

    if username:
        pattern = re.compile(r"\b" + re.escape(username) + r"\b", re.IGNORECASE)
        if pattern.search(text):
            level_match = _ACCESS_LEVEL_RE.search(text)
            if level_match:
                level = int(level_match.group(1))
                if level >= min_access:
                    return ProbeVerdict(USABLE, access_level=level,
                                         reason=f"access {level} in reply line")
                return ProbeVerdict(UNUSABLE, access_level=level,
                                     reason=f"access {level} below minimum {min_access}")

    return ProbeVerdict(UNKNOWN, reason="unrecognized line")


def classify_access_reply(lines: List[str], *, username: str, min_access: int) -> ProbeVerdict:
    """Final verdict over every line collected for one probe. Folds
    classify_access_line over `lines`, taking the first definitive
    (non-UNKNOWN) verdict; if none of the lines were definitive, the
    reply is UNUSABLE -- this is the fail-closed floor: silence,
    gibberish, a header-only reply, or an empty collection can never
    resolve USABLE.
    """
    for line in lines:
        verdict = classify_access_line(line, username=username, min_access=min_access)
        if verdict.state != UNKNOWN:
            return verdict
    return ProbeVerdict(UNUSABLE, reason="no definitive line in reply"
                         if lines else "no reply received")


@dataclass
class CapabilityEntry:
    state: str
    access_level: Optional[int]
    checked_at: float
    last_attempt_at: float
    in_flight: bool
    raw_lines: List[str] = field(default_factory=list)
    reason: str = ""


class XCapabilityCache:
    """In-memory only (per plugin instance -- wiped on @reload UndernetX,
    correctly, since self.identified resets too and old verdicts from a
    prior session are meaningless). Keyed by (network, channel) EXACTLY
    as given -- callers are responsible for normalizing channel casing
    (e.g. via ircutils.toLower) before calling in, since IRC casemapping
    rules aren't this pure module's concern.
    """

    def __init__(self):
        self._entries: Dict[Tuple[str, str], CapabilityEntry] = {}

    def get(self, network: str, channel: str) -> Optional[CapabilityEntry]:
        return self._entries.get((network, channel))

    def is_usable(self, network: str, channel: str, *, ttl: float,
                  now: Optional[float] = None) -> bool:
        """False for a missing entry, an UNUSABLE entry, an in-flight
        (not-yet-answered) entry, or a USABLE entry whose `ttl` has
        elapsed -- staleness is treated as unusable, not as "assume
        still good", so a revoked access level self-corrects within
        `ttl` even if nothing ever demotes it explicitly.
        """
        now = now if now is not None else time.time()
        entry = self._entries.get((network, channel))
        if entry is None or entry.in_flight:
            return False
        if entry.state != USABLE:
            return False
        return (now - entry.checked_at) <= ttl

    def should_probe(self, network: str, channel: str, *, ttl: float,
                      min_interval: float, now: Optional[float] = None) -> bool:
        """Whether a NEW probe should be sent right now. False while
        already in flight, false within `min_interval` of the last
        attempt regardless of outcome (so a burst of joins/misses can
        never fire more than one probe per (network, channel) per
        interval), true once the cached verdict (if any) is missing or
        older than `ttl`.
        """
        now = now if now is not None else time.time()
        entry = self._entries.get((network, channel))
        if entry is None:
            return True
        if entry.in_flight:
            return False
        if (now - entry.last_attempt_at) < min_interval:
            return False
        if entry.state == USABLE and (now - entry.checked_at) <= ttl:
            return False
        return True

    def mark_in_flight(self, network: str, channel: str,
                        now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        key = (network, channel)
        existing = self._entries.get(key)
        if existing is not None:
            existing.in_flight = True
            existing.last_attempt_at = now
        else:
            self._entries[key] = CapabilityEntry(
                state=UNKNOWN, access_level=None, checked_at=0.0,
                last_attempt_at=now, in_flight=True,
            )

    def record(self, network: str, channel: str, verdict: ProbeVerdict,
               raw_lines: List[str], now: Optional[float] = None) -> None:
        now = now if now is not None else time.time()
        self._entries[(network, channel)] = CapabilityEntry(
            state=verdict.state, access_level=verdict.access_level,
            checked_at=now, last_attempt_at=now, in_flight=False,
            raw_lines=list(raw_lines), reason=verdict.reason,
        )

    def invalidate(self, network: str, channel: str) -> None:
        """Demotes an entry to UNUSABLE immediately (e.g. a real BAN/KICK
        attempt got a denial-shaped reply back) without waiting for TTL
        expiry -- self-correcting feedback for an imperfect probe verdict.
        No-op if there's no entry to demote.
        """
        entry = self._entries.get((network, channel))
        if entry is None:
            return
        entry.state = UNUSABLE
        entry.in_flight = False
        entry.reason = "invalidated after a denial-shaped enforcement reply"

    def clear(self, network: Optional[str] = None) -> None:
        """Drops every cached entry, or only those for `network` (e.g. on
        a fresh X login -- old verdicts from the previous session are
        meaningless).
        """
        if network is None:
            self._entries.clear()
            return
        for key in [k for k in self._entries if k[0] == network]:
            del self._entries[key]

    def snapshot(self) -> List[Tuple[str, str, CapabilityEntry]]:
        """Every tracked entry, for undernetxstatus/xprobe display."""
        return [(net, chan, entry) for (net, chan), entry in self._entries.items()]
