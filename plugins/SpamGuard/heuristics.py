"""Pure, non-term, threshold-based message heuristics (2026-08-14): flood,
mass nick-highlight, and excessive caps. See mojibake.py for the fourth
(garbled-encoding detection, vendored separately since it's a large
regex table, not written here).

Adapted from ideas in Libera Chat's own `ozone` network-abuse bot
(github.com/Libera-Chat/ozone, plugin.py's isChannelFlood/isHilight/
isChannelCaps) -- reimplemented independently for this codebase's own
conventions (pure functions here, plugin.py holds all mutable state, same
split as matcher.py/context.py), not copied. ozone's own versions are
tangled with its IRCop-KLINE architecture and a shared numeric "badness"
strike score across multiple triggers; these are deliberately simpler,
single-purpose checks that feed SpamGuard's existing gate chain
(_handle_match in plugin.py) the same way a word/phrase/pattern match
already does.

No supybot import -- pure, unit-testable without the plugin harness, same
convention as matcher.py/terms.py in this plugin.
"""
from __future__ import annotations


def prune_window(timestamps: list[float], now: float, window_secs: float) -> list[float]:
    """Keeps only the entries within `window_secs` of `now`. Used for
    both flood detection (per-(network,channel,nick) message
    timestamps) and its own periodic sweep of stale tracked keys --
    plugin.py appends the current event's own timestamp BEFORE calling
    this, so a fresh key's return value always includes at least that
    one entry.
    """
    return [t for t in timestamps if now - t <= window_secs]


def highlighted_nick_count(text: str, channel_nicks, exclude_nick: str,
                            min_nick_len: int = 3) -> int:
    """Counts how many DISTINCT real channel members (other than the
    sender) are named by nick in `text`, case-insensitively, via a plain
    substring check -- same technique ozone's own isHilight uses. Nicks
    shorter than `min_nick_len` are skipped: a 1-2 character nick is
    common enough as an ordinary word/word-fragment substring that
    counting it would make this trigger on completely unrelated chatter,
    not an actual raid pinging half the channel by name.
    """
    lowered_text = text.lower()
    exclude = exclude_nick.lower()
    count = 0
    for raw_nick in channel_nicks:
        nick = raw_nick.lower()
        if nick == exclude or len(nick) < min_nick_len:
            continue
        if nick in lowered_text:
            count += 1
    return count


def caps_percentage(text: str) -> float:
    """Fraction (0.0-1.0) of the ALPHABETIC characters in `text` that
    are uppercase -- non-letter characters (digits, punctuation,
    emoji/formatting) never count toward either the numerator or the
    denominator, so a message that's mostly punctuation/links can't
    accidentally read as "all caps" just because the few letters it does
    have happen to be capitalized. Returns 0.0 for text with no letters
    at all (never a false trigger on an empty/symbols-only message).
    """
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    upper = sum(1 for c in letters if c.isupper())
    return upper / len(letters)
