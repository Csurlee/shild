"""Pure log-file discovery and tailing for WebPanel's /panel/logs and
/panel/log/<network>/<channel> routes. No supybot import.

The channel name comes straight from the URL, which makes this the
single highest-risk piece of code in WebPanel -- see
tests/test_webpanel_logs.py. The design principle throughout: ENUMERATE
the real files on disk first, then match a request against that
enumeration exactly; never build a filesystem path by concatenating
user input, even after "sanitizing" it. IRC channel names can legally
contain '\\', '`', '^', '{', '}', '|', so a sanitizer that strips only
'/' -- which is all supybot.utils.file.sanitizeName does; it's a
filename WRITER's helper, not an input validator -- is not a safe gate
for arbitrary URL input.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

_FORBIDDEN_SEGMENT_CHARS = ("/", "\\", "\x00")


def is_safe_segment(segment: str) -> bool:
    """A URL path segment is only usable as a lookup KEY (never as a
    path-building input) if it doesn't contain a path separator or a NUL
    byte, and isn't exactly "." or "..". Legitimate IRC channel names
    (which may contain '|', '{', '}', '^', '`', etc.) all pass this."""
    if not segment or segment in (".", ".."):
        return False
    return not any(ch in segment for ch in _FORBIDDEN_SEGMENT_CHARS)


def enumerate_logs(base_dir: str) -> Dict[Tuple[str, str], Path]:
    """Walks base_dir at depth 2 (<network>/<channel-dir>/*.log) and
    returns {(network, channel): resolved Path}. Skips symlinks (one
    inside the log tree could point anywhere), non-directories,
    non-files, and anything not ending in .log.

    A channel directory can legitimately hold MORE than one .log file --
    this was originally treated as "ambiguous, skip it", which was wrong
    on two counts, found live 2026-08-06: (1) a channel that was logging
    before rotateLogs was turned on keeps its old un-rotated file
    alongside the new dated one forever, and (2) rotateLogs=True means
    every channel accumulates one NEW file per day it's ever rotated on
    -- "exactly one file" would only ever have been true on day one. Pick
    the most-recently-modified file instead, which is "today's" file in
    the normal case and degrades sensibly (most recent history) in any
    other. A directory with zero .log files is still skipped -- nothing
    to show.
    """
    base = Path(base_dir)
    result: Dict[Tuple[str, str], Path] = {}
    if not base.is_dir():
        return result
    for network_dir in sorted(base.iterdir()):
        if network_dir.is_symlink() or not network_dir.is_dir():
            continue
        for channel_dir in sorted(network_dir.iterdir()):
            if channel_dir.is_symlink() or not channel_dir.is_dir():
                continue
            log_files = [
                f for f in channel_dir.iterdir()
                if f.is_file() and not f.is_symlink() and f.suffix == ".log"
            ]
            if not log_files:
                continue
            try:
                newest = max(log_files, key=lambda f: f.stat().st_mtime)
            except OSError:
                continue
            result[(network_dir.name, channel_dir.name)] = newest.resolve()
    return result


def resolve_log(
    index: Dict[Tuple[str, str], Path], base_dir: str, network: str, channel: str,
) -> Optional[Path]:
    """Looks up (network, channel) in an already-built `index` (see
    enumerate_logs) -- never touches the filesystem with the raw
    network/channel strings directly. Returns None (the caller must 404,
    never guess) unless BOTH segments are safe, the pair is a real
    enumerated log, AND the resolved path is still actually inside
    base_dir (defends against a symlink planted inside the log tree
    pointing somewhere else, even though enumerate_logs already skips
    symlinks at the directory/file level it walks -- this is the
    belt-and-suspenders check on the final resolved path)."""
    if not is_safe_segment(network) or not is_safe_segment(channel):
        return None
    path = index.get((network, channel))
    if path is None:
        return None
    try:
        base_resolved = Path(base_dir).resolve()
    except OSError:
        return None
    if base_resolved not in path.parents:
        return None
    return path


def tail_lines(path: Path, n: int, max_bytes: int) -> List[str]:
    """Reads at most the last `max_bytes` of `path` and returns up to
    the last `n` lines, decoded permissively (IRC logs are not reliably
    UTF-8). Reads the file size once and never reads past it, so a
    concurrent append can't hand back a torn read -- worst case is one
    cosmetically truncated line at the very start, from discarding a
    partial leading line after a mid-file seek. Returns [] for a
    missing/unreadable file or n <= 0, never raises.
    """
    if n <= 0:
        return []
    try:
        size = path.stat().st_size
    except OSError:
        return []
    try:
        with open(path, "rb") as f:
            start = max(0, size - max_bytes)
            f.seek(start)
            data = f.read(size - start)
    except OSError:
        return []
    if start > 0:
        # Seeked into the middle of the file -- the fragment before the
        # first newline is a partial line, discard it.
        _, _, data = data.partition(b"\n")
    text = data.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return lines[-n:]
