"""Pure HTML rendering for WebPanel. No supybot import.

Deliberately NOT using httpserver.get_template: it `assert`s (crashes
the request) on a missing template file, and its bare %-substitution
raises ValueError on a stray "%" on the left side of a substitution --
and IRC nicks/messages/log lines contain "%" constantly. Plain string
building instead, with html.escape() at every single insertion point of
untrusted content -- log lines, nicks, channel/network names, hostmasks
all count as untrusted, since any IRC user can put arbitrary text in
most of them. Skipping escaping anywhere here is stored XSS reachable
from any user in any logged channel; the Content-Security-Policy set in
http.py (`default-src 'none'`, no script-src at all) is the second layer,
not a replacement for this one.
"""
from __future__ import annotations

import datetime
import html
import urllib.parse
from typing import Iterable, Tuple


def escape(s: str) -> str:
    return html.escape(s, quote=True)


_PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
{refresh}<title>{title}</title>
<link rel="stylesheet" href="/panel/style.css">
</head>
<body>
<div class="nav"><a href="/panel/">overview</a> | <a href="/panel/logs">logs</a> | <a href="/panel/live">live</a> | <a href="/panel/stats">stats</a> | <a href="/panel/gate">gate</a> | <a href="/panel/report">report</a> | <a href="/panel/commands">commands</a></div>
<h1>{heading}</h1>
{body}
</body>
</html>
"""

STYLE_CSS = b"""\
body { font-family: monospace; margin: 2em; background: #111; color: #ddd; }
a { color: #6cf; }
.nav { margin-bottom: 1.5em; }
table { border-collapse: collapse; width: 100%; }
td, th { padding: 0.25em 0.75em; text-align: left; border-bottom: 1px solid #333; }
pre { background: #000; padding: 1em; overflow-x: auto; white-space: pre-wrap; word-break: break-word; }
table.heatmap { width: auto; table-layout: fixed; }
table.heatmap th, table.heatmap td {
    padding: 0.15em 0.4em; text-align: center; border: 1px solid #222;
    font-size: 0.85em; min-width: 1.6em;
}
table.heatmap th:first-child, table.heatmap td:first-child { text-align: right; }
td.heat-0 { background: #111; color: #444; }
td.heat-1 { background: #1b3a2f; color: #ddd; }
td.heat-2 { background: #2e6b4a; color: #eee; }
td.heat-3 { background: #4fa860; color: #111; }
td.heat-4 { background: #9ee06a; color: #111; }
code { color: #9ee06a; }
.cmd-help { color: #999; }
.parted { color: #d78a3a; }
"""


def page(title: str, heading: str, body_html: str, refresh_secs: int | None = None) -> bytes:
    """`body_html` is trusted to already be escaped -- every caller in
    this module builds it via escape() below, and http.py never passes
    raw request data straight into this function. `refresh_secs`, when
    given, adds a <meta http-equiv="refresh"> tag -- this is how the
    live-preview pages poll without any JavaScript at all, which matters
    because the CSP set in http.py is `default-src 'none'` with no
    script-src: no JS can run on this site, period, so an escaping
    mistake anywhere degrades to garbled text instead of executing."""
    refresh = (
        f'<meta http-equiv="refresh" content="{int(refresh_secs)}">'
        if refresh_secs else ""
    )
    return _PAGE.format(
        title=escape(title), heading=escape(heading), body=body_html, refresh=refresh,
    ).encode("utf-8")


def simple_message(message: str) -> str:
    return f"<p>{escape(message)}</p>"


def _parted_annotation(parted_since: float | None, retention_days: int) -> str:
    """Empty string for a channel that's still joined (parted_since is
    None) -- ONLY a parted channel gets the "(Parted -- deletes <date>)"
    marker, per the explicit "only on part" requirement. The date shown
    is when retention cleanup deletes the log directory (parted_since +
    retention_days), not the part date itself, so it doubles as an
    early warning rather than just a status label."""
    if parted_since is None:
        return ""
    deletion = datetime.datetime.fromtimestamp(
        parted_since + retention_days * 86400
    ).strftime("%Y-%m-%d")
    return f' <span class="parted">(Parted -- deletes {escape(deletion)})</span>'


def logs_index(
    entries: Iterable[Tuple[str, str, int, float, "float | None"]],
    retention_days: int,
) -> str:
    """entries: iterable of (network, channel, size_bytes, mtime_epoch,
    parted_since_epoch_or_None), already sorted by the caller.
    parted_since is None for a channel the bot is still joined to;
    otherwise the epoch time it was FIRST observed parted (see
    plugins/WebPanel/parted.py) -- see _parted_annotation above for how
    that's rendered."""
    rows = []
    for network, channel, size, mtime, parted_since in entries:
        url = "/panel/log/%s/%s" % (
            urllib.parse.quote(network, safe=""),
            urllib.parse.quote(channel, safe=""),
        )
        when = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M")
        channel_cell = escape(channel) + _parted_annotation(parted_since, retention_days)
        rows.append(
            "<tr><td><a href=\"%s\">%s</a></td><td>%s</td>"
            "<td>%s bytes</td><td>%s</td></tr>" % (
                escape(url), escape(network), channel_cell,
                # NOT the bare builtin format(size, ",") -- merely
                # importing supybot monkeypatches the real `format`
                # builtin process-wide (supybot/__init__.py:38, replaces
                # it with supybot's own i18n-string function, a totally
                # different signature) -- an f-string's :, spec doesn't
                # go through that call at all, so it's the only safe way
                # to comma-format an int anywhere in this codebase once
                # supybot has been imported (which it always has been,
                # by the time this module is reachable).
                f"{size:,}", escape(when),
            )
        )
    if not rows:
        return "<p>No channel logs yet.</p>"
    return (
        "<table><tr><th>network</th><th>channel</th><th>size</th>"
        "<th>last write</th></tr>" + "".join(rows) + "</table>"
    )


def log_tail(network: str, channel: str, lines: Iterable[str], requested_n: int) -> str:
    body_lines = "\n".join(escape(line) for line in lines)
    return (
        "<p>Last %d line(s) of %s / %s. <a href=\"/panel/logs\">back to index</a></p>"
        "<pre>%s</pre>" % (requested_n, escape(network), escape(channel), body_lines)
    )


def plain_text_block(label: str, text: str) -> str:
    return "<p>%s</p><pre>%s</pre>" % (escape(label), escape(text))


def overview(snapshot: dict) -> str:
    """snapshot: a plugins/Shild `Shild.runtime_snapshot()` dict -- see
    that method's docstring. Formats the SAME data !shildstatus does, so
    the two can never drift out of sync with each other."""
    stats = snapshot["stats"]
    if snapshot["ollama_enabled"]:
        if snapshot["ollama_latency_p50_ms"] is not None:
            ollama_line = (
                f"p50={snapshot['ollama_latency_p50_ms']:.0f}ms "
                f"p99={snapshot['ollama_latency_p99_ms']:.0f}ms"
            )
        else:
            ollama_line = "enabled, no samples yet"
    else:
        ollama_line = "disabled (classifier-only)"

    rows = [
        ("uptime", f"{snapshot['uptime_secs']}s"),
        ("classifier", "loaded" if snapshot["classifier_available"] else "unavailable"),
        ("classifier schema", snapshot["classifier_schema_hash"] or "n/a"),
        ("worker", "running" if snapshot["worker_running"] else "STOPPED"),
        ("worker dropped", str(snapshot["worker_dropped_count"])),
        ("ollama", ollama_line),
        ("joins (since restart)", str(stats.get("joins", 0))),
        ("messages (since restart)", str(stats.get("messages", 0))),
        ("decisions (since restart)", str(stats.get("decisions", 0))),
        ("degraded (since restart)", str(stats.get("degraded", 0))),
        ("gated (since restart)", str(stats.get("gated", 0))),
        ("enforced (since restart)", str(stats.get("enforced", 0))),
        ("evidence cache", f"{snapshot['evidence_cache_size']} entries"),
        ("budget", str(snapshot["budget_stats"])),
        ("kill switch", "ON (safe)" if snapshot["kill_switch"] else "OFF (live)"),
        ("pending unbans", str(snapshot["pending_unbans"])),
        ("ignored hosts", str(snapshot.get("ignore_list_size", 0))),
    ]
    body_rows = "".join(
        f"<tr><th>{escape(k)}</th><td>{escape(v)}</td></tr>" for k, v in rows
    )
    return (
        f"<table>{body_rows}</table>"
        "<p>The \"(since restart)\" counters above reset to 0 on every bot "
        "restart or `@reload Shild` -- see <a href=\"/panel/stats\">stats</a> "
        "for real historical activity that doesn't reset.</p>"
        "<p><a href=\"/panel/scans\">recent scanned hosts</a> | "
        "<a href=\"/panel/logs\">channel logs</a> | "
        "<a href=\"/panel/report\">daily report</a></p>"
    )


def channel_stats_table(rows: Iterable[Tuple[str, str, object]]) -> str:
    """rows: iterable of (network, channel, ChannelStat-like object with
    .msgs/.joins/.parts/.kicks/.quits/.users attributes) -- see
    plugins/ChannelStats/plugin.py's ChannelStat. Object rather than a
    typed import so render.py stays supybot-free."""
    rows = sorted(rows, key=lambda r: (r[0], r[1]))
    if not rows:
        return "<p>No channel stats recorded yet.</p>"
    body_rows = []
    for network, channel, stat in rows:
        body_rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td></tr>" % (
                escape(network), escape(channel),
                getattr(stat, "msgs", 0), getattr(stat, "joins", 0),
                getattr(stat, "parts", 0), getattr(stat, "kicks", 0),
                getattr(stat, "quits", 0),
            )
        )
    return (
        "<table><tr><th>network</th><th>channel</th><th>messages</th>"
        "<th>joins</th><th>parts</th><th>kicks</th><th>quits</th></tr>"
        + "".join(body_rows) + "</table>"
    )


_HEATMAP_WEEKDAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


def _heat_level(count: int, max_count: int) -> int:
    """0-4 quantized bucket for a CSS class -- WebPanel's CSP is
    `style-src 'self'` with no `unsafe-inline`, so per-cell color has to
    come from a class in STYLE_CSS, not an inline style= attribute."""
    if count <= 0 or max_count <= 0:
        return 0
    ratio = count / max_count
    if ratio >= 0.75:
        return 4
    if ratio >= 0.5:
        return 3
    if ratio >= 0.25:
        return 2
    return 1


def activity_heatmap(grid: list | None) -> str:
    """grid: 7x24 row-major (Monday=0..Sunday=6, hour 0-23) event counts
    -- see scripts/daily_data_summary.py's summarize_rows for how it's
    built. Mostly join timing today, since messageAnalysis defaults off."""
    if not grid or not any(any(row) for row in grid):
        return (
            "<h2>Activity heatmap</h2>"
            "<p>No timestamped events in the current window yet.</p>"
        )
    flat_max = max((v for row in grid for v in row), default=0)
    header = "<tr><th></th>" + "".join(
        f"<th>{h:02d}</th>" for h in range(24)) + "</tr>"
    body_rows = []
    for day_idx, day_name in enumerate(_HEATMAP_WEEKDAYS):
        row = grid[day_idx] if day_idx < len(grid) else [0] * 24
        cells = []
        for hour in range(24):
            count = row[hour] if hour < len(row) else 0
            level = _heat_level(count, flat_max)
            tooltip = escape(f"{day_name} {hour:02d}:00 -- {count} event(s)")
            cells.append(
                f'<td class="heat-{level}" title="{tooltip}">'
                f'{count or ""}</td>'
            )
        body_rows.append(f"<tr><th>{escape(day_name)}</th>{''.join(cells)}</tr>")
    return (
        "<h2>Activity heatmap (events by hour, server-local time)</h2>"
        '<table class="heatmap">' + header + "".join(body_rows) + "</table>"
    )


def aggregate_block(title: str, result: dict | None, computed_at: float,
                     error: str | None) -> str:
    """Generic renderer for a plugins/WebPanel/stats.SummaryCache result
    -- used by both /panel/stats (near-miss/distribution summary) and
    /panel/gate (pre/post-gate A/B). `result` is shown as an indented,
    escaped JSON dump rather than bespoke tables for every possible key
    -- both underlying computations (scripts.daily_data_summary,
    scripts.gate_report) already produce a stable, documented dict shape
    meant to be read directly; a hand-built table per field would just
    be a second, driftable copy of that shape."""
    import json as _json

    parts = [f"<h2>{escape(title)}</h2>"]
    if result is None:
        parts.append("<p>Not computed yet -- check back in a few seconds.</p>")
    else:
        when = (
            datetime.datetime.fromtimestamp(computed_at).strftime("%Y-%m-%d %H:%M:%S")
            if computed_at else "?"
        )
        parts.append(f"<p>Computed at {escape(when)}.</p>")
        parts.append(f"<pre>{escape(_json.dumps(result, indent=2, default=str))}</pre>")
    if error:
        parts.append(f"<p class=\"error\">Last refresh attempt failed: {escape(error)}</p>")
    return "".join(parts)


def live_index(
    pairs: Iterable[Tuple[str, str, "float | None"]],
    retention_days: int,
) -> str:
    """pairs: iterable of (network, channel, parted_since_epoch_or_None)
    -- see logs_index's identical parted_since convention above."""
    pairs = sorted(pairs, key=lambda p: (p[0], p[1]))
    if not pairs:
        return "<p>No channels with a log file yet.</p>"
    items = "".join(
        "<li><a href=\"/panel/live/%s/%s\">%s / %s</a>%s</li>" % (
            urllib.parse.quote(network, safe=""), urllib.parse.quote(channel, safe=""),
            escape(network), escape(channel),
            _parted_annotation(parted_since, retention_days),
        )
        for network, channel, parted_since in pairs
    )
    return (
        f"<ul>{items}"
        "<li><a href=\"/panel/live/decisions\">Shild decision feed (all networks)</a></li>"
        "</ul>"
    )


def live_channel(network: str, channel: str, lines: Iterable[str], refresh_secs: int) -> str:
    body_lines = "\n".join(escape(line) for line in lines)
    return (
        "<p>%s / %s -- auto-refreshing every %ds. "
        "<a href=\"/panel/live\">back to live index</a></p>"
        "<pre>%s</pre>" % (escape(network), escape(channel), refresh_secs, body_lines)
    )


def live_disabled(network: str, channel: str) -> str:
    return simple_message(
        f"Live preview is disabled (livePreviewSource=none) for {network}/{channel}.")


def live_decisions(events: Iterable[tuple], refresh_secs: int) -> str:
    """events: ContextStore.recent_global_events() tuples --
    (ts, network, channel, event_type, nick, host, detail), newest
    first."""
    events = list(events)
    if not events:
        return "<p>No events observed yet.</p>"
    rows = []
    for ts, network, channel, event_type, nick, host, detail in events:
        when = (
            datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")
            if isinstance(ts, (int, float)) else "?"
        )
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td></tr>" % (
                escape(when), escape(str(network)), escape(str(channel)),
                escape(str(event_type)), escape(str(nick)), escape(str(host)),
                escape(str(detail)),
            )
        )
    return (
        "<p>Auto-refreshing every %ds. <a href=\"/panel/live\">back to live index</a></p>"
        "<table><tr><th>time</th><th>network</th><th>channel</th><th>type</th>"
        "<th>nick</th><th>host</th><th>detail</th></tr>%s</table>" % (
            refresh_secs, "".join(rows),
        )
    )


def _command_syntax_and_help(doc: str | None) -> Tuple[str, str]:
    """Splits a command method's raw __doc__ into (syntax, description),
    the same two pieces supybot's own callbacks.getHelp() shows on IRC --
    built independently rather than calling that function directly,
    since it wraps the syntax in mIRC bold control codes (meant for a
    PRIVMSG, not HTML) and pulls in channel/network-scoped config
    (conf.supybot.reply.showSimpleSyntax) via thread-local `dynamic`
    state that isn't set on the HTTP server thread. The convention every
    command docstring in this codebase already follows (wrap()'s own
    error-reply mechanism depends on it too): first line is the argument
    syntax, a blank line, then free-form prose description."""
    if not doc or not doc.strip():
        return "", "(no help available)"
    lines = doc.strip().splitlines()
    syntax = lines[0].strip()
    description = " ".join(line.strip() for line in lines[1:] if line.strip())
    return syntax, description or "(no description)"


def commands_list(entries: Iterable[Tuple[str, Iterable[Tuple[str, str | None]]]]) -> str:
    """entries: iterable of (plugin_name, [(command_name, raw_docstring), ...])
    -- already filtered by the caller to public plugins only (see
    http.py's _route_commands, which mirrors the same public/private
    gating scripts/bootstrap_runtime.py and plugins/Misc/plugin.py's
    patched `list` command already enforce -- this page must not
    re-open that hole). `raw_docstring` is the command method's own
    __doc__, unparsed -- may be None (e.g. a dispatcher command with no
    docstring of its own)."""
    entries = sorted(entries)
    if not entries:
        return "<p>No public plugins loaded.</p>"
    blocks = []
    for plugin_name, commands in entries:
        commands = sorted(commands, key=lambda c: c[0])
        if commands:
            items = []
            for cname, doc in commands:
                syntax, description = _command_syntax_and_help(doc)
                usage = f"{cname} {syntax}".strip()
                items.append(
                    f"<li><code>{escape(usage)}</code><br>"
                    f"<span class=\"cmd-help\">{escape(description)}</span></li>"
                )
            blocks.append(f"<h2>{escape(plugin_name)}</h2><ul>{''.join(items)}</ul>")
        else:
            blocks.append(f"<h2>{escape(plugin_name)}</h2><p>(no commands)</p>")
    return "".join(blocks)


def scans_table(records: Iterable[dict], requested_n: int) -> str:
    """records: shild-py v2 shadow_decisions.jsonl rows, oldest-first
    (same order plugins/WebPanel/stats.tail_records returns them in).
    Rendered newest-first."""
    records = list(records)
    if not records:
        return "<p>No shadow-mode decisions recorded yet.</p>"
    rows = []
    for r in reversed(records):
        ts = r.get("ts")
        when = (
            datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(ts, (int, float)) else "?"
        )
        fused = r.get("fused") or {}
        action = fused.get("action", "?")
        confidence = fused.get("confidence")
        conf_str = f"{confidence:.2f}" if isinstance(confidence, (int, float)) else "?"
        source = fused.get("source", "?")
        rows.append(
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s</td><td>%s</td><td>%s</td></tr>" % (
                escape(when), escape(str(r.get("network", ""))),
                escape(str(r.get("channel", ""))), escape(str(r.get("nick", ""))),
                escape(str(r.get("host", ""))), escape(str(action)),
                escape(conf_str), escape(str(source)),
            )
        )
    return (
        "<p>Last %d scanned host(s) (requested %d).</p>"
        "<table><tr><th>time</th><th>network</th><th>channel</th><th>nick</th>"
        "<th>host</th><th>action</th><th>confidence</th><th>source</th></tr>"
        "%s</table>" % (len(records), requested_n, "".join(rows))
    )
