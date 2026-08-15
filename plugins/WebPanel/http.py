"""The only module in WebPanel that imports supybot.httpserver -- routing,
the auth gate, and response headers. All the dangerous logic (password
hashing, Basic-Auth parsing, lockout, path/log handling) lives in pure
modules (auth.py, and logs.py/render.py/stats.py in later phases) so it
gets fast unit tests with no IRC harness; this file just wires that logic
to the actual HTTP request/response objects.

**Phase 1 is read-only.** doPost returns a bare 405 -- see the comment on
WebPanelCallback.doPost for exactly what must exist before that changes.

**Shared-callback hazard** (see also plugins/Shild/context.py's own
threading notes for the analogous IRC-side issue): Limnoria's
httpserver.py `setattr`s `wfile`/`headers`/`send_response`/etc. onto THIS
SAME callback instance for every request
(`SupyHTTPRequestHandler.do_X`). With more than one bound address (IPv4
+ IPv6) that's two server threads mutating one object concurrently.
Every handler in this file uses the `handler` argument it's given, never
`self.wfile`/`self.headers`/etc. -- and scripts/bootstrap_runtime.py
binds exactly one address (hosts6=[]) so the race can't happen in the
first place either. Belt and suspenders.
"""
from __future__ import annotations

import re
import shutil
import time
import urllib.parse
from pathlib import Path
from typing import Iterable

from supybot import conf, httpserver, ircutils, log, world

from . import auth, logs, parted, render, stats
from .secrets import CredentialWatcher

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_LOG_INDEX_TTL_SECS = 30.0
_MIN_LOG_TAIL_N = 50
_MAX_SCANS_N = 100

# The subdir this callback is hooked at (plugin.py's httpserver.hook call
# must use the same string) -- needed here too because httpserver.py's
# path-stripping leaves a bare "/panel" (no trailing slash) as "/panel",
# not "/" -- see _route's handling of that case.
SUBDIR = "panel"

SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("Content-Security-Policy",
     "default-src 'none'; style-src 'self'; img-src 'self'"),
    ("Cache-Control", "no-store"),
)


def _write(
    handler,
    status: int,
    content_type: str,
    body: bytes,
    write_content: bool = True,
    extra_headers: Iterable[tuple[str, str]] = (),
) -> None:
    """The only place this module writes a response -- always via
    `handler`, never `self`, per the module docstring."""
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(body)))
    for name, value in SECURITY_HEADERS:
        handler.send_header(name, value)
    for name, value in extra_headers:
        handler.send_header(name, value)
    handler.end_headers()
    if write_content:
        handler.wfile.write(body)


class WebPanelCallback(httpserver.SupyHTTPServerCallback):
    name = "WebPanel"
    # Kept off the root index (SupyIndex only lists public=True callbacks)
    # -- same reasoning as Owner/Admin/Config being marked non-public in
    # scripts/bootstrap_runtime.py: don't advertise an admin surface's
    # existence to a bare GET /.
    public = False

    def __init__(self, plugin):
        self._plugin = plugin
        self._credentials = CredentialWatcher(plugin.registryValue("secretsPath"))
        # Auth-tuning values are snapshotted here at construction (i.e.
        # at hook time), not re-read per request -- a live @config change
        # to authCacheSecs/maxAuthFailures/authLockoutSecs needs a plugin
        # reload to take effect. Documented on the registry values
        # themselves too.
        self._cache = auth.CredentialCache(
            ttl_secs=plugin.registryValue("authCacheSecs"))
        self._lockout = auth.LockoutTracker(
            max_failures=plugin.registryValue("maxAuthFailures"),
            lockout_secs=plugin.registryValue("authLockoutSecs"))
        self._last_failure_log: dict[str, float] = {}
        # Log-file enumeration cache -- see _log_index below. Rebuilt on
        # a short TTL so a newly-logged channel appears without a plugin
        # reload, without doing a directory walk on every single request.
        self._log_index_cache: dict[tuple[str, str], Path] | None = None
        self._log_index_base_dir: str | None = None
        self._log_index_ts: float = 0.0
        # Background-refreshed aggregates for /panel/stats and
        # /panel/gate -- see stats.SummaryCache's docstring for why
        # these must never compute on the request thread. Started in
        # doHook (once the callback is actually wired up), stopped in
        # doUnhook, so no background thread lingers while the panel is
        # disabled.
        self._summary_cache = stats.SummaryCache(
            path_fn=self._plugin.shadow_data_path,
            compute=stats.summarize_tail,
            refresh_secs=plugin.registryValue("summaryRefreshSecs"),
        )
        self._gate_cache = stats.SummaryCache(
            path_fn=self._plugin.shadow_data_path,
            compute=stats.gate_report,
            refresh_secs=plugin.registryValue("gateRefreshSecs"),
        )
        # Parted-channel retention tracking -- see parted.py's module
        # docstring and run_parted_maintenance below. Constructed here
        # (not lazily) so a freshly-enabled panel starts tracking
        # immediately rather than waiting for the first periodic check.
        self._parted = parted.PartedTracker(plugin.registryValue("partedStatePath"))

    # ---- httpserver entry points ----

    def doGetOrHead(self, handler, path, write_content):
        self._dispatch(handler, path, write_content)

    def doPost(self, handler, path, form=None):
        # No state-changing route exists in this phase -- see this
        # plugin's design notes (CLAUDE.md) for the phase-1/phase-2
        # boundary. This 405 is deliberate, not a stub to fill in later
        # without also adding CSRF protection, an Origin/Referer check,
        # and a capability-based allowlist of settable keys first: Basic
        # Auth alone gives ZERO CSRF protection, since a malicious page
        # you merely visit can POST here and your browser will attach
        # cached credentials automatically.
        _write(handler, 405, "text/plain; charset=utf-8", b"Method not allowed.")

    def doHook(self, handler, subdir):
        self._summary_cache.start()
        self._gate_cache.start()

    def doUnhook(self, handler):
        self._summary_cache.stop()
        self._gate_cache.stop()

    # ---- auth gate ----

    def _dispatch(self, handler, path: str, write_content: bool) -> None:
        allowed_hosts = set(self._plugin.registryValue("allowedHosts"))
        host = handler.headers.get("Host", "")
        if host not in allowed_hosts:
            # Anti DNS-rebinding, and the ONLY defense against it: without
            # this, a website you merely visit can resolve its own
            # hostname to this box's LAN/loopback IP and reach the panel
            # through your own browser, which attaches your cached
            # Basic-Auth credentials automatically. An empty allowedHosts
            # (misconfiguration) fails closed here too -- rejects every
            # Host rather than silently allowing all.
            _write(handler, 400, "text/plain; charset=utf-8",
                   b"Bad Host header.", write_content)
            return

        client_ip = handler.address_string()
        credentials = self._credentials.get()
        result = auth.check_request(
            credentials,
            handler.headers.get("Authorization"),
            client_ip,
            self._cache,
            self._lockout,
        )

        if result == auth.AuthResult.NOT_CONFIGURED:
            _write(handler, 503, "text/plain; charset=utf-8",
                   b"WebPanel has no credentials configured.", write_content)
            return
        if result == auth.AuthResult.LOCKED:
            _write(handler, 429, "text/plain; charset=utf-8",
                   b"Too many failed attempts. Try again later.",
                   write_content, extra_headers=(("Retry-After", "60"),))
            return
        if result == auth.AuthResult.UNAUTHORIZED:
            self._log_failure(client_ip)
            _write(handler, 401, "text/plain; charset=utf-8",
                   b"Unauthorized.", write_content,
                   extra_headers=(
                       ("WWW-Authenticate",
                        'Basic realm="shild-py panel", charset="UTF-8"'),
                   ))
            return

        self._route(handler, path, write_content)

    def _log_failure(self, client_ip: str) -> None:
        # At most one log line per IP per 60s, so an unauthenticated
        # scanner can't fill runtime/logs with warnings.
        now = time.time()
        last = self._last_failure_log.get(client_ip, 0.0)
        if now - last >= 60.0:
            self._last_failure_log[client_ip] = now
            log.warning("WebPanel: auth failure from %s", client_ip)
            # Deliberately NOT logging the attempted username/password --
            # runtime/stdout.log is not access-restricted beyond the
            # filesystem, same reasoning as never logging attempted
            # credentials anywhere else in this repo.

    # ---- routing (authenticated only) ----

    def _route(self, handler, path: str, write_content: bool) -> None:
        # Query strings are NOT parsed by httpserver.py -- they arrive
        # still attached to `path`. Split first, THEN split path into
        # segments and unquote PER SEGMENT (never unquote the whole path
        # before splitting) -- a %2F in a raw segment must never turn
        # into a path separator that wasn't there.
        clean_path, _, query = path.partition("?")
        params = urllib.parse.parse_qs(query)

        if clean_path == "/" + SUBDIR:
            # httpserver.py's path-stripping (`split('/', 2)[-1]`) leaves
            # a bare "/panel" (no trailing slash) as literally "/panel"
            # rather than "/" -- redirect to the canonical form instead
            # of silently 404ing on it.
            _write(handler, 301, "text/plain; charset=utf-8", b"",
                   write_content, extra_headers=(("Location", "/panel/"),))
            return

        if clean_path in ("/health", "/health/"):
            _write(handler, 200, "text/plain; charset=utf-8", b"ok\n", write_content)
            return

        if clean_path == "/style.css":
            _write(handler, 200, "text/css; charset=utf-8", render.STYLE_CSS, write_content)
            return

        if clean_path in ("/logs", "/logs/"):
            self._route_logs_index(handler, write_content)
            return

        if clean_path.startswith("/log/"):
            self._route_log_tail(handler, clean_path, params, write_content)
            return

        if clean_path in ("/report", "/report/"):
            self._route_report(handler, params, write_content)
            return

        if clean_path in ("/scans", "/scans/"):
            self._route_scans(handler, params, write_content)
            return

        if clean_path in ("/stats", "/stats/"):
            self._route_stats(handler, write_content)
            return

        if clean_path in ("/gate", "/gate/"):
            self._route_gate(handler, write_content)
            return

        if clean_path in ("/commands", "/commands/"):
            self._route_commands(handler, write_content)
            return

        if clean_path in ("/live", "/live/"):
            self._route_live_index(handler, write_content)
            return

        if clean_path in ("/live/decisions", "/live/decisions/"):
            self._route_live_decisions(handler, write_content)
            return

        if clean_path.startswith("/live/"):
            self._route_live_channel(handler, clean_path, write_content)
            return

        if clean_path in ("/", ""):
            self._route_overview(handler, write_content)
            return

        _write(handler, 404, "text/plain; charset=utf-8", b"Not found.", write_content)

    # ---- Shild-backed pages (degrade gracefully if Shild isn't loaded) ----

    def _route_overview(self, handler, write_content: bool) -> None:
        shild = self._plugin.shild_callback()
        if shild is None:
            body = render.simple_message(
                "Shild plugin is not loaded -- no runtime status available. "
                "File-backed pages (logs, report) still work.")
        else:
            body = render.overview(shild.runtime_snapshot())
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel", "Overview", body), write_content)

    def _route_scans(self, handler, params: dict, write_content: bool) -> None:
        default_n = self._plugin.registryValue("recentScansCount")
        n = _clamp_int(params.get("n", [None])[0], default=default_n,
                        lower=1, upper=_MAX_SCANS_N)
        path = self._plugin.shadow_data_path()
        records = stats.tail_records(path, n)
        body = render.scans_table(records, n)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: scans", "Recently scanned hosts", body),
               write_content)

    def _route_stats(self, handler, write_content: bool) -> None:
        cs = self._plugin.channelstats_callback()
        if cs is None:
            channel_stats_html = render.simple_message(
                "ChannelStats plugin is not loaded -- no per-channel message "
                "stats available.")
        else:
            rows = []
            for (key, id_), stat in cs.db.items():
                if id_ != "channelStats":
                    continue
                network, _, channel = key.partition(":")
                rows.append((network, channel, stat))
            channel_stats_html = render.channel_stats_table(rows)

        result, computed_at, error = self._summary_cache.get()
        # Render the heatmap as its own grid rather than letting it fall
        # into aggregate_block's generic JSON dump below -- a 7x24 nested
        # list is unreadable as raw text. `result` is the SAME dict
        # SummaryCache hands to every request (see its own docstring: it
        # never blocks, just returns the last-computed reference), so
        # build a shallow copy minus that one key rather than popping it
        # in place -- mutating the cached dict would corrupt it for every
        # other/future reader.
        heatmap_html = render.activity_heatmap(
            result.get("activity_heatmap") if result else None)
        rest = {k: v for k, v in result.items() if k != "activity_heatmap"} \
            if result else None
        summary_html = render.aggregate_block(
            "Recent activity (tail-bounded, not a strict time window)",
            rest, computed_at, error)

        body = channel_stats_html + heatmap_html + summary_html
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: stats", "Channel + decision stats", body),
               write_content)

    def _route_gate(self, handler, write_content: bool) -> None:
        result, computed_at, error = self._gate_cache.get()
        body = render.aggregate_block(
            "Pre/post evidence-gate A/B (whole corpus)", result, computed_at, error)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: gate", "Evidence gate report", body),
               write_content)

    # ---- commands ----

    def _route_commands(self, handler, write_content: bool) -> None:
        irc = next(iter(world.ircs), None)
        if irc is None:
            body = render.simple_message("No connected networks yet.")
        else:
            entries = []
            for cb in irc.callbacks:
                name = cb.name()
                plugin_group = conf.supybot.plugins.get(name)
                # Same public/private gating already enforced for `list`
                # (scripts/bootstrap_runtime.py sets Owner/Admin/Config
                # non-public; plugins/Misc/plugin.py's patched `list`
                # honors it too) -- this page must not reopen that hole
                # by enumerating commands the IRC side deliberately hides.
                if not plugin_group.public():
                    continue
                command_names = cb.listCommands() if hasattr(cb, "listCommands") else []
                # Raw __doc__ handed to render.py as-is (a plain string
                # or None) -- render.py does the syntax/description
                # parsing and HTML escaping, keeping this module's job
                # limited to "find the data", same division of labor as
                # every other route here.
                commands = [
                    (cname, getattr(getattr(cb, cname, None), "__doc__", None))
                    for cname in sorted(command_names)
                ]
                entries.append((name, commands))
            body = render.commands_list(entries)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: commands", "Bot commands", body), write_content)

    # ---- live preview ----

    def _route_live_index(self, handler, write_content: bool) -> None:
        base_dir = self._plugin.channel_log_dir()
        index = self._log_index(base_dir)
        retention_days = self._plugin.registryValue("partedRetentionDays")
        pairs = [
            (network, channel, self._parted.parted_at(network, channel))
            for (network, channel) in index.keys()
        ]
        body = render.live_index(pairs, retention_days)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: live", "Live channels", body), write_content)

    def _route_live_decisions(self, handler, write_content: bool) -> None:
        refresh_secs = max(3, self._plugin.registryValue("liveRefreshSecs"))
        shild = self._plugin.shild_callback()
        if shild is None:
            body = render.simple_message(
                "Shild plugin is not loaded -- no decision feed available.")
        else:
            n = self._plugin.registryValue("liveDecisionsCount")
            events = shild.context_store().recent_global_events(limit=n)
            body = render.live_decisions(events, refresh_secs)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: live decisions", "Shild decision feed",
                           body, refresh_secs=refresh_secs),
               write_content)

    def _route_live_channel(self, handler, clean_path: str, write_content: bool) -> None:
        # clean_path looks like "/live/<network>/<channel>" -- same
        # split-before-unquote discipline as _route_log_tail.
        parts = clean_path.split("/")
        if len(parts) != 4:
            _write(handler, 404, "text/plain; charset=utf-8", b"Not found.", write_content)
            return
        network = urllib.parse.unquote(parts[2])
        channel = urllib.parse.unquote(parts[3])
        refresh_secs = max(3, self._plugin.registryValue("liveRefreshSecs"))

        source = self._plugin.registryValue("livePreviewSource")
        if source == "none":
            body = render.live_disabled(network, channel)
            _write(handler, 200, "text/html; charset=utf-8",
                   render.page(f"WebPanel: {network}/{channel}",
                               f"{network} / {channel}", body), write_content)
            return

        base_dir = self._plugin.channel_log_dir()
        index = self._log_index(base_dir)
        path = logs.resolve_log(index, base_dir, network, channel)
        if path is None:
            _write(handler, 404, "text/plain; charset=utf-8", b"Not found.", write_content)
            return

        n = self._plugin.registryValue("liveLines")
        max_bytes = self._plugin.registryValue("logTailMaxBytes")
        raw_lines = logs.tail_lines(path, n, max_bytes)
        clean_lines = [ircutils.stripFormatting(line) for line in raw_lines]
        body = render.live_channel(network, channel, clean_lines, refresh_secs)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page(f"WebPanel: {network}/{channel}",
                           f"{network} / {channel}", body, refresh_secs=refresh_secs),
               write_content)

    # ---- file-backed pages ----

    def _log_index(self, base_dir: str) -> dict[tuple[str, str], Path]:
        now = time.time()
        stale = (
            self._log_index_cache is None
            or base_dir != self._log_index_base_dir
            or now - self._log_index_ts > _LOG_INDEX_TTL_SECS
        )
        if stale:
            self._log_index_cache = logs.enumerate_logs(base_dir)
            self._log_index_base_dir = base_dir
            self._log_index_ts = now
        return self._log_index_cache

    def _route_logs_index(self, handler, write_content: bool) -> None:
        base_dir = self._plugin.channel_log_dir()
        index = self._log_index(base_dir)
        retention_days = self._plugin.registryValue("partedRetentionDays")
        entries = []
        for (network, channel), path in sorted(index.items()):
            try:
                st = path.stat()
            except OSError:
                continue
            parted_since = self._parted.parted_at(network, channel)
            entries.append((network, channel, st.st_size, st.st_mtime, parted_since))
        body = render.logs_index(entries, retention_days)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: logs", "Channel logs", body), write_content)

    # ---- parted-channel retention (real deletion -- see parted.py) ----

    def run_parted_maintenance(self) -> None:
        """Called periodically from plugin.py's scheduled event, on
        Limnoria's main thread (needs live irc.state, so it can't run on
        the background SummaryCache threads). Reconciles tracked parted
        state against every connected network's actual join list, then
        deletes any channel's whole log directory once
        partedRetentionDays has elapsed since it was first observed
        parted. Real, irreversible deletion -- see parted.py's module
        docstring for the conservative rules gating detection, and
        _delete_channel_logs below for the path-safety checks gating
        the delete itself.

        2026-08-14 fix: plugin.py's own periodic event fires this with
        `now=True` -- immediately at plugin __init__/_startHttp, i.e. at
        every bot startup/reload, well before any network has actually
        finished joining its channels (a real join takes 5-40+ seconds
        after connect on this deployment -- see CLAUDE.md). A network's
        `Irc` object exists in `world.ircs` the moment a connection is
        ATTEMPTED, long before `irc.state.channels` reflects reality, so
        the old code's "any irc in world.ircs counts as known" logic
        treated that transient empty-channel-list moment as "genuinely
        parted from every single channel" -- confirmed live: every one of
        this deployment's ~13 real channels got mass-marked parted at the
        exact timestamp of a routine restart. A network with ZERO
        currently-joined channels is excluded from `known_networks`
        entirely (same conservative treatment as a network with no live
        connection at all, per parted.py's own module docstring) --
        indistinguishable from "still connecting" in a deployment where
        every configured network always has at least one real channel.
        """
        base_dir = self._plugin.channel_log_dir()
        index = self._log_index(base_dir)
        logged_channels = list(index.keys())

        joined_channels: list[tuple[str, str]] = []
        known_networks: list[str] = []
        for irc in world.ircs:
            if not irc.state.channels:
                continue
            known_networks.append(irc.network)
            for channel in irc.state.channels:
                joined_channels.append((irc.network, channel))

        self._parted.sync(logged_channels, joined_channels, known_networks)

        retention_days = self._plugin.registryValue("partedRetentionDays")
        for network, channel in self._parted.due_for_deletion(retention_days * 86400):
            self._delete_channel_logs(base_dir, network, channel, retention_days)
            self._parted.clear(network, channel)

    def _delete_channel_logs(
        self, base_dir: str, network: str, channel: str, retention_days: int,
    ) -> None:
        """Deletes base_dir/<network>/<channel>/ entirely. Same
        enumerate-then-verify-containment discipline as logs.resolve_log
        -- network/channel here come from THIS process's own tracked
        state (never a raw URL), but a deletion is irreversible, so the
        path-safety check is not skipped just because the input is
        "trusted" this time.
        """
        if not logs.is_safe_segment(network) or not logs.is_safe_segment(channel):
            log.warning("WebPanel: refusing to delete unsafe path segment %r/%r",
                        network, channel)
            return
        try:
            base_resolved = Path(base_dir).resolve()
            resolved = (base_resolved / network / channel).resolve()
        except OSError:
            return
        if base_resolved not in resolved.parents:
            log.warning("WebPanel: refusing to delete path outside channelLogDir: %s",
                        resolved)
            return
        if not resolved.is_dir():
            return  # already gone -- nothing to do, caller still clears tracking
        try:
            shutil.rmtree(resolved)
            log.info(
                "WebPanel: deleted retained logs for %s/%s (parted >= %d days)",
                network, channel, retention_days,
            )
        except OSError:
            log.exception(
                "WebPanel: failed to delete parted-channel logs for %s/%s",
                network, channel,
            )

    def _route_log_tail(self, handler, clean_path: str, params: dict,
                         write_content: bool) -> None:
        # clean_path looks like "/log/<network>/<channel>" -- split
        # BEFORE unquoting each segment, so a %2F inside an encoded
        # segment can't invent an extra path level.
        parts = clean_path.split("/")
        if len(parts) != 4:
            _write(handler, 404, "text/plain; charset=utf-8", b"Not found.", write_content)
            return
        network = urllib.parse.unquote(parts[2])
        channel = urllib.parse.unquote(parts[3])

        base_dir = self._plugin.channel_log_dir()
        index = self._log_index(base_dir)
        path = logs.resolve_log(index, base_dir, network, channel)
        if path is None:
            _write(handler, 404, "text/plain; charset=utf-8", b"Not found.", write_content)
            return

        default_n = self._plugin.registryValue("logTailLines")
        max_bytes = self._plugin.registryValue("logTailMaxBytes")
        # The 50-line floor exists so a client's own ?n= can't request
        # an unhelpfully tiny tail -- but it must never push the
        # effective ceiling ABOVE what the admin configured as
        # logTailLines. If the admin set a ceiling below 50, that
        # smaller ceiling wins on both ends.
        lower = min(_MIN_LOG_TAIL_N, default_n)
        n = _clamp_int(params.get("n", [None])[0], default=default_n,
                        lower=lower, upper=default_n)

        raw_lines = logs.tail_lines(path, n, max_bytes)
        clean_lines = [ircutils.stripFormatting(line) for line in raw_lines]
        body = render.log_tail(network, channel, clean_lines, n)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page(f"WebPanel: {network}/{channel}",
                           f"{network} / {channel}", body), write_content)

    def _route_report(self, handler, params: dict, write_content: bool) -> None:
        report_dir = Path(self._plugin.report_dir())
        if not report_dir.is_dir():
            body = render.simple_message("No reports directory found yet.")
            _write(handler, 200, "text/html; charset=utf-8",
                   render.page("WebPanel: report", "Daily report", body), write_content)
            return

        date_param = (params.get("date") or [None])[0]
        if date_param is not None:
            if not _DATE_RE.match(date_param):
                _write(handler, 404, "text/plain; charset=utf-8",
                       b"Invalid date.", write_content)
                return
            candidate = report_dir / f"{date_param}-report.md"
            if not candidate.is_file():
                _write(handler, 404, "text/plain; charset=utf-8",
                       b"No report for that date.", write_content)
                return
            report_path = candidate
        else:
            candidates = sorted(report_dir.glob("*-report.md"))
            if not candidates:
                body = render.simple_message("No reports yet.")
                _write(handler, 200, "text/html; charset=utf-8",
                       render.page("WebPanel: report", "Daily report", body), write_content)
                return
            report_path = candidates[-1]

        try:
            text = report_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            _write(handler, 404, "text/plain; charset=utf-8",
                   b"Report unreadable.", write_content)
            return

        body = render.plain_text_block(report_path.name, text)
        # The machine-readable companion, if present -- shown as raw
        # (but escaped) JSON for now; a proper table renderer is
        # deferred to a later phase.
        summary_path = report_path.with_name(
            report_path.name.replace("-report.md", "-summary.json"))
        if summary_path.is_file():
            try:
                summary_text = summary_path.read_text(encoding="utf-8", errors="replace")
                body += render.plain_text_block(summary_path.name, summary_text)
            except OSError:
                pass

        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: report", "Daily report", body), write_content)


def _clamp_int(raw: str | None, default: int, lower: int, upper: int) -> int:
    if raw is None:
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return default
    return max(lower, min(value, max(lower, upper)))
