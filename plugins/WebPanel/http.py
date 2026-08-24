"""The only module in WebPanel that imports supybot.httpserver -- routing,
the auth gate, and response headers. All the dangerous logic (password
hashing, Basic-Auth parsing, lockout, path/log handling) lives in pure
modules (auth.py, csrf.py, controls.py, audit.py, and logs.py/render.py/
stats.py) so it gets fast unit tests with no IRC harness; this file just
wires that logic to the actual HTTP request/response objects.

**Write support (2026-08-24)** -- a scoped, allowlisted exception to what
used to be a blanket "phase 1 is read-only" rule. `doPost` now handles
exactly the routes under `/panel/controls/...`; every other path still
gets a bare 405. See plugins/WebPanel/controls.py's module docstring for
the exact allowlist (3 kill switches, 13 per-channel toggles, SpamGuard's
term categories, Shild's ignore list) and csrf.py's module docstring for
the CSRF/Origin defense. `writeEnabled` (config.py) must be explicitly
turned on -- ships inert by default, same as every other real-enforcement
switch in this deployment.

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

from . import audit, auth, controls, csrf, logs, parted, render, stats
from .secrets import CredentialWatcher

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_LOG_INDEX_TTL_SECS = 30.0
_MIN_LOG_TAIL_N = 50
_MAX_SCANS_N = 100

# The 6 IRC-facing term categories offered by the web add form -- see
# controls.py's module docstring for why this is 6, not TermStore's full
# 8 storage categories (word/phrase auto-split on a space, same as the
# `spamguard` IRC command).
_TERM_ADD_CATEGORIES = ("word", "ident", "nick", "realname", "pattern", "black")

# The subdir this callback is hooked at (plugin.py's httpserver.hook call
# must use the same string) -- needed here too because httpserver.py's
# path-stripping leaves a bare "/panel" (no trailing slash) as "/panel",
# not "/" -- see _route's handling of that case.
SUBDIR = "panel"

SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    # "same-origin" (2026-08-24, was "no-referrer") -- the write routes'
    # Origin/Referer CSRF check (csrf.check_origin) needs a real Referer
    # to fall back on when a browser omits Origin; "no-referrer" would
    # have made that fallback dead on arrival for every LEGITIMATE
    # same-origin form POST too, not just attacker traffic. Zero privacy
    # cost: this panel never links anywhere external (confirmed: every
    # href render.py emits is a bare /panel/... path).
    ("Referrer-Policy", "same-origin"),
    ("Content-Security-Policy",
     "default-src 'none'; style-src 'self'; img-src 'self'; "
     # form-action/frame-ancestors (2026-08-24) -- default-src 'none'
     # does NOT cover either directive; added now that render.py emits
     # actual <form> elements for the first time.
     "form-action 'self'; frame-ancestors 'none'"),
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
    # 2026-08-24: marks the per-request `handler` object (never the
    # shared callback -- see module docstring) as having received a real
    # response, so doPost's outer try/except (below) can tell "a handler
    # already answered, possibly then raised" apart from "nothing was
    # ever written" before deciding whether a fallback 500 is needed.
    handler._webpanel_responded = True


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
        # Write-support machinery (2026-08-24) -- see controls.py's/
        # csrf.py's own module docstrings for the design. The signing key
        # is regenerated on every construction (i.e. every @reload
        # WebPanel or enable toggle), which deliberately invalidates any
        # currently-open write form -- an accepted tradeoff, not an
        # oversight (see csrf.py's TokenSigner docstring).
        self._csrf = csrf.TokenSigner(bucket_secs=plugin.registryValue("csrfTokenTtlSecs"))
        self._audit = audit.AuditLog(plugin.registryValue("auditPath"))
        # Populated by run_controls_warm() (main thread only, via a
        # periodic event in plugin.py) -- the channel picker on
        # /panel/controls reads this rather than touching irc.state
        # itself, since this callback's own methods run on the HTTP
        # thread. Empty until the first warm pass completes.
        self._controls_channels: tuple[tuple[str, str], ...] = ()

    # ---- httpserver entry points ----

    def doGetOrHead(self, handler, path, write_content):
        if not self._gate(handler, path, write_content):
            return
        self._route(handler, path, write_content)

    def doPost(self, handler, path, form=None):
        # Wrapped in a real try/except (2026-08-24) rather than relying
        # solely on supybot's own __firewalled__ swallow -- that swallow
        # is silent in production (only re-raises under world.testing),
        # which used to mean an uncaught exception here left the client
        # with a dropped connection and nothing but a log line. `_write`
        # marks `handler._webpanel_responded` the moment any response is
        # actually sent, so this only emits a fallback 500 if a handler
        # raised BEFORE writing anything at all -- never a double
        # response.
        try:
            self._dispatch_post(handler, path, form)
        except Exception:
            if not getattr(handler, "_webpanel_responded", False):
                log.exception("WebPanel: unhandled error in doPost")
                _write(handler, 500, "text/plain; charset=utf-8", b"Internal error.")
            else:
                log.exception("WebPanel: error in doPost after a response was already sent")

    def doHook(self, handler, subdir):
        self._summary_cache.start()
        self._gate_cache.start()

    def doUnhook(self, handler):
        self._summary_cache.stop()
        self._gate_cache.stop()

    # ---- auth gate ----

    def _gate(self, handler, path: str, write_content: bool) -> bool:
        """Host allowlist + Basic-Auth check -- shared by GET/HEAD
        (doGetOrHead) and POST (_dispatch_post below). Returns True if
        the request may proceed (nothing written yet); False means a
        response has already been sent and the caller must stop.
        Extracted 2026-08-24 from what used to be GET-only `_dispatch`
        logic specifically so POST goes through the IDENTICAL Host/auth
        gate instead of bypassing it entirely, which is what the old
        bare-405 doPost always did.
        """
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
            return False

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
            return False
        if result == auth.AuthResult.LOCKED:
            _write(handler, 429, "text/plain; charset=utf-8",
                   b"Too many failed attempts. Try again later.",
                   write_content, extra_headers=(("Retry-After", "60"),))
            return False
        if result == auth.AuthResult.UNAUTHORIZED:
            self._log_failure(client_ip)
            _write(handler, 401, "text/plain; charset=utf-8",
                   b"Unauthorized.", write_content,
                   extra_headers=(
                       ("WWW-Authenticate",
                        'Basic realm="shild-py panel", charset="UTF-8"'),
                   ))
            return False

        return True

    def _actor(self, handler) -> str:
        """The authenticated username, for the audit log only -- never
        used for any access-control decision (there's only one shared
        panel identity; see auth.py). Re-parses the Authorization header
        rather than threading a value through from _gate, since doPost's
        gate chain and its handlers are separate calls."""
        parsed = auth.parse_basic_auth(handler.headers.get("Authorization"))
        return parsed[0] if parsed else "?"

    def _csrf_ok(self, form, scope: str) -> bool:
        return self._csrf.verify(form.getfirst("csrf"), scope)

    def _flash_html(self, params: dict) -> str:
        code = (params.get("flash") or [None])[0]
        arg = (params.get("arg") or [None])[0]
        result = controls.flash_for(code, arg)
        if result is None:
            return ""
        level, message = result
        return render.flash_banner(level, message)

    def _redirect(self, handler, location: str, code: "str | None" = None,
                  arg: "str | None" = None) -> None:
        query: dict[str, str] = {}
        if code:
            query["flash"] = code
        if arg:
            query["arg"] = arg
        full = location + ("?" + urllib.parse.urlencode(query) if query else "")
        _write(handler, 303, "text/plain; charset=utf-8", b"",
               extra_headers=(("Location", full),))

    def _resolve_toggle_node(self, plugin_name: str, path: "tuple[str, ...]"):
        """Walks a FIXED, hardcoded path (controls.ChannelToggle.path /
        GlobalSwitch.path -- never request-controlled) from a plugin's
        registry root down to the target Value node. Safe to call
        node-creating `.get()` along the way here: every path segment
        names a permanently-registered group/value (e.g. "protection",
        "killSwitch"), never a channel/network name -- those only ever
        appear as the LAST hop inside controls.py's own peek/warm/write
        helpers, which handle that risk separately."""
        group = getattr(conf.supybot.plugins, plugin_name, None)
        if group is None:
            return None
        node = group
        for part in path:
            node = node.get(part)
        return node

    # ---- write dispatch (2026-08-24) ----

    def _dispatch_post(self, handler, path: str, form) -> None:
        """Gate order (each layer independently tested):
        writeEnabled -> Host+auth (_gate) -> Content-Type duck-typing ->
        Origin/Referer check -> route match -> (inside each handler)
        CSRF token check -> field validation. See csrf.py's module
        docstring for why Origin/Referer is checked before the route
        even matches (cheap, and rejects the vast majority of forged
        cross-site traffic before any real work happens), while the CSRF
        TOKEN check happens per-handler instead -- its correct `scope`
        argument depends on which route matched (e.g. a per-channel
        page's scope includes the network/channel), so it can't be
        checked generically before that's known.
        """
        if not self._plugin.registryValue("writeEnabled"):
            _write(handler, 403, "text/plain; charset=utf-8",
                   b"Writing from the panel is currently disabled.")
            return
        if not self._gate(handler, path, True):
            return
        if not hasattr(form, "getfirst"):
            # A non-urlencoded Content-Type (httpserver.py's do_POST
            # matches it by exact string equality, defaulting to
            # urlencoded only when the header is absent) arrives as raw
            # bytes instead of the HttpHeaders form object every handler
            # below assumes -- duck-typed check rather than inspecting
            # Content-Type directly, since that header's exact spelling
            # (e.g. a trailing "; charset=utf-8") isn't something to
            # depend on either.
            _write(handler, 415, "text/plain; charset=utf-8",
                   b"Unsupported Content-Type.")
            return
        origin_result = csrf.check_origin(
            handler.headers.get("Origin"),
            handler.headers.get("Referer"),
            self._plugin.registryValue("allowedHosts"),
        )
        if origin_result != csrf.OriginResult.OK:
            _write(handler, 403, "text/plain; charset=utf-8",
                   b"Origin/Referer check failed.")
            return

        clean_path, _, _query = path.partition("?")
        self._route_post(handler, clean_path, form)

    def _route_post(self, handler, clean_path: str, form) -> None:
        if clean_path == "/controls/killswitch":
            self._post_killswitch(handler, form)
            return
        if clean_path == "/controls/ignore":
            self._post_ignore(handler, form)
            return
        if clean_path.startswith("/controls/channel/"):
            self._post_channel(handler, clean_path, form)
            return
        if clean_path == "/controls/terms/add":
            self._post_term_add(handler, form)
            return
        if clean_path == "/controls/terms/remove":
            self._post_term_remove(handler, form)
            return
        _write(handler, 405, "text/plain; charset=utf-8", b"Method not allowed.")

    def _post_killswitch(self, handler, form) -> None:
        if not self._csrf_ok(form, "controls"):
            self._redirect(handler, "/panel/controls", "csrf_expired")
            return
        switch = controls.global_switch_by_key(form.getfirst("key", "") or "")
        if switch is None:
            self._redirect(handler, "/panel/controls", "invalid_input", "key")
            return
        value = controls.parse_bool(form.getfirst("value"))
        if value is None:
            self._redirect(handler, "/panel/controls", "invalid_input", "value")
            return
        if value == switch.dangerous_value and form.getfirst("confirm") != "1":
            self._redirect(handler, "/panel/controls", "confirmation_required")
            return
        node = self._resolve_toggle_node(switch.plugin, switch.path)
        if node is None:
            self._redirect(handler, "/panel/controls", "plugin_not_loaded", switch.plugin)
            return
        node.setValue(value)
        self._audit.record(
            action="killswitch_set", actor=self._actor(handler),
            client_ip=handler.address_string(),
            detail={"key": switch.key, "value": value},
        )
        self._redirect(handler, "/panel/controls", "killswitch_set")

    def _post_ignore(self, handler, form) -> None:
        if not self._csrf_ok(form, "controls"):
            self._redirect(handler, "/panel/controls", "csrf_expired")
            return
        action = form.getfirst("action", "") or ""
        host = (form.getfirst("host", "") or "").strip()
        shild = self._plugin.shild_callback()
        if shild is None:
            self._redirect(handler, "/panel/controls", "plugin_not_loaded", "Shild")
            return
        if action == "add":
            ok, code = shild.web_add_ignore(host)
        elif action == "remove":
            ok, code = shild.web_remove_ignore(host)
        else:
            self._redirect(handler, "/panel/controls", "invalid_input", "action")
            return
        if not ok:
            self._redirect(handler, "/panel/controls", code, host)
            return
        self._audit.record(
            action=f"ignore_{action}", actor=self._actor(handler),
            client_ip=handler.address_string(), detail={"host": host},
        )
        self._redirect(handler, "/panel/controls", code, host)

    def _post_channel(self, handler, clean_path: str, form) -> None:
        # clean_path looks like "/controls/channel/<network>/<channel>"
        # -- same split-before-unquote discipline as _route_log_tail.
        parts = clean_path.split("/")
        if len(parts) != 5:
            _write(handler, 404, "text/plain; charset=utf-8", b"Not found.")
            return
        network = urllib.parse.unquote(parts[3])
        channel = urllib.parse.unquote(parts[4])
        location = "/panel/controls/channel/%s/%s" % (
            urllib.parse.quote(network, safe=""), urllib.parse.quote(channel, safe=""))
        scope = f"controls-channel:{network}:{channel}"

        if not self._csrf_ok(form, scope):
            self._redirect(handler, location, "csrf_expired")
            return
        toggle = controls.channel_toggle_by_key(form.getfirst("key", "") or "")
        if toggle is None:
            self._redirect(handler, location, "invalid_input", "key")
            return
        value = controls.parse_bool(form.getfirst("value"))
        if value is None:
            self._redirect(handler, location, "invalid_input", "value")
            return
        node = self._resolve_toggle_node(toggle.plugin, toggle.path)
        if node is None:
            self._redirect(handler, location, "plugin_not_loaded", toggle.plugin)
            return
        if not controls.write_channel_value(node, network, channel, value):
            self._redirect(handler, location, "channel_not_ready")
            return
        self._audit.record(
            action="channel_toggle_set", actor=self._actor(handler),
            client_ip=handler.address_string(),
            detail={"network": network, "channel": channel, "key": toggle.key, "value": value},
        )
        self._redirect(handler, location, "channel_toggle_set", toggle.label)

    def _post_term_add(self, handler, form) -> None:
        if not self._csrf_ok(form, "controls-terms"):
            self._redirect(handler, "/panel/controls/terms", "csrf_expired")
            return
        category = form.getfirst("category", "") or ""
        text = (form.getfirst("text", "") or "").strip()
        if not text:
            self._redirect(handler, "/panel/controls/terms", "invalid_input", "text")
            return
        spamguard = self._plugin.spamguard_callback()
        if spamguard is None:
            self._redirect(handler, "/panel/controls/terms", "plugin_not_loaded", "SpamGuard")
            return
        ok, error_code = spamguard.web_add_term(
            category, text, added_by=self._actor(handler))
        if not ok:
            self._redirect(handler, "/panel/controls/terms", error_code, text)
            return
        self._audit.record(
            action="term_added", actor=self._actor(handler),
            client_ip=handler.address_string(), detail={"category": category, "text": text},
        )
        self._redirect(handler, "/panel/controls/terms", "term_added", text)

    def _post_term_remove(self, handler, form) -> None:
        if not self._csrf_ok(form, "controls-terms"):
            self._redirect(handler, "/panel/controls/terms", "csrf_expired")
            return
        try:
            term_id = int(form.getfirst("term_id", "") or "")
        except (TypeError, ValueError):
            self._redirect(handler, "/panel/controls/terms", "invalid_input", "term_id")
            return
        spamguard = self._plugin.spamguard_callback()
        if spamguard is None:
            self._redirect(handler, "/panel/controls/terms", "plugin_not_loaded", "SpamGuard")
            return
        if not spamguard.web_remove_term_by_id(term_id):
            self._redirect(handler, "/panel/controls/terms", "term_not_found")
            return
        self._audit.record(
            action="term_removed", actor=self._actor(handler),
            client_ip=handler.address_string(), detail={"term_id": term_id},
        )
        self._redirect(handler, "/panel/controls/terms", "term_removed", str(term_id))

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

        if clean_path in ("/controls", "/controls/"):
            self._route_controls(handler, params, write_content)
            return

        if clean_path in ("/controls/terms", "/controls/terms/"):
            self._route_controls_terms(handler, params, write_content)
            return

        if clean_path.startswith("/controls/channel/"):
            self._route_controls_channel(handler, clean_path, params, write_content)
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

    # ---- controls (write surface, 2026-08-24) ----

    def _route_controls(self, handler, params: dict, write_content: bool) -> None:
        write_enabled = self._plugin.registryValue("writeEnabled")
        flash_html = self._flash_html(params)
        token = self._csrf.issue("controls")
        switches = []
        for switch in controls.GLOBAL_SWITCHES:
            node = self._resolve_toggle_node(switch.plugin, switch.path)
            switches.append((switch, bool(node()) if node is not None else None,
                              node is not None))
        shild = self._plugin.shild_callback()
        ignore_hosts = list(shild.registryValue("ignoreList")) if shild is not None else []
        body = render.controls_overview(
            switches, ignore_hosts, self._controls_channels, token, flash_html, write_enabled)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: controls", "Controls", body), write_content)

    def _route_controls_channel(self, handler, clean_path: str, params: dict,
                                 write_content: bool) -> None:
        # clean_path looks like "/controls/channel/<network>/<channel>"
        # -- same split-before-unquote discipline as _route_log_tail.
        parts = clean_path.split("/")
        if len(parts) != 5:
            _write(handler, 404, "text/plain; charset=utf-8", b"Not found.", write_content)
            return
        network = urllib.parse.unquote(parts[3])
        channel = urllib.parse.unquote(parts[4])
        write_enabled = self._plugin.registryValue("writeEnabled")
        flash_html = self._flash_html(params)
        token = self._csrf.issue(f"controls-channel:{network}:{channel}")
        rows = []
        for toggle in controls.CHANNEL_TOGGLES:
            node = self._resolve_toggle_node(toggle.plugin, toggle.path)
            if node is None:
                continue  # plugin not loaded -- this toggle just doesn't appear
            ready = controls.channel_nodes_ready(node, network, channel)
            current = controls.peek_channel_value(node, network, channel)
            rows.append((toggle.key, toggle.label, toggle.help, current, ready))
        body = render.controls_channel(network, channel, rows, token, flash_html, write_enabled)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page(f"WebPanel: controls {network}/{channel}",
                           f"{network} / {channel} settings", body), write_content)

    def _route_controls_terms(self, handler, params: dict, write_content: bool) -> None:
        flash_html = self._flash_html(params)
        token = self._csrf.issue("controls-terms")
        spamguard = self._plugin.spamguard_callback()
        if spamguard is None:
            body = flash_html + render.controls_unavailable("SpamGuard")
        else:
            write_enabled = self._plugin.registryValue("writeEnabled")
            terms = [
                (t.id, t.category, t.text, t.added_by, t.added_at)
                for t in spamguard.all_terms()
            ]
            body = render.controls_terms(
                _TERM_ADD_CATEGORIES, terms, token, flash_html, write_enabled)
        _write(handler, 200, "text/html; charset=utf-8",
               render.page("WebPanel: terms", "SpamGuard terms", body), write_content)

    def run_controls_warm(self) -> None:
        """MAIN-THREAD ONLY -- called from plugin.py's periodic warm
        event. The single place in this whole plugin that's allowed to
        create per-channel registry nodes (see controls.py's own module
        docstring for exactly why that's unsafe from the HTTP thread) and
        the only place that reads irc.state at all. Same "empty channel
        list = still connecting, not genuinely known" conservative
        exclusion already established by run_parted_maintenance above --
        this is deliberately the identical guard, not a coincidence."""
        channels: list[tuple[str, str]] = []
        for irc in world.ircs:
            if not irc.state.channels:
                continue
            for channel in irc.state.channels:
                channels.append((irc.network, channel))

        for toggle in controls.CHANNEL_TOGGLES:
            node = self._resolve_toggle_node(toggle.plugin, toggle.path)
            if node is None:
                continue
            for network, channel in channels:
                controls.warm_channel_nodes(node, network, channel)

        self._controls_channels = tuple(sorted(set(channels)))

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
