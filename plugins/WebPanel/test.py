"""Limnoria PluginTestCase tests for WebPanel -- covers the HTTP/auth
wiring in http.py + plugin.py that tests/test_webpanel_auth.py (the pure
pytest suite) can't reach, since that needs supybot's actual httpserver
routing and request/response objects.

Two TestCase classes: WebPanelHTTPTestCase loads ONLY WebPanel (proving
every route -- including the Shild-backed ones -- degrades to a real 200
with a "not loaded" notice rather than erroring, since a WebPanel deploy
must not assume Shild is present); WebPanelWithShildTestCase loads both,
to exercise the real overview/scans data path.
"""
from __future__ import annotations

import io
import json
import tempfile
import time
from pathlib import Path

import numpy as np
import supybot.conf as conf
import supybot.httpserver as httpserver
import supybot.ircmsgs as ircmsgs
from supybot.test import ChannelHTTPPluginTestCase, TestRequestHandler

from shildml import artifact, features

from .auth import hash_password


def _write_dummy_model(path, bias_toward: str = "allow"):
    """A tiny hand-built model that always predicts `bias_toward`, so
    WebPanelWithShildTestCase below doesn't depend on a real trained
    artifact. Deliberately a LOCAL copy of
    plugins/Shild/test.py's `_write_dummy_model` rather than an import
    from it -- `from Shild.test import ...` at this module's top level
    bit us for real: plugins/WebPanel/__init__.py's `from . import test`
    (guarded by world.testing) runs the first time ANYTHING imports the
    WebPanel package, which can happen during supybot-test's plugin
    discovery before Shild has been imported at all, however that
    particular test run happens to enumerate --plugins-dir -- producing
    a `ModuleNotFoundError: No module named 'Shild'` that only showed up
    on some invocations, not others. shildml (unlike Shild the plugin
    package) is pip-installed and always importable regardless of any
    plugin-loading order, so this has no equivalent failure mode.
    """
    n_actions = len(features.ACTIONS)
    idx = features.ACTION_IDX[bias_toward]
    margin = 10.0
    layer_spec = [
        {"w": np.zeros((64, features.N_FEATURES), dtype="float32"),
         "b": np.zeros(64, dtype="float32"), "act": "relu"},
        {"w": np.zeros((32, 64), dtype="float32"),
         "b": np.zeros(32, dtype="float32"), "act": "relu"},
        {"w": np.zeros((n_actions, 32), dtype="float32"),
         "b": np.array([margin if i == idx else -margin for i in range(n_actions)],
                        dtype="float32"),
         "act": None},
    ]
    artifact.save(path, layer_spec, {
        "trained_at": "test", "train_rows": 0, "label_distribution": {},
        "split_strategy": "none", "val_metrics": {},
    })

TEST_USER = "testuser"
TEST_PASS = "testpass"


class _AddressedTestRequestHandler(TestRequestHandler):
    """supybot.test's own TestRequestHandler never sets client_address
    (its __init__ skips BaseHTTPRequestHandler.__init__ entirely), so
    handler.address_string() -- which WebPanelCallback needs for lockout
    accounting -- raises AttributeError under this test harness. This is
    purely a test-harness gap; the real server always has a real
    client_address supplied by socketserver. Default IP is fixed so
    lockout tests are deterministic across calls within one test.
    """

    def __init__(self, rfile, wfile, client_address=("127.0.0.1", 12345)):
        self.client_address = client_address
        super().__init__(rfile, wfile)


def _basic_auth_header(username: str, password: str) -> str:
    import base64
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def _raw_request(method: str, url: str, headers: dict | None = None,
                  client_address=("127.0.0.1", 12345)):
    """supybot.test.HTTPPluginTestCase.request() has no way to attach
    custom headers (Authorization, Host), which every meaningful WebPanel
    test needs -- so this builds a raw HTTP/1.0 request directly and
    drives it through TestRequestHandler, same technique the plan calls
    for. Returns (status, body_bytes).
    """
    headers = headers or {}
    lines = [f"{method} {url} HTTP/1.0"]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    lines.append("")
    lines.append("")
    raw = "\r\n".join(lines).encode("utf-8")
    rfile = io.BytesIO(raw)
    wfile = io.BytesIO()
    handler = _AddressedTestRequestHandler(rfile, wfile, client_address=client_address)
    wfile.seek(0)
    return handler._response, wfile.read()


DEFAULT_HEADERS = {"Host": "127.0.0.1:8080"}


class WebPanelHTTPTestCase(ChannelHTTPPluginTestCase):
    plugins = ("WebPanel",)
    config = {
        "servers.http.keepAlive": True,
        "plugins.WebPanel.enable": False,
        # Low iteration count elsewhere (see setUp's stored hash) keeps
        # this suite fast; lockout tuned tight so the lockout test
        # doesn't need many requests.
        "plugins.WebPanel.maxAuthFailures": 3,
        "plugins.WebPanel.authLockoutSecs": 60,
        "plugins.WebPanel.partedRetentionDays": 7,
    }

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        secrets_path = Path(self._tmpdir) / "secrets.json"
        secrets_path.write_text(json.dumps({
            "web_panel_user": TEST_USER,
            # Low iteration count -- this is a test fixture, not a real
            # deployment, and 600k iterations x dozens of test requests
            # would make the suite noticeably slow for no benefit.
            "web_panel_password_hash": hash_password(TEST_PASS, iterations=100),
        }))
        conf.supybot.plugins.WebPanel.secretsPath.setValue(str(secrets_path))
        conf.supybot.plugins.WebPanel.allowedHosts.setValue(
            ["127.0.0.1:8080", "localhost:8080"])

        self._log_dir = Path(self._tmpdir) / "logs"
        (self._log_dir / "libera" / "#windrop").mkdir(parents=True)
        (self._log_dir / "libera" / "#windrop" / "#windrop.log").write_text(
            "line one\nline two\nline three\n")
        conf.supybot.plugins.WebPanel.channelLogDir.setValue(str(self._log_dir))
        # Never the real runtime/webpanel_parted.json -- each test gets
        # its own empty, isolated tracking file.
        conf.supybot.plugins.WebPanel.partedStatePath.setValue(
            str(Path(self._tmpdir) / "webpanel_parted.json"))

        self._report_dir = Path(self._tmpdir) / "daily_analysis"
        conf.supybot.plugins.WebPanel.reportDir.setValue(str(self._report_dir))

        # WebPanel.shadowDataPath defaults to "" ("derive from Shild's own
        # shadowDataPath") for every test below that doesn't explicitly
        # override it -- and Shild isn't loaded in this class, so nothing
        # else ever points Shild.shadowDataPath anywhere. Its registered
        # default (plugins/Shild/config.py) is the RELATIVE path
        # "data/shadow_decisions.jsonl", which resolves against the
        # process cwd -- exactly the real, live production file when
        # supybot-test is run from the repo root the normal way. Found
        # 2026-08-09 as a real hang, not just a theoretical leak: with the
        # live bot actually running and appending to that file every few
        # seconds, /panel/stats's background SummaryCache never sees the
        # file settle and recomputes forever. Point it at a path under
        # this test's own isolated tmpdir (fine that it doesn't exist --
        # that's exactly what test_stats_summary_not_computed_yet_is_not_an_error
        # below is asserting stays a clean 200) and restore the real
        # default afterward, same "don't leak into a later class in the
        # same process" reasoning as the WebPanel.shadowDataPath reset below.
        self._orig_shild_shadow_data_path = conf.supybot.plugins.Shild.shadowDataPath()
        conf.supybot.plugins.Shild.shadowDataPath.setValue(
            str(Path(self._tmpdir) / "data" / "shadow_decisions.jsonl"))

        super(ChannelHTTPPluginTestCase, self).setUp()
        httpserver.startServer()

    def tearDown(self):
        httpserver.stopServer()
        # A few tests below set plugins.WebPanel.shadowDataPath directly
        # via conf...setValue() (not through this class's `config` dict,
        # which is all PluginTestCase's own restore machinery tracks) --
        # reset it here so it can't leak into a later test/class in the
        # same process. Same class of bug as the logTailLines leak fixed
        # in test_log_tail_n_param_clamped; this one is class-wide since
        # three separate tests touch it.
        conf.supybot.plugins.WebPanel.shadowDataPath.setValue("")
        conf.supybot.plugins.Shild.shadowDataPath.setValue(
            self._orig_shild_shadow_data_path)
        super(ChannelHTTPPluginTestCase, self).tearDown()

    # ---- hook/unhook via the enable toggle ----

    def test_disabled_by_default_is_404(self):
        # Not hooked at all -- httpserver's own Supy404, proves the
        # plugin didn't hook on load since config defaults enable=False.
        status, _body = _raw_request("GET", "/panel/health", DEFAULT_HEADERS)
        self.assertEqual(status, 404)

    def test_enable_toggle_hooks_and_unhooks_live(self):
        status, _ = _raw_request("GET", "/panel/health", DEFAULT_HEADERS)
        self.assertEqual(status, 404)

        self.assertNotError("config plugins.WebPanel.enable True")
        status, _ = _raw_request("GET", "/panel/health", DEFAULT_HEADERS)
        # Hooked now -- auth gate kicks in (no credentials sent), proving
        # both that hooking worked AND that auth isn't bypassable.
        self.assertEqual(status, 401)

        self.assertNotError("config plugins.WebPanel.enable False")
        status, _ = _raw_request("GET", "/panel/health", DEFAULT_HEADERS)
        self.assertEqual(status, 404)

    # ---- auth gate ----

    def test_missing_credentials_401_with_challenge(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        status, body = _raw_request("GET", "/panel/health", DEFAULT_HEADERS)
        self.assertEqual(status, 401)

    def test_wrong_password_401(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = dict(DEFAULT_HEADERS,
                       Authorization=_basic_auth_header(TEST_USER, "wrongpass"))
        status, _ = _raw_request("GET", "/panel/health", headers)
        self.assertEqual(status, 401)

    def test_correct_credentials_200(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = dict(DEFAULT_HEADERS,
                       Authorization=_basic_auth_header(TEST_USER, TEST_PASS))
        status, body = _raw_request("GET", "/panel/health", headers)
        self.assertEqual(status, 200)
        self.assertEqual(body.strip(), b"ok")

    def test_lockout_after_repeated_failures(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = dict(DEFAULT_HEADERS,
                       Authorization=_basic_auth_header(TEST_USER, "wrongpass"))
        # maxAuthFailures is 3 (see class config above).
        for _ in range(3):
            status, _ = _raw_request("GET", "/panel/health", headers)
            self.assertEqual(status, 401)
        status, _ = _raw_request("GET", "/panel/health", headers)
        self.assertEqual(status, 429)
        # Even the CORRECT password is rejected while locked out.
        good = dict(DEFAULT_HEADERS,
                    Authorization=_basic_auth_header(TEST_USER, TEST_PASS))
        status, _ = _raw_request("GET", "/panel/health", good)
        self.assertEqual(status, 429)

    def test_bad_host_header_400(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = {
            "Host": "evil.example.com",
            "Authorization": _basic_auth_header(TEST_USER, TEST_PASS),
        }
        status, _ = _raw_request("GET", "/panel/health", headers)
        self.assertEqual(status, 400)

    def test_missing_host_header_400(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = {"Authorization": _basic_auth_header(TEST_USER, TEST_PASS)}
        status, _ = _raw_request("GET", "/panel/health", headers)
        self.assertEqual(status, 400)

    def test_no_credentials_configured_returns_503(self):
        # Blank out the secrets file entirely -- the fail-closed path.
        conf.supybot.plugins.WebPanel.secretsPath.setValue(
            str(Path(self._tmpdir) / "does-not-exist.json"))
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = dict(DEFAULT_HEADERS,
                       Authorization=_basic_auth_header(TEST_USER, TEST_PASS))
        status, _ = _raw_request("GET", "/panel/health", headers)
        self.assertEqual(status, 503)

    # ---- routing ----

    def test_post_is_405(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = dict(DEFAULT_HEADERS,
                       Authorization=_basic_auth_header(TEST_USER, TEST_PASS))
        status, _ = _raw_request("POST", "/panel/health", headers)
        self.assertEqual(status, 405)

    def test_bare_panel_redirects(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = dict(DEFAULT_HEADERS,
                       Authorization=_basic_auth_header(TEST_USER, TEST_PASS))
        status, _ = _raw_request("GET", "/panel", headers)
        self.assertEqual(status, 301)

    def test_unknown_authenticated_path_404(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = dict(DEFAULT_HEADERS,
                       Authorization=_basic_auth_header(TEST_USER, TEST_PASS))
        status, _ = _raw_request("GET", "/panel/nosuchpage", headers)
        self.assertEqual(status, 404)

    # ---- shild not loaded still works ----

    def test_health_ok_without_shild_loaded(self):
        # plugins=("WebPanel",) above already means Shild is never loaded
        # in this suite -- this test exists to name that guarantee
        # explicitly rather than leave it implicit.
        self.assertNotError("config plugins.WebPanel.enable True")
        headers = dict(DEFAULT_HEADERS,
                       Authorization=_basic_auth_header(TEST_USER, TEST_PASS))
        status, _ = _raw_request("GET", "/panel/health", headers)
        self.assertEqual(status, 200)

    # ---- file-backed pages: logs ----

    def _auth_headers(self):
        return dict(DEFAULT_HEADERS,
                    Authorization=_basic_auth_header(TEST_USER, TEST_PASS))

    def test_logs_index_lists_enumerated_channel(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        status, body = _raw_request("GET", "/panel/logs", self._auth_headers())
        self.assertEqual(status, 200)
        self.assertIn(b"libera", body)
        self.assertIn(b"#windrop", body)

    def test_logs_index_requires_auth(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        status, _ = _raw_request("GET", "/panel/logs", DEFAULT_HEADERS)
        self.assertEqual(status, 401)

    def test_log_tail_returns_lines(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        status, body = _raw_request(
            "GET", "/panel/log/libera/%23windrop", self._auth_headers())
        self.assertEqual(status, 200)
        self.assertIn(b"line one", body)
        self.assertIn(b"line three", body)

    def test_log_tail_unknown_channel_404(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        status, _ = _raw_request(
            "GET", "/panel/log/libera/%23nosuchchannel", self._auth_headers())
        self.assertEqual(status, 404)

    def test_log_tail_path_traversal_dotdot_404(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        # ".." as the network segment -- must never escape channelLogDir.
        status, body = _raw_request(
            "GET", "/panel/log/../%23windrop", self._auth_headers())
        self.assertEqual(status, 404)

    def test_log_tail_path_traversal_encoded_404(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        # A literal %2e%2e%2f embedded in a segment decodes to "../" --
        # since we split on "/" BEFORE unquoting, this can only ever be
        # looked up as a literal (and unknown) key, never interpreted as
        # a path separator. Must 404, never 200/500.
        status, body = _raw_request(
            "GET", "/panel/log/x/%2e%2e%2fetc%2fpasswd", self._auth_headers())
        self.assertEqual(status, 404)

    def test_log_tail_embedded_slash_via_double_encoding_404(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        # %2F decodes to "/" -- if unquoting happened before splitting,
        # this would smuggle in an extra path segment. It must not.
        status, _ = _raw_request(
            "GET", "/panel/log/libera/%23wind%2f..%2f..%2fetc%2fpasswd",
            self._auth_headers())
        self.assertEqual(status, 404)

    def test_log_tail_n_param_clamped(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        # Set via the registry directly (not "config ..." over IRC) and
        # restored in finally -- an IRC-issued @config change isn't
        # tracked by PluginTestCase's own config-restore machinery (that
        # only restores values set through this class's `config` dict at
        # setUp), so leaving it set would leak into every later test in
        # this file that shares the same process-wide registry value.
        original = conf.supybot.plugins.WebPanel.logTailLines()
        conf.supybot.plugins.WebPanel.logTailLines.setValue(2)
        try:
            status, body = _raw_request(
                "GET", "/panel/log/libera/%23windrop?n=999", self._auth_headers())
        finally:
            conf.supybot.plugins.WebPanel.logTailLines.setValue(original)
        self.assertEqual(status, 200)
        # Clamped to logTailLines=2 -- "line one" (the oldest of 3) must
        # have been dropped.
        self.assertNotIn(b"line one", body)
        self.assertIn(b"line three", body)

    def test_log_tail_escapes_script_content(self):
        (self._log_dir / "libera" / "#windrop" / "#windrop.log").write_text(
            "<script>alert(1)</script>\n")
        status, body = self._enable_and_get(
            "/panel/log/libera/%23windrop")
        self.assertEqual(status, 200)
        self.assertNotIn(b"<script>alert(1)</script>", body)

    def _enable_and_get(self, path):
        self.assertNotError("config plugins.WebPanel.enable True")
        return _raw_request("GET", path, self._auth_headers())

    # ---- file-backed pages: report ----

    def test_report_no_directory_yet_200_with_message(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        status, body = _raw_request("GET", "/panel/report", self._auth_headers())
        self.assertEqual(status, 200)
        self.assertIn(b"No reports", body)

    def test_report_latest_returned(self):
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-05-report.md").write_text("older report")
        (self._report_dir / "2026-08-06-report.md").write_text("newest report")
        status, body = self._enable_and_get("/panel/report")
        self.assertEqual(status, 200)
        self.assertIn(b"newest report", body)
        self.assertNotIn(b"older report", body)

    def test_report_specific_date(self):
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-05-report.md").write_text("older report")
        (self._report_dir / "2026-08-06-report.md").write_text("newest report")
        status, body = self._enable_and_get("/panel/report?date=2026-08-05")
        self.assertEqual(status, 200)
        self.assertIn(b"older report", body)

    def test_report_invalid_date_404(self):
        self._report_dir.mkdir(parents=True)
        status, _ = self._enable_and_get("/panel/report?date=not-a-date")
        self.assertEqual(status, 404)

    def test_report_date_path_traversal_404(self):
        self._report_dir.mkdir(parents=True)
        status, _ = self._enable_and_get(
            "/panel/report?date=..%2f..%2f..%2fetc%2fpasswd")
        self.assertEqual(status, 404)

    def test_report_includes_summary_json(self):
        self._report_dir.mkdir(parents=True)
        (self._report_dir / "2026-08-06-report.md").write_text("the report body")
        (self._report_dir / "2026-08-06-summary.json").write_text(
            '{"total_rows": 42}')
        status, body = self._enable_and_get("/panel/report")
        self.assertEqual(status, 200)
        self.assertIn(b"the report body", body)
        self.assertIn(b"total_rows", body)

    # ---- Shild-backed pages: graceful degradation when Shild isn't loaded ----

    def test_overview_without_shild_shows_notice_not_error(self):
        status, body = self._enable_and_get("/panel/")
        self.assertEqual(status, 200)
        self.assertIn(b"not loaded", body)

    def test_scans_without_shild_still_works_from_disk(self):
        # /panel/scans reads shadow_decisions.jsonl directly -- it must
        # work even with Shild unloaded, same as the logs/report pages.
        data_path = Path(self._tmpdir) / "shadow.jsonl"
        data_path.write_text(json.dumps({
            "ts": 1700000000.0, "network": "libera", "channel": "#windrop",
            "nick": "alice", "host": "1.2.3.4",
            "fused": {"action": "allow", "confidence": 0.9, "source": "classifier"},
        }) + "\n")
        conf.supybot.plugins.WebPanel.shadowDataPath.setValue(str(data_path))
        status, body = self._enable_and_get("/panel/scans")
        self.assertEqual(status, 200)
        self.assertIn(b"alice", body)

    def test_scans_empty_shows_placeholder(self):
        conf.supybot.plugins.WebPanel.shadowDataPath.setValue(
            str(Path(self._tmpdir) / "does-not-exist.jsonl"))
        status, body = self._enable_and_get("/panel/scans")
        self.assertEqual(status, 200)
        self.assertIn(b"No shadow-mode decisions", body)

    def test_scans_escapes_malicious_nick(self):
        data_path = Path(self._tmpdir) / "shadow.jsonl"
        data_path.write_text(json.dumps({
            "ts": 1700000000.0, "network": "libera", "channel": "#windrop",
            "nick": "<script>alert(1)</script>", "host": "1.2.3.4",
            "fused": {"action": "warn", "confidence": 0.5, "source": "classifier"},
        }) + "\n")
        conf.supybot.plugins.WebPanel.shadowDataPath.setValue(str(data_path))
        status, body = self._enable_and_get("/panel/scans")
        self.assertEqual(status, 200)
        self.assertNotIn(b"<script>alert(1)</script>", body)

    # ---- stats/gate: graceful degradation with nothing loaded/no data ----

    def test_stats_without_channelstats_shows_notice(self):
        status, body = self._enable_and_get("/panel/stats")
        self.assertEqual(status, 200)
        self.assertIn(b"ChannelStats plugin is not loaded", body)

    def test_stats_summary_not_computed_yet_is_not_an_error(self):
        # SummaryCache's background thread may not have finished its
        # first pass yet -- the route must still be a clean 200, not a
        # crash or a 5xx.
        status, body = self._enable_and_get("/panel/stats")
        self.assertEqual(status, 200)

    def test_gate_not_computed_yet_is_not_an_error(self):
        status, body = self._enable_and_get("/panel/gate")
        self.assertEqual(status, 200)

    # ---- commands ----

    def test_commands_lists_public_plugin_but_not_private_ones(self):
        status, body = self._enable_and_get("/panel/commands")
        self.assertEqual(status, 200)
        # WebPanel itself is loaded and NOT marked non-public in this
        # test fixture (only bootstrap_runtime.py sets that live) -- it
        # should appear. Real owner-only plugins aren't loaded in this
        # minimal fixture, so this mainly pins "the route doesn't crash
        # and does filter by the `public` registry value" -- the
        # positive "definitely excludes Owner" case is covered by
        # test_commands_excludes_non_public_plugin below.
        self.assertIn(b"Misc", body)

    def test_commands_excludes_non_public_plugin(self):
        # Owner is always loaded by PluginTestCase itself (see
        # supybot.test.PluginTestCase.setUp). Mark it non-public the
        # same way scripts/bootstrap_runtime.py does for the real
        # deploy, and confirm /panel/commands respects it -- this is
        # the same hardening plugins/Misc/plugin.py's patched `list`
        # enforces on the IRC side; this page must not reopen it.
        original = conf.supybot.plugins.Owner.public()
        conf.supybot.plugins.Owner.public.setValue(False)
        try:
            status, body = self._enable_and_get("/panel/commands")
        finally:
            conf.supybot.plugins.Owner.public.setValue(original)
        self.assertEqual(status, 200)
        self.assertNotIn(b">Owner<", body)

    # ---- live preview ----

    def test_live_index_empty_without_channellogger(self):
        status, body = self._enable_and_get("/panel/live")
        self.assertEqual(status, 200)
        self.assertIn(b"decisions", body)  # the decision-feed link always renders

    def test_live_index_lists_enumerated_channel(self):
        status, body = self._enable_and_get("/panel/live")
        self.assertEqual(status, 200)
        self.assertIn(b"libera", body)
        self.assertIn(b"%23windrop", body)

    def test_live_channel_shows_log_tail(self):
        status, body = self._enable_and_get("/panel/live/libera/%23windrop")
        self.assertEqual(status, 200)
        self.assertIn(b"line one", body)
        self.assertIn(b'http-equiv="refresh"', body)

    def test_live_channel_unknown_channel_404(self):
        status, _ = self._enable_and_get("/panel/live/libera/%23nosuchchannel")
        self.assertEqual(status, 404)

    def test_live_channel_path_traversal_404(self):
        status, _ = self._enable_and_get("/panel/live/../%23windrop")
        self.assertEqual(status, 404)

    def test_live_channel_disabled_via_config(self):
        original = conf.supybot.plugins.WebPanel.livePreviewSource()
        conf.supybot.plugins.WebPanel.livePreviewSource.setValue("none")
        try:
            status, body = self._enable_and_get("/panel/live/libera/%23windrop")
        finally:
            conf.supybot.plugins.WebPanel.livePreviewSource.setValue(original)
        self.assertEqual(status, 200)
        self.assertIn(b"disabled", body)

    def test_live_decisions_without_shild_shows_notice(self):
        status, body = self._enable_and_get("/panel/live/decisions")
        self.assertEqual(status, 200)
        self.assertIn(b"not loaded", body)
        self.assertIn(b'http-equiv="refresh"', body)

    # ---- parted-channel retention (2026-08-10) ----

    def _setup_parted_fixture(self):
        """Two log directories under network "test" (matching
        self.irc.network, the only network run_parted_maintenance can
        classify without treating it as "unknown network, leave alone"
        -- see parted.py's module docstring): self.channel (auto-joined
        by ChannelPluginTestCase.setUp, so it's genuinely in
        irc.state.channels) and a second channel the test irc was never
        joined to at all, standing in for a real part.
        """
        (self._log_dir / "test" / self.channel).mkdir(parents=True)
        (self._log_dir / "test" / self.channel / f"{self.channel}.log").write_text(
            "still here\n")
        (self._log_dir / "test" / "#oldchannel").mkdir(parents=True)
        (self._log_dir / "test" / "#oldchannel" / "#oldchannel.log").write_text(
            "old stuff\n")

    def test_parted_channel_shows_annotation_active_channel_does_not(self):
        self._setup_parted_fixture()
        self.assertNotError("config plugins.WebPanel.enable True")
        cb = self.irc.getCallback("WebPanel")._callback
        cb.run_parted_maintenance()

        status, body = _raw_request("GET", "/panel/logs", self._auth_headers())
        self.assertEqual(status, 200)
        self.assertIn(b"oldchannel", body)
        self.assertIn(b"Parted", body)
        # The still-joined channel's own row must NOT carry the
        # annotation -- can't just assertNotIn(b"Parted", ...) since
        # that string legitimately appears elsewhere on the same page
        # for #oldchannel's row.
        text = body.decode("utf-8")
        windrop_row = text[text.index(self.channel):text.index(self.channel) + 200]
        self.assertNotIn("Parted", windrop_row)

    def test_parted_channel_logs_deleted_after_retention_window(self):
        self._setup_parted_fixture()
        self.assertNotError("config plugins.WebPanel.enable True")
        cb = self.irc.getCallback("WebPanel")._callback
        cb.run_parted_maintenance()

        # Backdate the tracked part time well past the retention window
        # rather than waiting -- same "control time via the data, not a
        # real sleep" approach as tests/test_webpanel_parted.py.
        cb._parted.mark_parted("test", "#oldchannel", when=0.0)
        # mark_parted() is a no-op once already tracked (see parted.py)
        # -- clear first so the backdated value actually takes.
        cb._parted.clear("test", "#oldchannel")
        cb._parted.mark_parted("test", "#oldchannel", when=0.0)

        cb.run_parted_maintenance()

        self.assertFalse((self._log_dir / "test" / "#oldchannel").exists())
        status, body = _raw_request("GET", "/panel/logs", self._auth_headers())
        self.assertNotIn(b"oldchannel", body)

    def test_rejoining_a_parted_channel_clears_tracking(self):
        self._setup_parted_fixture()
        self.assertNotError("config plugins.WebPanel.enable True")
        cb = self.irc.getCallback("WebPanel")._callback
        cb.run_parted_maintenance()
        self.assertIsNotNone(cb._parted.parted_at("test", "#oldchannel"))

        self.irc.feedMsg(ircmsgs.join("#oldchannel", prefix=self.prefix))
        while self.irc.takeMsg() is not None:
            pass  # drain MODE/WHO noise from the simulated join
        cb.run_parted_maintenance()
        self.assertIsNone(cb._parted.parted_at("test", "#oldchannel"))

    def test_network_with_no_joined_channels_yet_is_not_treated_as_fully_parted(self):
        """2026-08-14 fix: right after a fresh connect (or any moment
        before the initial autojoin has synced), irc.state.channels can
        be legitimately empty for a network that's very much alive --
        the OLD code treated "an Irc object exists in world.ircs" alone
        as "this network is known, so anything not in its (empty)
        channel list just parted", mass-marking every logged channel on
        that network. Real incident: every one of a live deployment's
        ~13 real channels got mass-marked parted at the exact timestamp
        of a routine bot restart, because plugin.py's periodic check
        runs with now=True -- immediately at plugin init, before any
        join has synced."""
        self._setup_parted_fixture()
        self.assertNotError("config plugins.WebPanel.enable True")
        cb = self.irc.getCallback("WebPanel")._callback
        # Enabling above already triggered one real run_parted_maintenance
        # (plugin.py's periodic event fires with now=True) against GENUINE
        # channel state -- reset that so the assertions below test ONLY
        # the effect of the empty-channel-list call below, not state left
        # over from that earlier, accurate pass.
        cb._parted._parted.clear()

        # Simulate the mid-connect moment: the Irc object exists (as
        # self.irc always does in this harness) but hasn't joined
        # anything yet.
        self.irc.state.channels.clear()
        cb.run_parted_maintenance()

        self.assertIsNone(cb._parted.parted_at("test", self.channel),
                           "a still-joined channel must not be marked parted "
                           "just because the network briefly showed 0 joins")
        self.assertIsNone(cb._parted.parted_at("test", "#oldchannel"),
                           "a channel with no PRIOR tracked state must not be "
                           "freshly marked parted off an empty-channel-list "
                           "network either -- the whole network must be "
                           "skipped, not selectively trusted")


class WebPanelWithShildTestCase(ChannelHTTPPluginTestCase):
    """Exercises the overview/scans/stats/gate routes with real, loaded
    Shild + ChannelStats instances -- WebPanelHTTPTestCase above
    deliberately never loads either, to prove the no-plugin degradation
    path; this class proves the happy path instead.
    """
    plugins = ("WebPanel", "Shild", "ChannelStats")
    config = {
        "servers.http.keepAlive": True,
        "plugins.WebPanel.enable": False,
        # Fast background-refresh intervals so tests don't wait anywhere
        # near the real 300s/900s production defaults -- these are read
        # once at WebPanelCallback construction time (see http.py), i.e.
        # when `enable` first flips True, so setting them here (applied
        # by PluginTestCase.setUp BEFORE any test body runs) is early
        # enough.
        "plugins.WebPanel.summaryRefreshSecs": 1,
        "plugins.WebPanel.gateRefreshSecs": 1,
    }

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        secrets_path = Path(self._tmpdir) / "secrets.json"
        secrets_path.write_text(json.dumps({
            "web_panel_user": TEST_USER,
            "web_panel_password_hash": hash_password(TEST_PASS, iterations=100),
        }))
        conf.supybot.plugins.WebPanel.secretsPath.setValue(str(secrets_path))
        conf.supybot.plugins.WebPanel.allowedHosts.setValue(
            ["127.0.0.1:8080", "localhost:8080"])

        model_path = str(Path(self._tmpdir) / "model.npz")
        _write_dummy_model(model_path, bias_toward="allow")
        conf.supybot.plugins.Shild.classifier.modelPath.setValue(model_path)
        data_path = Path(self._tmpdir) / "shadow.jsonl"
        conf.supybot.plugins.Shild.shadowDataPath.setValue(str(data_path))
        conf.supybot.plugins.Shild.evidence.enabled.setValue(False)

        super(ChannelHTTPPluginTestCase, self).setUp()
        httpserver.startServer()

    def tearDown(self):
        httpserver.stopServer()
        super(ChannelHTTPPluginTestCase, self).tearDown()

    def _auth_headers(self):
        return dict(DEFAULT_HEADERS,
                    Authorization=_basic_auth_header(TEST_USER, TEST_PASS))

    def test_overview_shows_real_shild_status(self):
        self.assertNotError("config plugins.WebPanel.enable True")
        status, body = _raw_request("GET", "/panel/", self._auth_headers())
        self.assertEqual(status, 200)
        self.assertIn(b"classifier", body)
        self.assertIn(b"worker", body)
        self.assertNotIn(b"not loaded", body)

    def _poll_until(self, path, needle: bytes, timeout=5.0):
        """Polls a route until `needle` appears in the body or `timeout`
        elapses -- used for the SummaryCache-backed pages, whose
        background thread computes asynchronously (see stats.py)."""
        deadline = time.time() + timeout
        status, body = None, b""
        while time.time() < deadline:
            status, body = _raw_request("GET", path, self._auth_headers())
            if needle in body:
                return status, body
            time.sleep(0.05)
        return status, body

    def test_stats_shows_channelstats_table(self):
        # ChannelPluginTestCase's own setUp already puts the bot in
        # self.channel ("#test") via a real JOIN, which ChannelStats
        # (loaded -- see this class's `plugins`) legitimately records --
        # so "zero stats" is never actually true once ChannelStats is
        # loaded in this harness. Assert the real row renders instead.
        self.assertNotError("config plugins.WebPanel.enable True")
        status, body = _raw_request("GET", "/panel/stats", self._auth_headers())
        self.assertEqual(status, 200)
        self.assertIn(b"#test", body)
        self.assertIn(b"messages", body)  # table header

    def test_stats_shows_computed_summary_once_ready(self):
        data_path = conf.supybot.plugins.Shild.shadowDataPath()
        Path(data_path).write_text(json.dumps({
            "ts": 1700000000.0, "network": "libera", "channel": "#windrop",
            "nick": "carol", "host": "9.9.9.9",
            "fused": {"action": "warn", "confidence": 0.6, "source": "classifier"},
        }) + "\n")
        self.assertNotError("config plugins.WebPanel.enable True")
        # The JSON dump inside <pre> is HTML-escaped by render.py (as it
        # must be -- see render.py's module docstring on why escaping
        # applies everywhere, including here), so the literal substring
        # in the response body has &quot; in place of every ".
        status, body = self._poll_until("/panel/stats", b"&quot;total_rows&quot;: 1")
        self.assertEqual(status, 200)
        self.assertIn(b"&quot;total_rows&quot;: 1", body)
        self.assertIn(b"&quot;warn&quot;: 1", body)

    def test_stats_shows_activity_heatmap_once_ready(self):
        data_path = conf.supybot.plugins.Shild.shadowDataPath()
        Path(data_path).write_text(json.dumps({
            "ts": 1700000000.0, "network": "libera", "channel": "#windrop",
            "nick": "erin", "host": "9.9.9.10",
            "fused": {"action": "allow", "confidence": 0.1, "source": "classifier"},
        }) + "\n")
        self.assertNotError("config plugins.WebPanel.enable True")
        # Timezone-independent on purpose (the bucket a fixed unix
        # timestamp lands in depends on the test machine's local time) --
        # just prove the grid rendered with a real, non-empty count rather
        # than the "no timestamped events" placeholder, and that it's kept
        # OUT of the raw JSON dump below it (aggregate_block's <pre>
        # block), which is what stats.py's own docstring on this split
        # promises.
        status, body = self._poll_until("/panel/stats", b"Activity heatmap")
        self.assertEqual(status, 200)
        self.assertIn(b"Activity heatmap", body)
        self.assertIn(b'class="heat-4"', body)  # the one event is the max -> hottest bucket
        self.assertNotIn(b"&quot;activity_heatmap&quot;", body)

    def test_gate_shows_computed_report_once_ready(self):
        data_path = conf.supybot.plugins.Shild.shadowDataPath()
        Path(data_path).write_text(json.dumps({
            "ts": 1700000000.0, "network": "libera", "channel": "#windrop",
            "nick": "dave", "host": "8.8.8.8",
            "fused": {"action": "warn", "confidence": 0.6, "source": "classifier"},
            "fused_raw": {"action": "ban", "confidence": 0.9, "source": "classifier"},
            "gate": {"applied": True, "rule": "downgrade"},
        }) + "\n")
        self.assertNotError("config plugins.WebPanel.enable True")
        status, body = self._poll_until("/panel/gate", b"&quot;gated&quot;: 1")
        self.assertEqual(status, 200)
        self.assertIn(b"&quot;gated&quot;: 1", body)
        self.assertIn(b"&quot;total_rows&quot;: 1", body)

    def test_scans_picks_up_shadow_data_path_from_shild(self):
        # WebPanel.shadowDataPath is left empty -- it should derive the
        # path from Shild's own registry value, not need its own copy.
        data_path = conf.supybot.plugins.Shild.shadowDataPath()
        Path(data_path).write_text(json.dumps({
            "ts": 1700000000.0, "network": "libera", "channel": "#windrop",
            "nick": "bob", "host": "5.6.7.8",
            "fused": {"action": "ban", "confidence": 0.95, "source": "classifier"},
        }) + "\n")
        self.assertNotError("config plugins.WebPanel.enable True")
        status, body = _raw_request("GET", "/panel/scans", self._auth_headers())
        self.assertEqual(status, 200)
        self.assertIn(b"bob", body)
        self.assertIn(b"ban", body)

    def test_live_decisions_shows_real_join_event(self):
        # A real join to an ENABLED channel goes through Shild's
        # _handle_event -> context.snapshot(), which records it into
        # ContextStore's global event ring -- this is the actual data
        # source /panel/live/decisions reads, independent of the
        # shadow_decisions.jsonl file the other tests above write
        # directly.
        conf.supybot.plugins.Shild.enabled.get(self.channel).setValue(True)
        from supybot import ircmsgs
        self.irc.feedMsg(ircmsgs.IrcMsg(
            command="JOIN", args=(self.channel,),
            prefix="livejoiner!~ident@203.0.113.7"))
        self.assertNotError("config plugins.WebPanel.enable True")
        status, body = _raw_request("GET", "/panel/live/decisions", self._auth_headers())
        self.assertEqual(status, 200)
        self.assertIn(b"livejoiner", body)
        self.assertNotIn(b"not loaded", body)
