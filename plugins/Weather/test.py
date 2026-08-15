"""Limnoria PluginTestCase tests for Weather.

No test here ever reaches the real network: the running plugin
instance's WeatherClient (self._plugin._client) is replaced with a
_StubClient whose lookup()/geocode_only() are plain, synchronous, canned
responses -- same "reach into the live instance" move
plugins/SpamGuard/test.py makes with self._plugin._terms. Pure
parsing/formatting/store logic is tested separately, without the plugin
harness at all, in tests/test_weather_*.py.
"""
import json
import tempfile
import time
from pathlib import Path

import supybot.conf as conf
import supybot.ircdb as ircdb
from supybot.test import ChannelPluginTestCase, PluginTestCase

from .client import ClientConfig, WeatherResult
from .owm import CurrentWeather
from .store import GeocodeRecord


def _current(label="Stuttgart, DE"):
    return CurrentWeather(
        label=label, temp_c=27.0, temp_max_c=25.0, feels_like_c=27.0,
        humidity_pct=38, wind_speed_ms=0.28, clouds_pct=0, description="clear sky",
        icon="01d", tz_offset_secs=7200, sunrise_epoch=int(time.time()),
        sunset_epoch=int(time.time()) + 3600,
    )


class _StubClient:
    """Replaces the real WeatherClient in tests -- no aiohttp, no real
    network, deterministic canned results. `calls` records every method
    invocation so a test can assert something was (or, for the no-key
    path, was NOT) actually reached.
    """

    def __init__(self):
        self.calls = []
        self.lookup_result = WeatherResult(
            current=_current(), days=[], air=None, forecast_error=False, error=None,
        )
        self.geocode_result = (
            GeocodeRecord(query="stuttgart", lat=48.77, lon=9.18,
                          display_name="Stuttgart, DE", short_name="Stuttgart, DE",
                          country_code="de", fetched_at=time.time(), miss=False),
            None,
        )

    def lookup(self, place, cfg: ClientConfig, want_air=True):
        self.calls.append(("lookup", place))
        return self.lookup_result

    def geocode_only(self, place, cfg: ClientConfig):
        self.calls.append(("geocode_only", place))
        return self.geocode_result


class WeatherTestCase(ChannelPluginTestCase):
    plugins = ("Weather",)

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self._locations_path = str(Path(self._tmpdir) / "locations.json")
        self._geocode_path = str(Path(self._tmpdir) / "geocode.json")
        self._secrets_path = str(Path(self._tmpdir) / "secrets.json")
        Path(self._secrets_path).write_text(json.dumps({
            "openweathermap_key": "test-owm-key-SENTINEL",
            "openaq_key": "test-openaq-key-SENTINEL",
        }))
        conf.supybot.plugins.Weather.locationsPath.setValue(self._locations_path)
        conf.supybot.plugins.Weather.geocodeCachePath.setValue(self._geocode_path)
        conf.supybot.plugins.Weather.secretsPath.setValue(self._secrets_path)
        conf.supybot.plugins.Weather.enabled.get(self.channel).setValue(True)
        super().setUp()

        u = ircdb.users.newUser()
        u.name = "test-owner"
        u.addCapability("owner")
        u.addHostmask(self.prefix)
        ircdb.users.setUser(u)

        self._plugin = self.irc.getCallback("Weather")
        self._stub = _StubClient()
        self._plugin._client = self._stub

    def test_path_defaults_are_not_prefixed_with_runtime(self):
        # Guards the exact "runtime/runtime/" bug documented in
        # CLAUDE.md, made three times already for other plugins here.
        for name in ("locationsPath", "geocodeCachePath", "secretsPath"):
            default = getattr(conf.supybot.plugins.Weather, name)._default
            self.assertFalse(str(default).startswith("runtime/"), name)

    def test_weather_without_an_api_key_says_so_and_never_calls_the_network(self):
        conf.supybot.plugins.Weather.secretsPath.setValue(
            str(Path(self._tmpdir) / "does-not-exist.json"))
        m = self.getMsg("weather stuttgart")
        self.assertIn("no OpenWeatherMap API key", str(m))
        self.assertEqual(self._stub.calls, [])

    def test_bare_weather_with_no_saved_location_prompts_setweather(self):
        m = self.getMsg("weather")
        self.assertIn("no saved location", str(m))
        self.assertIn("setweather", str(m))

    def test_setweather_then_bare_weather_uses_the_saved_place(self):
        m = self.getMsg("setweather stuttgart")
        self.assertIn("saved", str(m).lower())
        self._stub.calls.clear()
        self.getMsg("weather")
        self.assertEqual(self._stub.calls, [("lookup", "stuttgart")])

    def test_setweather_then_unsetweather_round_trip(self):
        self.getMsg("setweather stuttgart")
        m = self.getMsg("unsetweather")
        self.assertIn("forgot", str(m).lower())
        m2 = self.getMsg("weather")
        self.assertIn("no saved location", str(m2))

    def test_unsetweather_with_nothing_saved_says_so(self):
        m = self.getMsg("unsetweather")
        self.assertIn("no saved location", str(m))

    def test_setweather_rejects_a_place_that_cannot_be_geocoded(self):
        self._stub.geocode_result = (None, "geocode_miss")
        m = self.getMsg("setweather nowhere-at-all")
        self.assertIn("couldn't find", str(m))
        # And nothing was saved.
        m2 = self.getMsg("weather")
        self.assertIn("no saved location", str(m2))

    def test_saved_location_is_keyed_to_the_account_when_registered(self):
        # self.prefix's user is already registered (owner) in setUp --
        # confirm the stored key uses the account form.
        self.getMsg("setweather stuttgart")
        key = self._plugin._location_key(self.irc, self._msg_from(self.prefix))
        self.assertTrue(key.startswith("acct:"))

    def _msg_from(self, prefix):
        import supybot.ircmsgs as ircmsgs
        return ircmsgs.privmsg(self.channel, "x", prefix=prefix)

    def test_saved_location_is_keyed_to_network_and_nick_when_not_registered(self):
        msg = self._msg_from("someoneelse!user@host.example")
        key = self._plugin._location_key(self.irc, msg)
        self.assertTrue(key.startswith("nick:"))
        self.assertIn("someoneelse", key)

    def test_w_is_a_command_in_its_own_right_with_its_own_help(self):
        self.assertIn("Short form of", self._plugin.w.__doc__)
        self.assertNotEqual(self._plugin.w.__doc__, self._plugin.weather.__doc__)

    def test_weather_line_reaches_the_channel_without_a_nick_prefix(self):
        m = self.getMsg("weather stuttgart")
        self.assertFalse(str(m.args[1]).startswith(self.nick))

    def test_weathercacheclear_requires_owner(self):
        # __no_testcap__ in the host part is required, or
        # ircdb.checkCapability short-circuits to True for every
        # capability under supybot-test (world.testing) and this test
        # would pass even with zero capability gate in place -- see
        # CLAUDE.md's documented gotcha, already hit once writing
        # Shild's/SpamGuard's own owner-only command tests.
        msg = self._msg_from("nobody!nobody@__no_testcap__.example")
        m = self.getMsg("weathercacheclear", frm=msg.prefix)
        if m is not None:
            self.assertNotIn("cleared", str(m).lower())

    def test_weathercacheclear_does_not_remove_saved_locations(self):
        self.getMsg("setweather stuttgart")
        self.getMsg("weathercacheclear")
        m = self.getMsg("weather")
        self.assertEqual(self._stub.calls[-1], ("lookup", "stuttgart"))

    def test_weatherstatus_never_prints_an_api_key(self):
        m = self.getMsg("weatherstatus")
        text = str(m)
        self.assertNotIn("SENTINEL", text)
        self.assertIn("present", text)

    def test_disabled_channel_produces_no_reply(self):
        conf.supybot.plugins.Weather.enabled.get(self.channel).setValue(False)
        m = self.getMsg("weather stuttgart")
        self.assertIsNone(m)

    def test_setweather_disk_write_failure_does_not_claim_success(self):
        # Point locationsPath at an unwritable location (a directory,
        # not a file) -- LocationStore.set() must return False, and the
        # command must say so rather than claiming success.
        bad_path = str(Path(self._tmpdir))  # a directory, not writable as a file
        self._plugin._locations.path = Path(bad_path)
        m = self.getMsg("setweather stuttgart")
        self.assertIn("disk error", str(m).lower())
