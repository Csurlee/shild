"""Weather: current conditions + forecast (OpenWeatherMap) and air
quality (OpenAQ v3), geocoded via OpenStreetMap Nominatim. Read-only --
no command changes anything but the caller's own saved location.

`threaded = True` (unlike Shild's/SpamGuard's `threaded = False`): those
two funnel all blocking work through a dedicated worker thread precisely
because doJoin/doPrivmsg must return instantly across every connected
network. This plugin has no event hooks at all -- every command already
runs on its own Limnoria-managed thread when threaded=True (confirmed:
this only affects command dispatch, not event hooks -- see
plugins/Shild/plugin.py's own docstring on the same flag, and
plugins/UndernetX/plugin.py, which already sets it). So a command can
safely block on client.py's asyncio.run() without stalling anything
else.
"""
from __future__ import annotations

import time

from supybot import callbacks, ircdb, log
from supybot.commands import optional, wrap

from . import store
from .client import ClientConfig, WeatherClient
from .render import format_weather_line, render_aqi_line
from .secrets import load_weather_secrets
from .store import GeocodeStore, LocationStore, SavedLocation


class Weather(callbacks.Plugin):
    """Current conditions, forecast, and air quality via
    OpenWeatherMap/Nominatim/OpenAQ. See "weather help" for commands.
    """

    threaded = True

    def __init__(self, irc):
        self.__parent = super(Weather, self)
        self.__parent.__init__(irc)
        self._locations = LocationStore(self.registryValue("locationsPath"))
        self._geocode_store = GeocodeStore(
            self.registryValue("geocodeCachePath"),
            max_entries=self.registryValue("cacheMaxEntries"),
        )
        self._client = WeatherClient(
            geocode_store=self._geocode_store,
            nominatim_rate_per_min=self.registryValue("nominatimRatePerMin"),
            owm_rate_per_min=self.registryValue("owmRatePerMin"),
            openaq_rate_per_min=self.registryValue("openaqRatePerMin"),
            cache_maxsize=self.registryValue("cacheMaxEntries"),
        )

    # ---- internal helpers ----

    def _enabled(self, channel) -> bool:
        if channel is None:  # PMs always answer
            return True
        return self.registryValue("enabled", channel)

    def _account_for(self, msg):
        try:
            return ircdb.users.getUser(msg.prefix).name
        except KeyError:
            return None

    def _location_key(self, irc, msg):
        account = self._account_for(msg)
        return store.location_key(account, irc.network, msg.nick)

    def _client_config(self, days: int = None) -> ClientConfig:
        secrets = load_weather_secrets(self.registryValue("secretsPath"))
        return ClientConfig(
            owm_key=secrets["openweathermap_key"],
            openaq_key=secrets["openaq_key"],
            user_agent=self._user_agent(),
            timeout_secs=self.registryValue("timeoutSecs"),
            forecast_days=days if days is not None else self.registryValue("forecastDays"),
            current_ttl_secs=self.registryValue("currentTtlSecs"),
            forecast_ttl_secs=self.registryValue("forecastTtlSecs"),
            air_quality_ttl_secs=self.registryValue("airQualityTtlSecs"),
            geocode_hit_ttl_secs=self.registryValue("geocodeCacheTtlDays") * 86400,
            geocode_miss_ttl_secs=self.registryValue("geocodeMissTtlHours") * 3600,
            air_quality_radius_meters=self.registryValue("airQualityRadiusMeters"),
        )

    def _user_agent(self) -> str:
        ua = self.registryValue("userAgent")
        email = self.registryValue("contactEmail")
        return f"{ua} ({email})" if email else ua

    def _resolve_place(self, irc, msg, location: str):
        """Returns (place_string, error_reply_or_None). `location` is the
        user-typed argument, possibly empty -- falls back to the caller's
        saved location, then the network's defaultLocation.
        """
        if location:
            return location, None
        key = self._location_key(irc, msg)
        saved = self._locations.get(key)
        if saved is not None:
            return saved.place, None
        default = self.registryValue("defaultLocation", network=irc.network)
        if default:
            return default, None
        return None, (
            'weather: no saved location -- try "setweather <place>", '
            'or "w <place>" for a one-off.'
        )

    def _no_key_reply(self, cfg: ClientConfig):
        if not cfg.owm_key:
            return (
                'weather: no OpenWeatherMap API key configured -- add '
                '"openweathermap_key" to runtime/secrets.json (or set '
                'SHILD_OPENWEATHERMAP_KEY) and @reload Weather.'
            )
        return None

    # "geocode_miss" is handled specially in _error_reply() (needs the
    # place name interpolated) -- not listed here.
    _ERROR_TEXT = {
        "geocode_rate_limited": (
            "weather: geocoding is rate-limited to 1 request/second -- try again in a moment."
        ),
        "http_401": (
            "weather: OpenWeatherMap rejected the API key (401) -- check "
            '"openweathermap_key". A brand-new free key can take up to ~2 '
            "hours to activate."
        ),
        "http_404": "weather: OpenWeatherMap has no data for that location.",
        "http_429": "weather: OpenWeatherMap rate limit hit (429) -- try again in a minute.",
        "unexpected_response": "weather: got an unexpected response -- try again shortly.",
    }

    def _error_reply(self, place: str, error: str) -> str:
        if error == "geocode_miss":
            return f'weather: couldn\'t find a place called "{place}".'
        text = self._ERROR_TEXT.get(error)
        if text is not None:
            return text
        if error is not None and error.startswith("http_"):
            return f"weather: geocoding service unavailable ({error}) -- try again shortly."
        return f"weather: lookup failed ({error})."

    # ---- commands ----

    def _weather(self, irc, msg, location):
        channel = msg.channel
        if not self._enabled(channel):
            return
        cfg = self._client_config()
        no_key = self._no_key_reply(cfg)
        if no_key:
            irc.reply(no_key, prefixNick=False)
            return
        place, err = self._resolve_place(irc, msg, location)
        if err:
            irc.reply(err, prefixNick=False)
            return
        show_air = channel is None or self.registryValue("showAirQuality", channel)
        try:
            result = self._client.lookup(place, cfg, want_air=show_air)
        except Exception:
            log.exception("Weather: lookup failed for %r", place)
            irc.reply(f"weather: lookup failed unexpectedly for \"{place}\".", prefixNick=False)
            return
        if result.current is None:
            irc.reply(self._error_reply(place, result.error), prefixNick=False)
            return
        line = format_weather_line(
            result.current, result.days, result.air, int(time.time()),
            max_line_bytes=self.registryValue("maxLineBytes"),
            forecast_error=result.forecast_error,
        )
        irc.reply(line, prefixNick=False)

    def weather(self, irc, msg, args, location):
        """[<location>]

        Reports current conditions and a short forecast for <location>,
        or for your saved location if none is given. Use "setweather
        <place>" to save one. Does not save <location>.
        """
        self._weather(irc, msg, location)
    weather = wrap(weather, [optional("text")])

    def w(self, irc, msg, args, location):
        """[<location>]

        Short form of "weather".
        """
        self._weather(irc, msg, location)
    w = wrap(w, [optional("text")])

    def aqi(self, irc, msg, args, location):
        """[<location>]

        Reports air quality (US AQI plus PM2.5) for <location>, or for
        your saved location if none is given.
        """
        channel = msg.channel
        if not self._enabled(channel):
            return
        cfg = self._client_config()
        if not cfg.openaq_key:
            irc.reply(
                'aqi: no OpenAQ API key configured -- add "openaq_key" to '
                "runtime/secrets.json (or set SHILD_OPENAQ_KEY) and @reload Weather.",
                prefixNick=False,
            )
            return
        place, err = self._resolve_place(irc, msg, location)
        if err:
            irc.reply(err, prefixNick=False)
            return
        try:
            result = self._client.lookup(place, cfg, want_air=True)
        except Exception:
            log.exception("Weather: aqi lookup failed for %r", place)
            irc.reply(f"aqi: lookup failed unexpectedly for \"{place}\".", prefixNick=False)
            return
        if result.current is None:
            irc.reply(self._error_reply(place, result.error).replace("weather:", "aqi:", 1),
                      prefixNick=False)
            return
        irc.reply(
            render_aqi_line(result.current.label, result.air,
                             self.registryValue("airQualityRadiusMeters")),
            prefixNick=False,
        )
    aqi = wrap(aqi, [optional("text")])

    def setweather(self, irc, msg, args, location):
        """<location>

        Saves <location> as your default for "weather"/"w"/"aqi". Keyed
        to your registered account if you have one, otherwise to your
        nick on this network. Rejects a place that can't be geocoded.
        """
        cfg = self._client_config()
        no_key = self._no_key_reply(cfg)
        if no_key:
            irc.reply(no_key, prefixNick=False)
            return
        rec, err = self._client.geocode_only(location, cfg)
        if rec is None:
            irc.reply(self._error_reply(location, err), prefixNick=False)
            return
        key = self._location_key(irc, msg)
        saved = SavedLocation(
            key=key, place=location, label=rec.short_name, lat=rec.lat, lon=rec.lon,
            saved_by=msg.prefix, saved_at=time.time(),
        )
        if self._locations.set(saved):
            irc.replySuccess(f"saved {rec.short_name} as your default location.")
        else:
            irc.reply(
                f"weather: saved {rec.short_name} for this session, but couldn't write "
                f"{self.registryValue('locationsPath')} (disk error) -- it won't survive a restart.",
                prefixNick=False,
            )
    setweather = wrap(setweather, ["text"])

    def unsetweather(self, irc, msg, args):
        """takes no arguments

        Forgets your saved location.
        """
        key = self._location_key(irc, msg)
        removed = self._locations.unset(key)
        if removed is None:
            irc.reply("weather: you have no saved location.", prefixNick=False)
        else:
            irc.replySuccess(f"forgot your saved location ({removed.label}).")
    unsetweather = wrap(unsetweather)

    def weatherstatus(self, irc, msg, args):
        """takes no arguments

        Reports API-key presence (never the keys themselves), cache
        sizes, and saved-location count. Read-only.
        """
        secrets = load_weather_secrets(self.registryValue("secretsPath"))
        irc.reply(
            "weather: OpenWeatherMap key: {owm} -- OpenAQ key: {aq} -- "
            "geocode cache: {geo} entries -- saved locations: {locs}".format(
                owm="present" if secrets["openweathermap_key"] else "MISSING",
                aq="present" if secrets["openaq_key"] else "not configured",
                geo=len(self._geocode_store),
                locs=len(self._locations.all()),
            ),
            prefixNick=False,
        )
    weatherstatus = wrap(weatherstatus)

    def weathercacheclear(self, irc, msg, args):
        """takes no arguments

        Empties the persisted Nominatim geocode cache. Saved locations
        are untouched.
        """
        n = self._geocode_store.clear()
        irc.replySuccess(f"cleared {n} cached geocode entries.")
    weathercacheclear = wrap(weathercacheclear, ["owner"])


Class = Weather
