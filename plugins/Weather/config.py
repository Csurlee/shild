"""Config registry for Weather. See CLAUDE.md's Weather section for the
full design rationale -- this file just registers the values.

`enabled` defaults True (channel-scoped, opSettable=False), unlike
Shild's/SpamGuard's own "enabled" (both default False). Those act ON
users -- a mis-scoped default there risks an unwanted kick. Weather only
ever answers when explicitly asked, so a True default's failure mode is
just "someone typed a command and got a reply", while a False default
would make a freshly-loaded plugin silently inert everywhere, which is
exactly the class of confusion this repo's secretsPath incidents (see
CLAUDE.md) warn about -- indistinguishable from a missing API key.
"""
from __future__ import annotations

from supybot import conf, registry

try:
    from supybot.i18n import PluginInternationalization
    _ = PluginInternationalization("Weather")
except ImportError:
    _ = lambda x: x  # noqa: E731


def configure(advanced):
    conf.registerPlugin("Weather", True)


Weather = conf.registerPlugin("Weather")

conf.registerChannelValue(
    Weather, "enabled",
    registry.Boolean(True, _(
        """Whether "weather"/"w"/"aqi" answer in this channel. Defaults True
        (see this file's module docstring for why, unlike Shild/SpamGuard).
        Not op-settable -- turning the plugin's command surface on/off per
        channel is an admin decision, not a channel-op one.""")),
    opSettable=False,
)

conf.registerChannelValue(
    Weather, "showAirQuality",
    registry.Boolean(True, _(
        """Whether to append a short air-quality fragment to the "weather"/
        "w" line (in addition to the standalone "aqi" command, which always
        shows it regardless of this setting). The only op-settable value in
        this plugin -- purely cosmetic line length, no security/policy
        weight.""")),
    opSettable=True,
)

# Network-specific, same reasoning as GitHubWatch's "channel"/Shild's
# relayChannel: a fallback location for one network's users must never
# apply to a different network by accident.
conf.registerNetworkValue(
    Weather, "defaultLocation",
    registry.String("", _(
        """Fallback place name for a bare "w"/"weather" from a user with
        nothing saved via "setweather" -- empty means such a user gets a
        prompt to save one instead.""")),
)

conf.registerGlobalValue(
    Weather, "secretsPath",
    registry.String("secrets.json", _(
        """Path to the gitignored local secrets file, resolved relative to
        the bot's own working directory (runtime/, since it's started via
        `cd runtime && supybot shildpy.conf`) -- NOT relative to the repo
        root, so this must be "secrets.json", not "runtime/secrets.json".
        This exact "runtime/runtime/" mistake has been made three times
        already in this deployment for other plugins' path values (see
        CLAUDE.md) -- do not repeat it here. Needs "openweathermap_key"
        and/or "openaq_key" (or the SHILD_OPENWEATHERMAP_KEY/
        SHILD_OPENAQ_KEY env vars, which take precedence) -- missing either
        one silently disables the corresponding feature rather than
        erroring (weather works with only an OWM key; air quality is
        additionally silent-skipped without an OpenAQ key).""")),
)

conf.registerGlobalValue(
    Weather, "locationsPath",
    registry.String("data/weather_locations.json", _(
        """Path to the persisted per-user saved-location store (written only
        by "setweather"/"unsetweather"), resolved relative to the bot's own
        working directory (runtime/) -- same "do not prefix with runtime/"
        rule as secretsPath above.""")),
)

conf.registerGlobalValue(
    Weather, "geocodeCachePath",
    registry.String("data/weather_geocode_cache.json", _(
        """Path to the persisted Nominatim geocode cache, resolved relative
        to the bot's own working directory (runtime/) -- same "do not
        prefix with runtime/" rule as secretsPath above. Persisting this
        (not just an in-process cache) is not an optimization -- Nominatim's
        usage policy (operations.osmfoundation.org/policies/nominatim)
        requires client-side caching of results, and an in-process-only
        cache is wiped by every restart/@reload, both frequent in this
        deployment.""")),
)

conf.registerGlobalValue(
    Weather, "userAgent",
    registry.String("shild-py-Weather/0.1 (+https://github.com/Csurlee/shild)", _(
        """User-Agent header sent on every Nominatim geocoding request.
        Nominatim's usage policy requires an identifying User-Agent or
        Referer -- a library default (or none at all) gets blocked. See
        also "contactEmail".""")),
)

conf.registerGlobalValue(
    Weather, "contactEmail",
    registry.String("", _(
        """Optional contact email appended to the User-Agent header sent to
        Nominatim, per its usage policy. Empty by default -- set this if
        Nominatim ever needs to reach an operator about this deployment's
        usage.""")),
)

conf.registerGlobalValue(
    Weather, "timeoutSecs",
    registry.PositiveFloat(8.0, _(
        """Per-request timeout (seconds) for every outbound HTTP call
        (Nominatim, OpenWeatherMap, OpenAQ).""")),
)

conf.registerGlobalValue(
    Weather, "forecastDays",
    registry.PositiveInteger(3, _(
        """Number of forecast days shown on the "weather"/"w" line. The
        free OpenWeatherMap forecast endpoint covers 5 days, so this always
        fits comfortably even after excluding "today".""")),
)

conf.registerGlobalValue(
    Weather, "currentTtlSecs",
    registry.PositiveInteger(600, _(
        """In-process cache TTL (seconds) for a current-conditions result --
        OpenWeatherMap's own data refreshes roughly every 10 minutes, so
        caching more aggressively than that would not lose real
        freshness.""")),
)

conf.registerGlobalValue(
    Weather, "forecastTtlSecs",
    registry.PositiveInteger(3600, _(
        """In-process cache TTL (seconds) for a forecast result.""")),
)

conf.registerGlobalValue(
    Weather, "airQualityTtlSecs",
    registry.PositiveInteger(1800, _(
        """In-process cache TTL (seconds) for an air-quality result.""")),
)

conf.registerGlobalValue(
    Weather, "geocodeCacheTtlDays",
    registry.PositiveInteger(30, _(
        """How many days a successful (hit) geocode result is considered
        fresh before a re-lookup is attempted -- places don't move, so this
        is deliberately long.""")),
)

conf.registerGlobalValue(
    Weather, "geocodeMissTtlHours",
    registry.PositiveInteger(6, _(
        """How many hours a geocode MISS (place not found) is
        negative-cached -- keeps a typo repeated in-channel from re-hitting
        Nominatim every time, without permanently remembering a query that
        might resolve once Nominatim's data improves.""")),
)

conf.registerGlobalValue(
    Weather, "cacheMaxEntries",
    registry.PositiveInteger(2000, _(
        """Maximum entries kept in the in-process LRU caches and the
        persisted geocode cache before the oldest are evicted.""")),
)

conf.registerGlobalValue(
    Weather, "nominatimRatePerMin",
    registry.PositiveInteger(60, _(
        """Refill rate (requests/minute) for the Nominatim rate limiter.
        Bucket CAPACITY is always forced to 1.0 in code regardless of this
        value -- Nominatim's usage policy caps at 1 request/second with NO
        burst allowance, so this only controls the refill rate, never how
        many requests can fire back-to-back.""")),
)

conf.registerGlobalValue(
    Weather, "owmRatePerMin",
    registry.PositiveInteger(50, _(
        """Requests/minute this plugin allows itself against OpenWeatherMap
        -- deliberate headroom under OWM's free-tier 60/minute limit.""")),
)

conf.registerGlobalValue(
    Weather, "openaqRatePerMin",
    registry.PositiveInteger(50, _(
        """Requests/minute this plugin allows itself against OpenAQ --
        deliberate headroom under OpenAQ's free-tier 60/minute limit.""")),
)

conf.registerGlobalValue(
    Weather, "airQualityRadiusMeters",
    registry.PositiveInteger(25000, _(
        """Search radius (meters) for finding the nearest OpenAQ monitoring
        station to a geocoded location. No station within this radius means
        air quality is silently omitted (on "weather"/"w") or reported as
        unavailable (on "aqi").""")),
)

conf.registerGlobalValue(
    Weather, "maxLineBytes",
    registry.PositiveInteger(430, _(
        """Maximum UTF-8 byte length of the "weather"/"w" reply line before
        segments are dropped (air-quality fragment first, then forecast
        days from the last back) -- measured in bytes, not characters,
        since the line is full of multi-byte characters (degree signs,
        weather symbols).""")),
)
