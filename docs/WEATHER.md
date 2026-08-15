# Weather

Current conditions, a short forecast, and air quality — via OpenWeatherMap, OpenStreetMap
Nominatim (geocoding), and OpenAQ v3. Independent of Shild — no ML/threat-analysis logic, purely
read-only informational commands. The only thing any command writes is the calling user's own
saved location.

## Status / prerequisites

`plugins.Weather.enabled` defaults **True** per channel (unlike Shild/SpamGuard, which default
`False` — see the "Configuration" table below for why), so the plugin answers everywhere it's
loaded as soon as an API key exists. Without a key it still loads cleanly and replies with a clear
one-line error rather than doing nothing or erroring:

1. **`openweathermap_key`** in `secrets.json` (or the `SHILD_OPENWEATHERMAP_KEY` env var) —
   required for `weather`/`w`. Free tier only (`data/2.5/weather` + `data/2.5/forecast`), **not**
   One Call 3.0, which requires a credit card on file. A brand-new free key can take up to ~2
   hours to activate — a 401 during that window looks exactly like a wrong key.
2. **`openaq_key`** in `secrets.json` (or `SHILD_OPENAQ_KEY`) — optional. Without it, air quality
   is silently omitted from `weather`/`w` and `aqi` replies with an explicit "no key configured"
   message.

No channel-privilege prerequisite of any kind — this plugin never needs op, never touches
`irc.state`, and has no kill switch (there's nothing here to arm; every command is read-only aside
from a user's own saved location).

**Nominatim (geocoding) has a real usage policy this plugin must respect, not just a courtesy**:
at most 1 request/second, a mandatory identifying `User-Agent`, and mandatory client-side caching
of results. All three are handled automatically (`plugins.Weather.userAgent`, a strict token
bucket, and a persisted geocode cache) — nothing to configure unless you want to add a contact
email (`plugins.Weather.contactEmail`) to the User-Agent, which is good practice but not required.

## Commands

None of these require a capability — same posture as `githubwatchstatus` — except
`weathercacheclear`, which is owner-only.

### `weather [<location>]` / `w [<location>]`

```
[<location>]
```

Reports current conditions and a short forecast. With no `<location>`, uses your saved location
(see `setweather`) or the network's `defaultLocation` if set; with neither, replies with a prompt
rather than guessing. `w` is a full second command (not just an alias) so its own help text stays
accurate. Neither form saves `<location>` — only `setweather` does that.

```
<user> w stuttgart
<Shild> weather: Stuttgart, DE: ☀ 27°C (80°F), max: 25°C (77°F), 38% humidity, 1 km/h (1 mph) wind, feels like: 27°C / 80°F, 0% cloud cover (clear sky) -- time: 10:25 -- sunrise: 06:14 -- sunset: 20:41 -- forecast: Sat: ☁ (high: 36°C / 96°F, low: 17°C / 62°F) -- Sun: ☀ (high: 30°C / 86°F, low: 21°C / 69°F) -- Mon: ☀ (high: 25°C / 77°F, low: 18°C / 64°F)
```

### `aqi [<location>]`

```
[<location>]
```

Standalone air-quality report — fuller than the short fragment `weather`/`w` can append (includes
station name and distance). Same location-resolution rule as `weather`.

```
<user> aqi stuttgart
<Shild> aqi: Stuttgart, DE: AQI 42 (moderate), PM2.5 8.4 µg/m³ -- station: Stuttgart Am Neckartor, 1.2km away
```

If nothing is nearby: `aqi: no air-quality station within 25 km of Stuttgart, DE.`

### `setweather <location>`

```
<location>
```

Saves `<location>` as your default for `weather`/`w`/`aqi`. Keyed to your registered ircdb account
if you have one (survives a nick/host change), otherwise to your nick on the current network.
Geocodes `<location>` live and **rejects** a place Nominatim can't find, so you find out
immediately rather than on your next `w`.

### `unsetweather`

```
takes no arguments
```

Forgets your saved location.

### `weatherstatus`

```
takes no arguments
```

Reports whether each API key is configured (never the key values themselves), the geocode cache
size, and the saved-location count. Read-only.

### `weathercacheclear`

```
takes no arguments
```

**Owner-only.** Empties the persisted Nominatim geocode cache. Saved locations are untouched —
this only affects how soon the next lookup for a given place re-hits Nominatim.

## Configuration

| Value | Scope | Type | Default | Description |
|---|---|---|---|---|
| `plugins.Weather.enabled` | channel | Boolean | `True` | Whether the lookup commands answer here. Not op-settable. Defaults **True**, unlike Shild/SpamGuard — those act on users, so a mis-scoped `False` there means a missed kick; this plugin only ever replies to an explicit command, so a `False` default would instead be indistinguishable from a missing API key. |
| `plugins.Weather.showAirQuality` | channel | Boolean | `True` | Append the short air-quality fragment to `weather`/`w`. The only op-settable value in this plugin — purely cosmetic line length. |
| `plugins.Weather.defaultLocation` | **network** | String | `""` | Fallback place for a bare `w`/`weather` from a user with nothing saved. |
| `plugins.Weather.secretsPath` | global | String | `secrets.json` | Gitignored key file — `openweathermap_key`/`openaq_key`. |
| `plugins.Weather.locationsPath` | global | String | `data/weather_locations.json` | Persisted saved locations (written only by `setweather`/`unsetweather`). |
| `plugins.Weather.geocodeCachePath` | global | String | `data/weather_geocode_cache.json` | Persisted Nominatim cache — required by Nominatim's own usage policy, not just a performance choice. |
| `plugins.Weather.userAgent` | global | String | `shild-py-Weather/0.1 (+https://github.com/Csurlee/shild)` | Sent on every Nominatim request. Nominatim blocks requests without an identifying UA. |
| `plugins.Weather.contactEmail` | global | String | `""` | Appended to the User-Agent when set, per Nominatim's policy. |
| `plugins.Weather.timeoutSecs` | global | Positive float | `8.0` | Per-request timeout for every outbound call (Nominatim, OWM, OpenAQ). |
| `plugins.Weather.forecastDays` | global | Positive integer | `3` | Forecast rows shown on the `weather`/`w` line. |
| `plugins.Weather.currentTtlSecs` | global | Positive integer | `600` | In-process cache TTL for a current-conditions result. |
| `plugins.Weather.forecastTtlSecs` | global | Positive integer | `3600` | In-process cache TTL for a forecast result. |
| `plugins.Weather.airQualityTtlSecs` | global | Positive integer | `1800` | In-process cache TTL for an air-quality result. |
| `plugins.Weather.geocodeCacheTtlDays` | global | Positive integer | `30` | How long a successful geocode is considered fresh. |
| `plugins.Weather.geocodeMissTtlHours` | global | Positive integer | `6` | Negative-cache TTL for a place Nominatim couldn't find. |
| `plugins.Weather.cacheMaxEntries` | global | Positive integer | `2000` | LRU bound for the in-process caches and the persisted geocode cache. |
| `plugins.Weather.nominatimRatePerMin` | global | Positive integer | `60` | Refill rate for the Nominatim limiter. Bucket capacity is always forced to `1.0` in code regardless of this value — Nominatim allows no burst above 1 request/second. |
| `plugins.Weather.owmRatePerMin` | global | Positive integer | `50` | Self-imposed headroom under OWM's free-tier 60/minute limit. |
| `plugins.Weather.openaqRatePerMin` | global | Positive integer | `50` | Self-imposed headroom under OpenAQ's free-tier 60/minute limit. |
| `plugins.Weather.airQualityRadiusMeters` | global | Positive integer | `25000` | Search radius for the nearest OpenAQ station that actually measures PM2.5 — not just the nearest station overall, several of which (confirmed live) measure only NO2/O3/etc. Up to 3 candidates are tried, nearest-capable-first. |
| `plugins.Weather.maxLineBytes` | global | Positive integer | `430` | UTF-8 byte budget for the `weather`/`w` line before segments are dropped (air fragment first, then forecast days from the last back). |

> `secretsPath`, `locationsPath`, and `geocodeCachePath` are resolved relative to the bot's own
> working directory (`runtime/`) — never prefix them with `runtime/`.

## When changes take effect

Every registry value here is re-read live, per command — no reload needed for a `@config` change.
A code change to any `plugins/Weather/*.py` file needs `@reload Weather` (no `shildml/` dependency
here, so a full bot restart is never required for this plugin).

## Files it reads/writes

| File | Purpose |
|---|---|
| `data/weather_locations.json` | Per-user saved locations (`setweather`/`unsetweather`). |
| `data/weather_geocode_cache.json` | Persisted Nominatim geocode cache — hits and negative-cached misses. |
| `secrets.json` | `openweathermap_key`, `openaq_key`. |
