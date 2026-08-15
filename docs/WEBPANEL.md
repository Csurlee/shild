# WebPanel

A read-only, LAN-only, authenticated web dashboard over data Shild/ChannelStats/ChannelLogger
already produce — a ZNC-web-style overview, channel logs, live channel preview, recently-scanned
hosts, per-channel stats, the evidence-gate A/B report, and a commands reference.

**WebPanel exposes zero IRC commands.** It's controlled entirely through
`@config plugins.WebPanel.*` — `enable` takes effect live, no reload needed.

**Deliberately read-only.** Every `POST` to any route returns a bare 405. Basic Auth gives zero
CSRF protection, so a settings-writing route needs a session/cookie/CSRF-token layer, an
Origin/Referer check, and a capability-based allowlist of settable keys before it can exist safely
— none of that exists yet, on purpose.

## Setup

In order — skipping any step leaves the panel either unreachable or refusing every request:

1. **Enable it**: `@config plugins.WebPanel.enable True`
2. **Generate credentials** — run this directly on the server, never through IRC:
   ```
   python plugins/WebPanel/auth.py
   ```
   Run it **directly**, not as `python -m plugins.WebPanel.auth` — the `-m` form imports the file
   through the `plugins.WebPanel` package, which raises `AttributeError` via Limnoria's own
   i18n machinery. The script prompts for a username and password (never echoed, never logged) and
   prints two lines to paste into `runtime/secrets.json` yourself:
   ```json
   {"web_panel_user": "...", "web_panel_password_hash": "pbkdf2_sha256$600000$..."}
   ```
   **Both keys must be present or the panel returns 503 on every request** — unlike every other
   secrets loader in this repo (which fails open), a missing WebPanel credential fails **closed**,
   because "open" here means serving real nicks, hosts, and reputation scores to the LAN with no
   login at all.
3. **Bind the HTTP server** to a reachable address — Limnoria's own registry, not WebPanel's:
   ```
   @config supybot.servers.http.hosts4 192.168.1.10
   @config supybot.servers.http.port 8080
   ```
   `0.0.0.0` is Limnoria's own default — deliberately overridden to a specific LAN IP in this
   deployment, since there is **no TLS anywhere** in Limnoria's httpserver: the password and every
   page cross the network in cleartext. Never set `supybot.servers.http.publicUrl`, never
   port-forward this, never point dynamic DNS at it.
4. **Match `allowedHosts`** to that same address — the entire defense against DNS rebinding, and
   the most common way this looks "broken" when it isn't:
   ```
   @config plugins.WebPanel.allowedHosts "192.168.1.10:8080 127.0.0.1:8080 localhost:8080"
   ```
   Any request whose `Host` header isn't in this list gets a 400 **before** authentication is even
   checked. An empty list rejects everything.

## Routes

All routes live under `/panel/`. There is no unauthenticated route, not even `/panel/health`.

| Route | Shows |
|---|---|
| `/panel/` | Overview — the same data `!shildstatus` formats, so IRC and web can't drift. |
| `/panel/health` | Plain-text `ok`. Still requires auth. |
| `/panel/logs` | Index of every logged `(network, channel)`, with a "Parted — deletes `<date>`" annotation for parted channels. |
| `/panel/log/<network>/<channel>` | Tail of that channel's log, IRC formatting stripped. `?n=` to request more lines (capped). |
| `/panel/report` | The newest daily shadow-data review report. `?date=YYYY-MM-DD` for a specific one. |
| `/panel/scans` | Table of recently scanned hosts from `data/shadow_decisions.jsonl`. `?n=` (1–100). |
| `/panel/stats` | Per-channel ChannelStats counts, a 7×24 activity heatmap, and a background-refreshed near-miss/distribution summary. |
| `/panel/gate` | The pre/post-evidence-gate A/B report over the whole corpus (background-refreshed). |
| `/panel/commands` | Every loaded plugin's commands with parsed docstring help — respects the same `public` gating the patched IRC `list` command enforces. |
| `/panel/live` | Index of channels available for live preview, with parted annotations. |
| `/panel/live/decisions` | Cross-network live decision feed (Shild's recent join/message events). |
| `/panel/live/<network>/<channel>` | Auto-refreshing tail of the last N lines. No JavaScript at all — plain `<meta http-equiv="refresh">`, `Content-Security-Policy: default-src 'none'`. |

Every Shild-backed page degrades to a "not loaded" 200 rather than a 500 if Shild isn't loaded.

## Configuration

All 21 values are **global** — none are per-channel or per-network.

### Access control

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.WebPanel.enable` | Boolean | `False` | Whether the panel's HTTP routes are hooked at all. Takes effect live. |
| `plugins.WebPanel.secretsPath` | String | `secrets.json` | Path to the file holding `web_panel_user`/`web_panel_password_hash`. |
| `plugins.WebPanel.allowedHosts` | Space-separated list | `127.0.0.1:8080 localhost:8080` | Host-header allowlist — the entire DNS-rebinding defense. Must match the actual bind address/port. |
| `plugins.WebPanel.authCacheSecs` | Non-negative integer | `300` | How long a verified credential is cached in memory, so the deliberately slow PBKDF2 hash isn't re-run on every request. Set to `0` while rotating the password. |
| `plugins.WebPanel.maxAuthFailures` | Positive integer | `5` | Failed logins from one client IP within 60s before lockout. |
| `plugins.WebPanel.authLockoutSecs` | Positive integer | `300` | Lockout duration once `maxAuthFailures` is hit. |

### Data sources

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.WebPanel.channelLogDir` | String | `""` | Base directory of ChannelLogger's per-channel logs. Empty derives it from Limnoria's own log directory. |
| `plugins.WebPanel.reportDir` | String | `""` | Directory of Shild's daily report files. Empty derives it from `Shild.report.dir` if loaded. |
| `plugins.WebPanel.shadowDataPath` | String | `""` | Path to `data/shadow_decisions.jsonl`. Empty derives it from `Shild.shadowDataPath` if loaded. |
| `plugins.WebPanel.partedStatePath` | String | `webpanel_parted.json` | Persisted record of when each parted channel was first observed parted. |

### Page behavior

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.WebPanel.logTailLines` | Positive integer | `300` | Default lines shown on `/panel/log/...`. |
| `plugins.WebPanel.logTailMaxBytes` | Positive integer | `1048576` (1 MiB) | Hard cap on bytes ever read for one log-tail request. |
| `plugins.WebPanel.recentScansCount` | Positive integer | `10` | Default rows on `/panel/scans` (max 100 via `?n=`). |
| `plugins.WebPanel.summaryRefreshSecs` | Positive integer | `300` | How often `/panel/stats`' background summary recomputes. |
| `plugins.WebPanel.gateRefreshSecs` | Positive integer | `900` | How often `/panel/gate`'s A/B report recomputes. |
| `plugins.WebPanel.livePreviewSource` | String (`logfile`/`none`) | `logfile` | Where per-channel live preview gets its content, or disables it. |
| `plugins.WebPanel.liveLines` | Positive integer | `40` | Lines shown per refresh on a live-preview page. |
| `plugins.WebPanel.liveRefreshSecs` | Positive integer | `10` | Auto-refresh interval (floored at 3 regardless of this value). |
| `plugins.WebPanel.liveDecisionsCount` | Positive integer | `30` | Rows shown on `/panel/live/decisions`. |
| `plugins.WebPanel.partedRetentionDays` | Positive integer | `7` | Days after a channel is first observed parted before its log directory is **deleted** — irreversibly. |
| `plugins.WebPanel.partedCheckIntervalSecs` | Positive integer | `3600` | How often the parted-channel check runs. |

## When changes take effect

`enable` is live (hooks/unhooks the HTTP routes immediately). Everything else — the auth-tuning
values, refresh intervals, and path overrides — is captured at plugin load/reload time and needs
`@reload WebPanel`. Credential file changes (a new hash in `secrets.json`) are picked up on the
next request via mtime watching, without a reload — but a *previously cached* credential stays
valid for up to `authCacheSecs` after rotation.

## Files it reads/writes

| File | Purpose |
|---|---|
| `secrets.json` | `web_panel_user`, `web_panel_password_hash` (PBKDF2-SHA256, 600k iterations). |
| `webpanel_parted.json` | When each parted channel was first observed parted. |
| `runtime/logs/ChannelLogger/` | Read-only — the log files the panel serves and, eventually, deletes on retention expiry. |
