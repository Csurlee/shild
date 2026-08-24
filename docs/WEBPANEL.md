# WebPanel

A LAN-only, authenticated web dashboard over data Shild/ChannelStats/ChannelLogger already
produce — a ZNC-web-style overview, channel logs, live channel preview, recently-scanned hosts,
per-channel stats, the evidence-gate A/B report, a commands reference, and (2026-08-24) a small,
explicitly allowlisted write surface.

**WebPanel exposes zero IRC commands.** It's controlled entirely through
`@config plugins.WebPanel.*` — `enable` takes effect live, no reload needed.

**Was read-only for a long time, on purpose — now has a small, scoped write surface.** Every
`POST` outside `/panel/controls/...` still returns a bare 405. The routes under
`/panel/controls/...` handle exactly four things: the Shild/SpamGuard kill switches (plus
UndernetX's X-fallback arm switch), Shild's ignore list, SpamGuard's term list, and 13 named
per-channel toggles — see "Controls (write surface)" below for the full design (CSRF, Origin/
Referer check, why there's still no code path that sets an arbitrary registry key). Ships
**inert**: `plugins.WebPanel.writeEnabled` defaults `False`.

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
| `/panel/controls` | Kill switches, Shild's ignore list, the per-channel picker. Read-only unless `writeEnabled` is on. |
| `/panel/controls/channel/<network>/<channel>` | 13 per-channel toggles (Shild `enabled`/`messageAnalysis`, SpamGuard's 10 `*Enabled` heuristics, UndernetX's `preferXCommands`). |
| `/panel/controls/terms` | SpamGuard's term list — add/remove by category (6 IRC-facing categories; removal is always by id, unambiguous across all 8 storage categories). |

Every Shild-backed page degrades to a "not loaded" 200 rather than a 500 if Shild isn't loaded.

## Controls (write surface, 2026-08-24)

**The write surface IS the allowlist** — `plugins/WebPanel/controls.py`'s `GLOBAL_SWITCHES` (3
entries) and `CHANNEL_TOGGLES` (13 entries) are the complete, hardcoded set of registry paths any
`POST` route can ever touch, plus SpamGuard's own term-add/remove validation and Shild's own
ignore-list validation. There is no route, anywhere, that accepts an arbitrary registry key and
writes it.

**Two CSRF layers**, neither alone the whole story:
- **Origin/Referer check (primary)** — a `POST` is rejected unless its `Origin` header (or, if
  absent, a same-origin `Referer`) matches an entry in `allowedHosts`. This is what actually stops
  a hostile page you merely visit from submitting a form here using your browser's cached Basic-
  Auth credentials — the `allowedHosts` Host-header check contributes nothing to this specific
  attack, since the attacker's form correctly targets the panel's own real address.
- **Signed CSRF token (secondary, defense-in-depth)** — a stateless, session-free HMAC token
  embedded in every rendered write form, checked on submit. Forging one would need XSS on the
  panel itself, which the existing `Content-Security-Policy: default-src 'none'` (no `script-src`
  at all) already rules out.
- **Neither layer defends against a LAN eavesdropper.** There is still no TLS anywhere in
  Limnoria's httpserver — the same caveat that already applies to the Basic-Auth password itself.

**Kill-switch polarity is never conflated.** `Shild.protection.killSwitch`/
`SpamGuard.protection.killSwitch` mean `True` = *safe* (enforcement disabled); UndernetX's
`enforcement.xFallbackEnabled` means `True` = *armed*. `/panel/controls` renders these as two
separate sections with per-switch action labels naming the resulting state — never a generic
"toggle" button. Disarming a kill switch, or arming the X-fallback, requires an extra "yes, I
understand" confirmation checkbox in the same form; the safer direction doesn't.

**Every write is logged** to `data/webpanel_actions.jsonl` (who, what, when, from which client
IP) — no IRC relay line for these, by deliberate choice.

**Ignore-list writes are host/IP only** — the web form doesn't accept a nick (resolving one needs
live `irc.state`, which the write routes must never touch — see the next section). Use
`!shildignore`/`!shildunignore` on IRC for nick-based resolution.

## Why per-channel writes go through a "peek/warm" split instead of the normal registry API

Limnoria's HTTP server runs on its **own dedicated thread**, separate from the main IRC reactor
thread — so a per-channel registry read/write from a write route runs concurrently with everything
else the bot is doing. `registry.Value.getSpecific()` (the normal way to read a per-channel value)
and the bundled `Config` plugin's own `channel` command (the normal way to write one) both *create*
a registry node as a side effect of merely being called — safe on the single main IRC thread it was
always called from, not safe from a second thread, since Limnoria's own config-flush code
(`list.sort()`/dict iteration over the registry tree, run on shutdown) can race a concurrent node
creation and silently drop the write-back.

Fixed with three pure helpers in `controls.py`: `peek_channel_value` reads a value WITHOUT ever
creating a node (correct by construction — a node that doesn't exist yet always holds exactly its
parent's inherited value); `warm_channel_nodes` is the only function allowed to create a node, and
it's called only from a periodic **main-thread** event (`controlsWarmIntervalSecs`, default 60s,
`now=True`); `write_channel_value` refuses to write anything until both target nodes already exist
— which is what makes it structurally impossible for the HTTP thread to ever create one itself. A
channel's toggles are unwritable for at most one warm interval after the bot joins it (or after a
`@reload WebPanel`/`enable` toggle) — the page shows "not warmed up yet" instead of silently
failing.

## Configuration

All values are **global** except the 13 per-channel toggles listed above (which belong to
Shild/SpamGuard/UndernetX, not WebPanel itself).

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

### Controls (write surface)

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.WebPanel.writeEnabled` | Boolean | `False` | Master arm switch for every `POST` route under `/panel/controls/`. Checked FIRST, before even the Host/auth gate. |
| `plugins.WebPanel.csrfTokenTtlSecs` | Positive integer | `1800` | Rounding bucket for the CSRF token embedded in write forms — valid for between this and 2x this after being rendered. |
| `plugins.WebPanel.controlsWarmIntervalSecs` | Positive integer | `60` | How often the main-thread "warm" pass runs — see the peek/warm section above. |
| `plugins.WebPanel.auditPath` | String | `data/webpanel_actions.jsonl` | Where every successful write action is logged. |

## When changes take effect

`enable` is live (hooks/unhooks the HTTP routes immediately), as is `allowedHosts` and
`writeEnabled` (both re-read per request). Everything else — the auth-tuning values, refresh
intervals, path overrides, and the CSRF/warm-interval/audit-path values above — is captured at
plugin load/reload time and needs `@reload WebPanel`. Credential file changes (a new hash in
`secrets.json`) are picked up on the next request via mtime watching, without a reload — but a
*previously cached* credential stays valid for up to `authCacheSecs` after rotation. A
`@reload WebPanel` also regenerates the CSRF signing key, invalidating any currently-open write
form (a deliberate tradeoff, not a bug).

## Files it reads/writes

| File | Purpose |
|---|---|
| `secrets.json` | `web_panel_user`, `web_panel_password_hash` (PBKDF2-SHA256, 600k iterations). |
| `webpanel_parted.json` | When each parted channel was first observed parted. |
| `runtime/logs/ChannelLogger/` | Read-only — the log files the panel serves and, eventually, deletes on retention expiry. |
| `data/webpanel_actions.jsonl` | Append-only audit log of every successful write action. |
