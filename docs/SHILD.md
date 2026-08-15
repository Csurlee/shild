# Shild

AI + ML classifier analysis for IRC joins and channel messages, with op-gated real enforcement.

Every join (and, optionally, every channel message) in an enabled channel is analyzed and logged
to `data/shadow_decisions.jsonl` — this shadow-mode logging is **unconditional** in every enabled
channel, regardless of op status or the kill switch. On top of that, a `ban` verdict additionally
becomes a real kick + ban only when **both** hold: the bot currently holds real op in that channel
(checked live, never cached) and the global kill switch is off. A `warn` verdict never triggers
real action.

See the main [README](../README.md) for the decision pipeline (classifier → evidence gate →
optional Ollama → fusion → enforcement) and [`CLAUDE.md`](../CLAUDE.md) for full operational
history.

## Status / prerequisites

Shild does nothing in a channel until `plugins.Shild.enabled` is set `True` for that
`(channel, network)` pair — this is deliberate, opt-in, and not settable by a channel op
(`opSettable=False`).

For real enforcement (not just shadow logging) to ever fire, **all** of the following must hold:

1. `plugins.Shild.enabled` is `True` for that channel
2. the fused decision is `ban` (never `warn`)
3. the bot actually holds op in that channel right now (checked live via IRC state)
4. `plugins.Shild.protection.killSwitch` is `False` (it **defaults to `True`** — safe out of the box)

Getting the bot opped at all is separate infrastructure (NickServ/ChanServ on Libera, X on
Undernet) — see `CLAUDE.md` → "Getting the bot opped". Even fully configured, Shild only ever
kicks+bans; it never voices, ops, or otherwise moderates beyond that.

## Commands

All six commands are **owner-only** — they surface real people's nicks, hosts, and reputation
data, and `shildcheck` spends real third-party API budget per call.

### `shildstatus`

```
takes no arguments
```

Reports Shild's status: classifier/model info, Ollama reachability, worker queue health, decision
counts since the last restart, and protection-mode state (kill switch, enforced count, pending
auto-unbans, ignore-list size). Sent as two separate IRC replies so nothing gets silently
truncated. The same data backs WebPanel's overview page, so IRC and the web panel can never drift.

```
<owner> shildstatus
<Shild> shild-py up 91234s (always shadow-logs; enforces only where opped and
        protection.killSwitch is off) | classifier: loaded (schema_hash=a1b2c3d4e5f6) |
        worker: running, dropped=0 | ollama: disabled (classifier-only) |
        events since restart: joins=142 messages=0 decisions=142 degraded=0 gated=3
<Shild> evidence cache: 87 entries | budget: {...} | protection: killSwitch=ON (safe)
        enforced=0 pending_unbans=0 ignored_hosts=4
```

### `shildreport [<YYYY-MM-DD>]`

```
[<YYYY-MM-DD>]
```

Returns an excerpt of the daily shadow-data review report (written by
`scripts/daily_data_analysis.sh`) — defaults to the most recent one, or a specific date. The full
report path is included in the reply so it can be opened directly.

```
<owner> shildreport
<Shild> 2026-08-13-report: 2 flagged: 91.193.232.107 (proxy+fraud, escalated); ...
<Shild> Full report: runtime/daily_analysis/2026-08-13-report.md
```

### `shildcheck <nick or host/IP>`

```
<nick or host/IP>
```

Manually runs the exact same classifier + evidence pipeline a live join would, against a nick
Shild has already seen (or is currently connected, via live IRC state), or a bare host/IP —
replies with the decision in the same format as a live `[shadow]` line, tagged
`[shadow-manual]`. **Never writes to `shadow_decisions.jsonl`** (not a real event) and **never
enforces**, regardless of the result or the kill switch — it only ever informs.

```
<owner> shildcheck 91.193.232.107
<Shild> [shadow-manual] checking 91.193.232.107 (91.193.232.107  @91.193.232.107 on undernet) ...
<Shild> [shadow-manual] BAN 91.193.232.107 (@91.193.232.107) in undernet via clas.+evi. (61%):
        IP 91.193.232.107 | network: Clouvider Limited AS62240 | flagged as proxy/VPN | ...
```

**Always shows a second line with the full gathered evidence (2026-08-14), regardless of the
outcome** — unlike the live `[shadow]` relay (which only ever posts non-`allow` decisions, so
staying terse is fine), this command always replies, including a clean `ALLOW` after a real Tier
1-3 lookup genuinely ran. The decision line's own reason text only ever embeds evidence when the
gate/escalation actually changed the action, so a clean check used to show nothing about what was
actually checked — fixed by always appending `[shadow-manual] evidence: ...` whenever evidence was
gathered (skipped only for the fast paths that never ran a real lookup at all: an ignored host, or
a channel-Tier-0-conclusive trusted cloak/account with nothing further to check).

### `shildignore <nick or host/IP>`

```
<nick or host/IP>
```

Adds a host to Shild's ignore list — future joins/messages from it resolve straight to `allow`,
skipping the classifier/evidence/Ollama pipeline entirely. For a known friend, the operator's own
second bot, or anything else that shouldn't be judged. The argument is resolved to **a host**, the
same way `shildcheck` resolves its target — a bare nick is never stored, since anyone could take
that nick later and inherit the bypass.

```
<owner> shildignore mybot
<Shild> mybot!~mybot@1.1.1.1 added to the ignore list.
```

### `shildunignore <nick or host/IP>`

```
<nick or host/IP>
```

Removes a host from the ignore list. Tries an exact match against what's actually stored first
(the common case of copying a host straight out of `shildlistignore`'s output), then falls back to
resolving the argument as a nick in case it no longer resolves to the same host it was added
under.

### `shildlistignore`

```
takes no arguments
```

Lists every host on the ignore list.

## Configuration

### Top level

| Value | Scope | Type | Default | Description |
|---|---|---|---|---|
| `plugins.Shild.enabled` | channel | Boolean | `False` | Whether shadow-mode analysis is active in this channel. Not op-settable. |
| `plugins.Shild.messageAnalysis` | channel | Boolean | `False` | Whether channel *messages* are analyzed, on top of joins (which are always analyzed once `enabled` is on). Off by default — message volume is what floods the Ollama worker queue. |
| `plugins.Shild.relayChannel` | network | String | `""` | Channel to relay "would have acted" shadow decisions to. Must never be the monitored channel itself. |
| `plugins.Shild.shadowDataPath` | global | String | `data/shadow_decisions.jsonl` | Path to the shadow-mode decision JSONL log. |
| `plugins.Shild.enforcementLogPath` | global | String | `data/enforcement_actions.jsonl` | Path to the JSONL log of real enforcement actions Shild itself took. |
| `plugins.Shild.moderationLogPath` | global | String | `data/observed_moderation.jsonl` | Path to the observed-moderation log: kicks/bans taken by **others** in enabled channels. |
| `plugins.Shild.secretsPath` | global | String | `secrets.json` | Path to the gitignored API-key file (AbuseIPDB/IPQS/Scamalytics). `SHILD_*` env vars take precedence. |
| `plugins.Shild.budgetPath` | global | String | `budget.json` | Path to persisted daily/lifetime lookup-budget counters. |
| `plugins.Shild.banIdsPath` | global | String | `shild_ban_ids.json` | Path to the persisted counter assigning each real ban its permanent `[ID: N]`. |
| `plugins.Shild.ignoreList` | global | Space-separated list | `[]` | Hosts Shild never evaluates. Managed via `shildignore`/`shildunignore`, not meant to be hand-edited. |

> All `*Path` values are resolved relative to the bot's own working directory (`runtime/`) — never
> prefix them with `runtime/`.

### `ollama.*`

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.Shild.ollama.enabled` | Boolean | `True` (code default — **`False` in this deployment**) | Whether the live decision path consults Ollama at all. Off = classifier-only; a non-confident classifier read resolves cleanly to `allow` rather than "degraded". |
| `plugins.Shild.ollama.url` | String | `http://localhost:11434` | Ollama API base URL. |
| `plugins.Shild.ollama.model` | String | `llama3.2:1b` | Ollama model name. |
| `plugins.Shild.ollama.timeout` | Positive float | `45.0` | Request timeout (seconds). CPU-only inference measured 23–46s; too low and every decision degrades to fail-open. |

### `classifier.*`

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.Shild.classifier.modelPath` | String | `models/shild_v2.npz` | Path to the classifier artifact. Missing/corrupt file → classifier reads as unavailable, never crashes. |
| `plugins.Shild.classifier.reloadCheckSecs` | Positive integer | `300` | How often to check whether the artifact on disk changed and hot-reload it. |

### `thresholds.*`

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.Shild.thresholds.classifierAct` | Probability | `0.85` | Classifier confidence required to skip consulting Ollama. |
| `plugins.Shild.thresholds.ollamaAct` | Probability | `0.75` | Ollama confidence required to treat its answer as actionable. |
| `plugins.Shild.thresholds.classifierActWithEvidence` | Probability | `0.50` | Lower confidence bar used **only** when independent host evidence already agrees with the classifier's own top ban/warn pick. Never usable alone. |
| `plugins.Shild.thresholds.classifierBanSecondaryFloor` | Probability | `0.30` | Floor on the classifier's own ban-probability (not its top pick) for the secondary-rank escalation sub-rule: promotes a `warn` to `ban` when ban was the classifier's 2nd choice (ranked above allow) at/above this floor, plus hard corroborating evidence. See `evidence.enableSecondaryBanEscalation` below. |

### `evidence.*`

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.Shild.evidence.enabled` | Boolean | `True` | Whether to gather host evidence and apply the evidence gate at all. Off is only useful for A/B comparison via `scripts/gate_report.py`. |
| `plugins.Shild.evidence.abuseipdbThreshold` | Integer | `50` | AbuseIPDB abuse-confidence score (0–100) at/above which a host counts as corroborated bad. |
| `plugins.Shild.evidence.ipqsThreshold` | Integer | `85` | IPQualityScore fraud score (0–100) at/above which a host counts as corroborated bad. |
| `plugins.Shild.evidence.scamalyticsThreshold` | Integer | `75` | Scamalytics fraud score (0–100) at/above which a host counts as corroborated bad (independent of the blacklist flag, which always counts). |
| `plugins.Shild.evidence.requireHardEvidenceForBan` | Boolean | `True` | A `ban` must be corroborated by **hard** evidence (DNSBL/IRCBL hit, confirmed open proxy port, bogon, or a score over threshold); a bare `geo_proxy` flag alone caps the action at `warn`. Safety valve — not recommended to disable. |
| `plugins.Shild.evidence.scamalyticsExtreme` | Integer | `80` | Higher bar than `scamalyticsThreshold`, used only by the extreme-evidence escalation sub-rule — a score this high can promote `warn`→`ban` even when the classifier's own ban-probability ranked below allow. |
| `plugins.Shild.evidence.abuseipdbExtreme` | Integer | `90` | Same as `scamalyticsExtreme` but for AbuseIPDB. |
| `plugins.Shild.evidence.ipqsExtreme` | Integer | `95` | Same as `scamalyticsExtreme` but for IPQualityScore. |
| `plugins.Shild.evidence.enableSecondaryBanEscalation` | Boolean | `True` | Safety valve for both new secondary escalation sub-rules (secondary-rank floor and extreme-evidence override). Independent of `requireHardEvidenceForBan`, which only governs the older hard/soft cap. |

### `dnsbl.*` / `ipapi.*` / `abuseipdb.*` / `ipqs.*` / `scamalytics.*` / `proxyscan.*`

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.Shild.dnsbl.timeout` | Positive float | `5.0` | DNS lookup timeout (seconds) for DNSBL/DroneBL/bogon/Tor-exit/IRCBL checks. |
| `plugins.Shild.dnsbl.cacheTtl` | Positive integer | `21600` (6h) | Cache TTL per IP for DNSBL results; also reused as the Tier 2 cache TTL. |
| `plugins.Shild.ipapi.timeout` | Positive float | `8.0` | HTTP timeout for ip-api.com geo/proxy lookups. |
| `plugins.Shild.ipapi.cacheTtl` | Positive integer | `86400` (24h) | Cache TTL per IP for ip-api.com results. |
| `plugins.Shild.ipapi.rateLimitPerMinute` | Positive integer | `45` | ip-api.com's free-tier rate limit. |
| `plugins.Shild.abuseipdb.enabled` | Boolean | `True` | Whether to call AbuseIPDB as a Tier 2 check. Silently skipped without a key. |
| `plugins.Shild.abuseipdb.dailyLimit` | Positive integer | `1000` | AbuseIPDB's free-tier daily limit. |
| `plugins.Shild.ipqs.enabled` | Boolean | `False` | Whether to call IPQualityScore. Ships off — the configured account has 0 usable free-tier credits. |
| `plugins.Shild.ipqs.lifetimeLimit` | Positive integer | `1000` | IPQualityScore's free-tier allowance (lifetime, not daily). |
| `plugins.Shild.scamalytics.enabled` | Boolean | `True` | Whether to call Scamalytics as a second Tier 2 check. Needs both a username and key; silently skipped otherwise. |
| `plugins.Shild.scamalytics.dailyLimit` | Positive integer | `150` | Conservative daily approximation of Scamalytics' 5,000-credit/month free tier. |
| `plugins.Shild.scamalytics.dailyLimit2` | Positive integer | `150` | Same, for an optional second Scamalytics account used only once the primary's daily budget is exhausted. |
| `plugins.Shild.proxyscan.enabled` | Boolean | `True` | Whether to actively probe a joining host for open proxy ports (Tier 3). Connects to a third party's machine — qualitatively different from every other check. |
| `plugins.Shild.proxyscan.connectTimeout` | Positive float | `2.0` | Per-port connect timeout (seconds). |
| `plugins.Shild.proxyscan.overallTimeout` | Positive float | `6.0` | Hard deadline for the whole port scan regardless of port count. |

### `worker.*` / `report.*`

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.Shild.worker.maxQueue` | Positive integer | `8` | Max pending worker jobs before drop-oldest shedding. |
| `plugins.Shild.worker.maxConcurrency` | Positive integer | `1` | Max concurrent Ollama requests, matched to real backend capacity. |
| `plugins.Shild.report.dir` | String | `runtime/daily_analysis` | Directory of daily review reports. |
| `plugins.Shild.report.announce` | Boolean | `True` | Whether to relay an excerpt to `relayChannel` when a new report appears. |
| `plugins.Shild.report.checkIntervalSecs` | Positive integer | `600` | How often to check for a new report. |

### `protection.*`

| Value | Type | Default | Description |
|---|---|---|---|
| `plugins.Shild.protection.killSwitch` | Boolean | `True` (safe) | Global override: while `True`, Shild never takes a real enforcement action anywhere, regardless of op status. Shadow logging/relay is unaffected either way. |
| `plugins.Shild.protection.banDurationSecs` | Positive integer | `3600` (60 min) | How long a real ban lasts before automatic unban. |

## When changes take effect

| Live (re-read per event) | Needs `@reload Shild` | Needs a full restart |
|---|---|---|
| `thresholds.*` (incl. `classifierBanSecondaryFloor`) | `evidence.abuseipdbThreshold` / `ipqsThreshold` / `scamalyticsThreshold` / `requireHardEvidenceForBan` / `scamalyticsExtreme` / `abuseipdbExtreme` / `ipqsExtreme` / `enableSecondaryBanEscalation` | Never for config values — but the `shildml/fusion.py` + `shildml/evidence.py` code behind the two new `evidence.*Extreme`/`enableSecondaryBanEscalation`-gated escalation sub-rules (2026-08-14) needs a full restart to load at all, same as any other `shildml/` change |
| `protection.*` | `dnsbl.*`, `ipapi.*`, `abuseipdb.*`, `ipqs.*`, `scamalytics.*`, `proxyscan.*` | |
| `ollama.*` | `classifier.*`, `worker.*` | |
| `evidence.enabled` | all `*Path` values, `report.checkIntervalSecs` | |
| `enabled`, `messageAnalysis`, `relayChannel`, `ignoreList`, `report.dir`, `report.announce` | | |

A code change to `shildml/` itself (the pure ML package) always needs a full bot restart — `@reload
Shild` does not re-import it, since it's a separate top-level package. See `CLAUDE.md` for the
history behind that rule.

## Files it reads/writes

| File | Purpose |
|---|---|
| `data/shadow_decisions.jsonl` | Every decision, unconditional (`fused_raw` + `fused` + `gate` + full `evidence`). |
| `data/enforcement_actions.jsonl` | Real kick+ban actions Shild itself took. |
| `data/observed_moderation.jsonl` | Kicks/bans observed from **other** ops/bots — free ground truth. |
| `secrets.json` | `abuseipdb_key`, `ipqs_key`, `scamalytics_username`/`_key` (+ optional `_username2`/`_key2`). |
| `budget.json` | Persisted daily/lifetime lookup-quota counters. |
| `shild_ban_ids.json` | Persisted counter for the `[ID: N]` shown in every real kick message. |
| `models/shild_v2.npz` | The trained classifier artifact. |
