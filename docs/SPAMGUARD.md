# SpamGuard

Deterministic content-match kick+ban for spam bots that join a channel and immediately paste a
known template message (or connect with a known-bad nick/ident/realname).

Unlike Shild, this is **not** an ML/evidence decision — it's an exact substring/regex match
against admin-curated terms, mirroring Shild's own Phase 2 enforcement safety model (own kill
switch, op-gated, auto-unban) rather than Limnoria's bundled `BadWords` plugin (which was
evaluated and rejected — see `CLAUDE.md`).

## Status / prerequisites

SpamGuard does nothing in a channel until `plugins.SpamGuard.enabled` is `True` for that channel,
and takes no real enforcement action until **all** of the following hold:

1. a term actually matches (content, ident, nick, or realname)
2. for a **content** match only: the sender joined within `joinWindowSecs` (default 60s) — ident,
   nick, and realname matches have no such window, since the match *is* the join event
3. the sender isn't exempt (channel halfop+, holds the channel's `op` capability, or —
   if `exemptRegistered` — is any recognized registered user at all)
4. `plugins.SpamGuard.protection.killSwitch` is `False` (**defaults `True`** — safe out of the box,
   independent of Shild's own kill switch)
5. the bot actually holds op in that channel right now (checked live) **or** (Undernet only,
   2026-08-16) it lacks op but a live-verified X capability fallback is available — see
   `docs/UNDERNETX.md`'s "X-routed enforcement fallback"; the native path is always used instead
   when the bot does hold op, regardless of the X cache

Every match is logged and relayed regardless of whether it acted, tagged with the exact reason it
didn't (`killswitch` / `not-opped` / `outside-window` / `exempt`) or that it did (`enforced`) — so
the term list can be tuned against real traffic before ever arming the kill switch. Each `enforced`
record's `via` field (2026-08-16) is `"native"` or `"x"`.

## Terms: id-keyed, not registry lists

Every term (word/phrase/pattern/ident/nick/realname) gets a **permanent numeric id** the moment
it's added, stored in a small JSON file (`plugins.SpamGuard.termsPath`), not the Limnoria registry
— this is what makes a term survive both a bot restart *and* a full `bootstrap_runtime.py` regen
with no script edit needed. The id shows up in the real kick message and in every log line, so a
past ban can always be looked back up.

There are **6 user-facing categories** you type on IRC, which map onto **8 internal storage
categories** — a `word`/`realname` term containing a space is automatically stored as a phrase:

| You type | Contains a space? | Stored as |
|---|---|---|
| `word` | no | `word` |
| `word` | yes | `phrase` |
| `ident` | (n/a — idents can't contain spaces) | `ident` |
| `nick` | (n/a — nicks can't contain spaces) | `nick` |
| `realname` | no | `realname_word` |
| `realname` | yes | `realname_phrase` |
| `pattern` | (n/a — always a regex) | `pattern` |
| `black` | (n/a — a nick or host, never a space) | `black` |

**Content** (`word`/`phrase`/`pattern`) is checked on channel messages, subject to the join
window. **Ident** is always present at JOIN, no capability needed. **Nick** is likewise always
present at JOIN (added 2026-08-13). **Realname** is only present on a JOIN when the server
negotiated IRCv3 `extended-join` — where it isn't supported, realname matching silently never
fires for that network. This is correct fail-safe behavior, not a bug. **Black** (2026-08-14) is
checked against BOTH a candidate's nick and host at JOIN (whichever hits) — see the dedicated
section below, it behaves differently from every other category in one important way.

At JOIN, fields are checked in this order, first match wins: **black → nick → ident → realname**
(content is a separate check, on PRIVMSG). If more than one field would match the same join, only
the first one checked is acted on/logged — one enforcement action per join, never two.

## Blacklist (`black`): matches nick or host, acts immediately too

`spamguard black add <nick/host>` is different from every other category in one real way: it
doesn't only block **future** joins/messages — the moment you add it, SpamGuard also immediately
sweeps **every network the bot is currently connected to** for anyone already sitting in an
enabled channel who matches, and kick+bans them right then (subject to the exact same exemption/
kill-switch/op gates as any live match — an already-present halfop+ or registered user is still
exempt, and nothing happens anywhere the kill switch is on, or the bot isn't opped and has no
live-verified X capability fallback available either — see `docs/UNDERNETX.md`'s "X-routed
enforcement fallback", 2026-08-16).

```
<owner> spamguard black add badbot
<Shild> 'badbot': added [id:9] -- kbanned 2 already-present match(es)
```

A `black` term matches against **both** a candidate's nick and their host — add a nick-shaped
string to catch a bot by its fixed default nick, or a host/hostname to catch it by connection
regardless of what nick it picks. The ban mask is always host-based (`*!*@<host>`, same fallback
every non-ident/nick field already uses) — nicks are too disposable to be worth banning by alone.

`black` is checked *first* at JOIN, ahead of nick/ident/realname — the most deliberate signal this
plugin has. `spamguardlist`/`spamguardsearch`/`spamguardremove` all work with `black` entries
exactly like any other category; there's no separate "unblacklist" command, just
`spamguard black remove <term>` or `spamguardremove <id>`.

**Scope note**: the retroactive sweep only reaches channels where `plugins.SpamGuard.enabled` is
already `True` — adding a `black` entry does not override or bypass that per-channel opt-in, same
as every other mechanism in this plugin. "Every channel the bot is or joins" means every channel
SpamGuard actually watches, not literally every channel the bot's IRC connection happens to be in.

## Message heuristics (flood, hilight, caps, mojibake, raid)

Four non-term, threshold-based message detectors (2026-08-14) — adapted from ideas in Libera
Chat's own `ozone` network-abuse bot (`github.com/Libera-Chat/ozone`), reimplemented independently
rather than copied (except the mojibake regex table, vendored verbatim under its MIT license — see
`mojibake.py`'s module docstring). Each funnels through the **same** gate chain as content/ident/
nick/realname matches (exemption → kill switch → op), checked only when no content term already
matched a message, and none require the join window — these are general per-message conduct
signals, not specifically the "just joined and pasted a template" pattern content matching targets.

A fifth, **raid** (2026-08-16), is join-based rather than message-based — adapted the same
"idea, not code" way from the "grouped flood" concept in progval's `AttackProtector` plugin
(`github.com/progval/Supybot-plugins/tree/master/AttackProtector`, 2010-era code, not vendored).
It fires on `raidJoinLimit` **distinct** nicks joining the same channel within `raidWindowSecs`,
but — unlike AttackProtector's own group-flood punishment, which can act on the whole burst — only
ever enforces against the ONE joiner whose join tipped the count over the limit, never retroactively
against the earlier ones. This is deliberately conservative: a genuine netsplit-reconnect burst of
real regulars rejoining together looks identical to a coordinated raid at the network level, so
`raidJoinLimit` defaults meaningfully higher than a single-nick flood threshold, and — like every
other heuristic here — it still funnels through the same exemption/kill-switch/op gate chain.

Unlike a term list (implicitly inert until a word/phrase/pattern is added), a threshold is always
*live* the moment code exists to check it — so each heuristic is its own **per-channel opt-in,
default off**, the equivalent safety property. Enable them one at a time and watch `[spamguard]`
relay lines with the kill switch still on, same staged-rollout discipline as the original word list.

| Heuristic | Enable value (channel) | Triggers when |
|---|---|---|
| **flood** | `plugins.SpamGuard.floodEnabled` | `floodMessageLimit` (default 5) messages from the same nick within `floodWindowSecs` (default 8.0s) |
| **hilight** | `plugins.SpamGuard.hilightEnabled` | a single message names `hilightNickLimit` (default 4) or more distinct real channel members by nick (each ≥ `hilightMinNickLen` chars, default 3) — classic raid-bot behavior |
| **caps** | `plugins.SpamGuard.capsEnabled` | `capsPercent` (default 70%) or more of a message's *letters* are uppercase, once it's at least `capsMinLength` (default 10) characters |
| **mojibake** | `plugins.SpamGuard.mojibakeEnabled` | `mojibake.mojibake_score()` (garbled-character-encoding detection) is at/above `mojibakeScore` (default 2) |
| **raid** | `plugins.SpamGuard.raidEnabled` | `raidJoinLimit` (default 8) *distinct* nicks join the channel within `raidWindowSecs` (default 15.0s) — acts only on the tipping-point joiner |

Each match is logged/relayed/enforced exactly like a term match, using a fixed negative pseudo-id
(`flood=-1`, `hilight=-2`, `caps=-3`, `mojibake=-4`, `raid=-5`) in place of a real TermStore id,
since these aren't user-managed text entries — `spamguardsearch`/`spamguardremove` never apply to
them; tune via `@config`/`config channel` instead. `spamguardstatus`, run **in a channel**, shows
that channel's on/off state for all five on a second reply line.

## Commands

All five commands are **owner-only**.

### `spamguard <word|ident|nick|realname|pattern|black> <add|remove> <term> [...]`

```
<word|ident|nick|realname|pattern|black> <add|remove> <term> [...]
```

Adds or removes one or more terms. A space in a `word`/`realname` term auto-stores it as a phrase.
`pattern` terms are validated as regex at add time — an invalid one is rejected with a reply, not
silently stored. Multiple terms may be given in one call; each gets its own result line. Category
names accept unambiguous abbreviation (`p` → `pattern`, `i` → `ident`, `n` → `nick`, `b` →
`black`). `black add` also immediately kbans any already-present match — see the dedicated
section above.

```
<owner> spamguard word add Czura
<Shild> 'Czura': added [id:1]

<owner> spamguard pattern add \bfree.{0,3}crypto\b
<Shild> '\bfree.{0,3}crypto\b': added [id:2]
```

### `spamguardlist`

```
takes no arguments
```

Lists every term with its id, grouped by category (content words, content phrases, content
patterns, idents, nicks, realname words, realname phrases, blacklist) — eight separate replies.

### `spamguardsearch <id or text>`

```
<id or text>
```

An exact numeric id always wins outright. Otherwise, a case-insensitive substring search across
every category's term text. Results capped at 20, with a `(+N more, refine your query)` suffix.

```
<owner> spamguardsearch czu
<Shild> [id:1] word: 'Czura'
```

### `spamguardremove <id>`

```
<id>
```

Removes a single term by its permanent id, regardless of category — the general counterpart to
`spamguard <category> remove <term>`'s by-text-within-one-category form. Rebuilds the compiled
matchers immediately; no reload needed.

### `spamguardstatus`

```
takes no arguments
```

Reports match/enforcement counters (since the last restart), kill-switch state, pending
auto-unbans, and per-category term counts — including a count of any stored patterns that failed
to compile. Run in a channel, a second reply line also shows that channel's flood/hilight/caps/
mojibake/raid enable state.

## Configuration

### Live, meaningful values

| Value | Scope | Type | Default | Description |
|---|---|---|---|---|
| `plugins.SpamGuard.enabled` | channel | Boolean | `False` | Whether SpamGuard watches this channel at all. Not op-settable. |
| `plugins.SpamGuard.termsPath` | global | String | `data/spamguard_terms.json` | The persisted, id-keyed term store — the actual source of truth for matching. |
| `plugins.SpamGuard.hostBansPath` | global | String | `data/spamguard_host_bans.json` | The persisted host-ban history store (see below). |
| `plugins.SpamGuard.hostBanAutoRebanEnabled` | global | Boolean | `False` | Arm switch for real auto-reban on a rejoin from a known-bad host. Recording into the store always happens regardless. |
| `plugins.SpamGuard.hostBanRetentionDays` | global | Positive integer | `30` | Days of inactivity before a host-ban record stops being eligible to trigger a reban. Refreshed on every hit. |
| `plugins.SpamGuard.hostBanPruneIntervalSecs` | global | Positive integer | `3600` | How often expired host-ban records are actually deleted from the file. |
| `plugins.SpamGuard.joinWindowSecs` | global | Positive integer | `60` | How long after a tracked join a **content** match is still eligible to enforce. Ident/realname matches ignore this. |
| `plugins.SpamGuard.exemptRegistered` | global | Boolean | `True` | Whether any ircdb-registered user is exempt from enforcement, on top of the always-exempt halfop+/channel-op cases. |
| `plugins.SpamGuard.logPath` | global | String | `data/spamguard_actions.jsonl` | JSONL log of every match seen, acted on or not. |
| `plugins.SpamGuard.relayChannel` | network | String | `""` | Channel to relay match notices to. Empty disables relaying (logging still happens). |
| `plugins.SpamGuard.protection.killSwitch` | global | Boolean | `True` (safe) | While `True`, SpamGuard never takes real action anywhere. Independent of Shild's own kill switch. |
| `plugins.SpamGuard.protection.banDurationSecs` | global | Positive integer | `3600` | How long a real ban lasts before automatic unban. |
| `plugins.SpamGuard.protection.kickReason` | global | String | `You are not welcome here!` | Reason text embedded in the kick message (see format below). May contain a literal `{term}` placeholder, substituted with the matched term's text — a value with no placeholder is used as-is. |
| `plugins.SpamGuard.floodEnabled` | channel | Boolean | `False` | Whether the flood heuristic is checked in this channel. Not op-settable. |
| `plugins.SpamGuard.floodMessageLimit` | global | Positive integer | `5` | Messages from the same nick within `floodWindowSecs` that counts as flooding. |
| `plugins.SpamGuard.floodWindowSecs` | global | Positive float | `8.0` | Rolling window (seconds) `floodMessageLimit` is counted over. |
| `plugins.SpamGuard.hilightEnabled` | channel | Boolean | `False` | Whether the mass-highlight heuristic is checked in this channel. Not op-settable. |
| `plugins.SpamGuard.hilightNickLimit` | global | Positive integer | `4` | Distinct real channel members named by nick in one message that counts as a mass-highlight. |
| `plugins.SpamGuard.hilightMinNickLen` | global | Positive integer | `3` | Nicks shorter than this never count toward `hilightNickLimit`. |
| `plugins.SpamGuard.capsEnabled` | channel | Boolean | `False` | Whether the excessive-caps heuristic is checked in this channel. Not op-settable. |
| `plugins.SpamGuard.capsPercent` | global | Probability | `0.70` | Fraction of a message's *letters* that must be uppercase to trigger. |
| `plugins.SpamGuard.capsMinLength` | global | Positive integer | `10` | Messages shorter than this (characters) are never checked for excessive caps. |
| `plugins.SpamGuard.mojibakeEnabled` | channel | Boolean | `False` | Whether the mojibake heuristic is checked in this channel. Not op-settable. |
| `plugins.SpamGuard.mojibakeScore` | global | Positive integer | `2` | `mojibake.mojibake_score()` value at/above which a message triggers — a raw count, not a percentage. |
| `plugins.SpamGuard.raidEnabled` | channel | Boolean | `False` | Whether the raid (coordinated-join) heuristic is checked in this channel. Not op-settable. |
| `plugins.SpamGuard.raidJoinLimit` | global | Positive integer | `8` | Distinct nicks joining within `raidWindowSecs` that counts as a raid. Higher than `floodMessageLimit` on purpose — a grouped signal needs more corroboration. |
| `plugins.SpamGuard.raidWindowSecs` | global | Positive float | `15.0` | Rolling window (seconds) `raidJoinLimit` is counted over. |

> `termsPath` and `logPath` are resolved relative to the bot's own working directory (`runtime/`)
> — never prefix them with `runtime/`.

Real kick reason format:
`SpamGuard: "<term>" - <nick>!<ident>@<host> - reason: <kickReason, with {term} substituted> - [id: <term id>]`

For example, with `kickReason` set to `Blacklisted: {term}`:
```
SpamGuard: "Czura" - primaryocelo!~ocelo@31.59.107.19 - reason: Blacklisted: Czura - [id: 1]
```

The hostmask shown is the **actual connecting identity** (`nick!ident@host`) — not necessarily the
ban mask that was set (see below). A `{term}` placeholder that fails to substitute (a stray `{`
from a typo, not the real placeholder) falls back to the raw configured string rather than ever
blocking enforcement.

**The ban mask itself targets whichever field actually matched, not always the host**:
- `ident` match → bans `*!<ident>@*` (the exact ident string observed, e.g. `*!~badident@*`) — the
  whole point of an ident-based rule is to catch that same ident reconnecting from a different IP.
- `nick` match → bans `<nick>!*@*` (e.g. `badbot!*@*`). Weaker than the other masks in one real
  sense: nicks are the most freely reusable identity of the three — without NickServ registration
  and enforcement, literally anyone can pick up a banned nick next. Still useful for a known-bad
  literal nick (a bot's fixed default), just don't expect it to survive a determined nick change.
- `content`, `realname`, `black`, and every heuristic (flood/hilight/caps/mojibake/raid/
  `host_history`) fall back to a host-based mask: content/black-by-nick/heuristics have no identity
  component of their own, and realname isn't part of an IRC ban mask at all (masks are strictly
  `nick!ident@host`).

**The host-based fallback is itself ident-aware (2026-08-22)**: an ident beginning with `~` means
the ircd could not verify it against a real identd response — the overwhelming majority of spam
bots connect this way. In that case the mask is narrowed to `*!~*@<host>`, which can ONLY ever
match another unverified-ident connection from that host — a later, unrelated person connecting
from the same IP/host with a real ident server running is never caught by it. A verified ident (no
`~`) is treated as real evidence this is a person, not a bot: banned normally with the full
`*!*@<host>` mask, exactly as before this feature existed.

Since the mask can differ from the hostmask shown in the kick reason, check `/mode <channel> +b`
live for the real active mask.

## Persisted host-ban history: auto-reban a known-bad host (2026-08-22)

A real, host-based enforcement (content/realname/pattern/black/any heuristic — never an ident- or
nick-field match) is automatically recorded to a small JSON store (`plugins.SpamGuard.hostBansPath`,
`hostbans.py`) the moment it fires, keyed by host/IP: the exact kick message, the term/field that
triggered it, first/last-seen timestamps, and a hit count. This survives both the temporary ban's
own auto-unban (`protection.banDurationSecs`, default 1h) and a bot restart — the whole point is
remembering a convicted host well after either of those.

**Recording always happens** and is harmless on its own (see `spamguardhostbans` below). **Real
auto-reban action is a separate, explicit arm switch**: `plugins.SpamGuard.hostBanAutoRebanEnabled`
(default `False`, global). Once armed, every JOIN checks the store FIRST — ahead of even `black` —
and if the host has a live (non-expired) record, **and the rejoining identity is ALSO running
unverified ident** (leading `~`), it's immediately re-kicked+banned using the exact original kick
message, no fresh term match needed. A rejoin from that same host with a *real* ident server is left
completely alone — same "not evidence this is the same actor" reasoning as the mask change above,
and it's a plain fall-through to the normal black/nick/ident/realname/heuristic chain, not a special
exemption.

A record ages out after `hostBanRetentionDays` (default 30) of inactivity — refreshed on every hit,
so a repeat offender stays flagged indefinitely, but a host that hasn't been seen in a long time
stops being eligible to auto-reban, protecting against a dynamic/residential IP later being
reassigned by its ISP to someone completely unrelated. A background sweep
(`hostBanPruneIntervalSecs`, default 1h) actually deletes expired records from the file; an expired
but not-yet-swept record still shows in `spamguardhostbans` output, just marked `expired`.

### `spamguardhostbans`

```
takes no arguments
```

Lists every persisted record: host, the field/term it was originally convicted on, hit count, how
long ago it was last seen, and whether it's currently `active` (would fire) or `expired`.

### `spamguardhostbansremove <host>`

```
<host or IP>
```

Manual override for a false positive — removes one record outright. Find the exact host string via
`spamguardhostbans` first.

### Legacy — migration-only, do not use

These six values used to be the live source of truth. They are now read **exactly once**, at
plugin startup, and **only if the term store is still completely empty** — a brand-new deployment.
**Setting one of these live does nothing** once the term store has anything in it. Use the
`spamguard <category> add` command instead.

| Value | Type | Migrates into |
|---|---|---|
| `plugins.SpamGuard.words` | Space-separated list | `word` |
| `plugins.SpamGuard.phrases` | Comma-separated list | `phrase` |
| `plugins.SpamGuard.patterns` | Comma-separated list | `pattern` |
| `plugins.SpamGuard.identWords` | Space-separated list | `ident` |
| `plugins.SpamGuard.realnameWords` | Space-separated list | `realname_word` |
| `plugins.SpamGuard.realnamePhrases` | Comma-separated list | `realname_phrase` |

## When changes take effect

Every command (`spamguard add/remove`, `spamguardremove`) rebuilds the compiled matchers
immediately — no reload needed. `protection.killSwitch`, `enabled`, `joinWindowSecs`,
`exemptRegistered`, `relayChannel`, `hostBanAutoRebanEnabled`, and `hostBanRetentionDays` are all
read live, per event. Nothing in this plugin requires a full bot restart.

## Files it reads/writes

| File | Purpose |
|---|---|
| `data/spamguard_terms.json` | The id-keyed term store — source of truth for matching. |
| `data/spamguard_host_bans.json` | Persisted host-ban history — auto-reban source of truth. |
| `data/spamguard_actions.jsonl` | Every match seen, acted on or not, with its outcome tag. |
