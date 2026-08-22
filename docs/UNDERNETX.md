# UndernetX

Logs the bot in to Undernet's X (CService) and, as of 2026-08-14, provides manual X moderation
commands and a per-channel setting to prefer routing through X over raw IRC MODE/KICK. The base
plugin (login, join-holding, `+x` on identify) is vendored verbatim from
`github.com/progval/oddluck-limnoria-plugins`; the credential command, the `x*` commands, and the
reply-correlation machinery are shild-py additions layered on top — see `plugin.py`'s own
"shild-py additions" marker for exactly where the vendored code ends.

Only does anything on Undernet — every command and hook checks `irc.state.supported["NETWORK"] ==
"UnderNet"` (a server-asserted ISUPPORT fact) before acting.

## Status / prerequisites

Inert with blank credentials: `auth.username`/`auth.password` default empty, and every login
attempt (on connect, or via `login`/`xsetpass`) just logs a warning and errors instead of doing
nothing silently (fixed 2026-08-14 — see `login`'s own history below).

**Automatically re-identifies across a `@reload UndernetX`.** A reload recreates the plugin object
from scratch, which used to leave `undernetxstatus` reporting `identified=False` even when the bot
was genuinely still logged in — confirmed live 2026-08-14. `__init__` now re-triggers login
immediately if the connection is already on UnderNet (true only on a mid-session reload; a no-op
at a genuine fresh connect, where `do376` covers it as before). X's own reply to a login attempted
while already authenticated (`"Sorry, You are already authenticated as <account>"`) is recognized
as a success too, not just `"AUTHENTICATION SUCCESSFUL as ..."`.

Credentials come from either:
1. **`runtime/secrets.json`**, loaded at bot startup by `scripts/bootstrap_runtime.py` (keys
   `undernet_x_username`/`undernet_x_password`, or the `SHILD_UNDERNETX_USERNAME`/
   `SHILD_UNDERNETX_PASSWORD` env vars) — survives a regen.
2. **`xsetpass <username> <password>`**, live — takes effect immediately, but only updates the
   registry (masked in `@config` output as of 2026-08-14); without also pasting the printed
   `secrets.json` lines in yourself, a future regen wipes it. See the command's own docstring.

## Commands

All commands below require the **`admin`** capability (matching the plugin's own original `login`
command — not `owner`, this repo's usual bar for moderation-adjacent commands elsewhere).

### `login`

```
takes no arguments
```

Re-attempts login to X using the currently configured credentials. Errors (rather than silently
logging only) if no credentials are configured, or if not on UnderNet.

### `xsetpass <username> <password>`

```
<username> <password>
```

Must be sent in a **private message** — never a channel, same as Services' own `password`
command. Sets `auth.username`/`auth.password` live and immediately re-attempts login if currently
on UnderNet. Never echoes the password back. Prints the `runtime/secrets.json` lines to paste in
yourself so the change survives a `scripts/bootstrap_runtime.py` regen.

```
<owner, in PM> xsetpass myaccount hunter2
<Shild> X credentials updated for this session. To survive a future bootstrap_runtime.py regen,
        also add to runtime/secrets.json: "undernet_x_username": "myaccount",
        "undernet_x_password": "<the password you just set>".
```

### `xban <channel> <host/nick> [duration] [reason]`

```
<channel> <host/nick> [duration] [reason]
```

Bans via X's own `BAN` command instead of a raw IRC `MODE +b` — works even without the bot
holding real channel op, as long as it's identified to X with enough access on `<channel>`.
`[duration]` defaults to `commands.defaultBanDuration` (`0d`, permanent) when omitted; X accepts
`5m` through `365d`. The ban's severity level (X calls it "banlevel") comes from
`commands.defaultBanAccess`, not a command argument — **confirmed live 2026-08-17 via
`/msg X help ban`**: it ranges 1 to the caller's own X access level; 1–74 only blocks `+o`, 75–500
removes the target from the channel entirely (X auto-kicks anyone present who matches). The old
default of `0` is flatly rejected by X — a real incident found every X-routed ban silently failing
outright (only the separate `KICK` was ever removing anyone) until this was caught and the default
raised to `75` (X's own stated default when the level argument is omitted, and the lowest level
that actually works).

### `xunban <channel> <host/nick>`, `xkick <channel> <nick> [reason]`

Straightforward X `UNBAN`/`KICK` passthroughs.

### `xop` / `xdeop` / `xvoice` / `xdevoice <channel> <nick> [nick2 ...]`

Op/deop/voice/devoice one or more nicks via X.

### `xinvite <channel>`

Asks X to invite the bot into `<channel>` — useful for an invite-only, key-protected, or banned
channel.

### `xaccess <channel> <username/=nick/pattern>`

Reports a target's access level in `<channel>`, via X. **A bare target is looked up as an X
username, not a nick** — confirmed live 2026-08-14: `xaccess #kezdi morfeus` correctly returned
that user's access only because `morfeus` also happens to be their X username; `xaccess #kezdi
_-_` returned `No Match!` because `_-_` isn't a registered username. To look up whoever currently
holds a given nick, prefix it with `=` (X's own syntax): `xaccess #kezdi =_-_`.

### `x <raw text>`

Escape hatch — sends `<text>` verbatim to X for anything not wrapped in its own command above
(e.g. `x flags #channel +god csurlee`).

### `xprobe <channel>`

Forces a fresh X-capability check for `<channel>` right now (bypassing the normal opt-in/rate-limit
gating), and reports the raw reply lines plus the resulting verdict. This is the tool for checking
whether a channel *would* be usable for the X-routed enforcement fallback before opting it in — see
"X-routed enforcement fallback" below. Admin-only, same gate as the other `x*` commands.

### `undernetxstatus`

```
takes no arguments
```

Read-only, no capability required. Reports whether the current network is UnderNet, whether the
bot is identified, how many `x*` commands are still awaiting a reply, whether the enforcement
fallback is armed, and a one-line summary of the X-capability cache (2026-08-16) — which channels
have been probed and whether each came back usable or unusable. Never prints a credential.

## How the `x*` commands report their result

Every `x*` command sends its X command immediately and replies **"sent to X: ... -- watching for
a reply"** right away — the actual result (or a timeout) arrives as a **second, separate**
message once X's NOTICE comes back (or `commands.replyTimeoutSecs` elapses). This is unavoidable:
Limnoria can't block a command handler waiting on an async NOTICE without stalling everything else
the bot is doing.

**Reply correlation is best-effort, not exact.** X's NOTICEs carry no request id, so the next
NOTICE from X (on a given network) is assumed to answer the *oldest* still-outstanding `x*`
command on that network — a FIFO queue, not true request/response. Firing two `x*` commands back
to back before either replies can misattribute which reply goes with which command. Fine for
admin-invoked, low-frequency use; not something to rely on under concurrent/scripted use.

## X-routed enforcement fallback (2026-08-16)

Shild's and SpamGuard's own real enforcement only ever fires when the bot holds real IRC op in a
channel. If it doesn't, a correct `ban`/match decision just logs `would ban ...`/`would kban ...`
and nothing happens — even on Undernet, where the bot might have real moderation *access* via X
without ever holding op itself. This feature lets `_maybe_enforce()` (Shild) and the gate chain
(SpamGuard) fall back to routing the kick+ban through X's own `BAN`/`KICK` commands instead, but
**only when a live check has actually confirmed X can do it** — never assumed from configuration
alone.

**Why a live check, not just a config flag**: some channels the bot sits in have no X presence at
all (never registered, or the bot has no access there) — attempting an X ban/kick there would just
silently fail, which is worse than doing nothing, because it looks like enforcement happened. So
before ever routing a real action through X, `plugins/UndernetX/xprobe.py` sends a real
`ACCESS <#channel> =<botnick>` query and classifies the reply: **fails closed by construction** —
`usable` is only produced when a reply line contains the bot's own X username *and* a numeric
access level *and* that level clears `enforcement.minAccessLevel`. Anything else — a negative
reply, someone else's access row, silence, or garbage — resolves `unusable`. The verdict is cached
per `(network, channel)` for `enforcement.probeTtlSecs` (default 1h); a probe fires automatically
on the bot's own join to an opted-in channel, right after a fresh X login, and lazily whenever
enforcement asks about a channel with no fresh cached verdict — the *current* incident always fails
closed either way; only a *later* one can benefit from a probe that just landed.

**Layered gating, every layer independent**: a channel must have `enforcement.preferXCommands=True`
(admin opt-in) **and** the global `enforcement.xFallbackEnabled=True` (master arm switch) **and** a
fresh `usable` cache entry, on top of the calling plugin's own `protection.killSwitch` being off —
`enforce_ban_via_x()` re-checks availability itself, so no caller can bypass the gate by holding a
stale reference. **X is always a fallback, never a substitute**: if the bot holds real op, the
native `MODE +b`/`KICK` path is used regardless of what the X cache says.

**Reply-text classification is UNVERIFIED against a live network as of this writing** — only one
string (`"No Match!"`) has ever been confirmed live (2026-08-14, via `xaccess`). Everything else in
`xprobe.py`'s `NEGATIVE_MARKERS`/`TERMINATOR_MARKERS`/access-row pattern is a best guess from
general X documentation. This is safe specifically *because* the design fails closed: a wrong guess
only ever costs "the feature stays inert on this channel", never a wrongly-attempted action. Do NOT
set `enforcement.xFallbackEnabled=True` anywhere live before running this verification:

1. On a channel the bot is genuinely X-registered/opped on, run `xaccess <#channel> =<botnick>` and
   capture the raw reply. Confirm a line contains the bot's own `auth.username` next to a plain
   integer — if not, `xprobe.py`'s `_ACCESS_LEVEL_RE`/`classify_access_line` need adjusting.
2. Note the real access level shown; lower `enforcement.minAccessLevel` to match reality if needed.
   `commands.defaultBanAccess`'s own caveat is now resolved — confirmed live 2026-08-17 via
   `/msg X help ban`, see that value's own docstring.
3. On a channel with no X presence, run the same query and confirm the reply lands `unusable`
   (either via a matched marker or the fail-closed default) — add the real string to
   `NEGATIVE_MARKERS` either way so future logs show *why*.
4. Arm `xFallbackEnabled`, opt in the one known-X channel, then run `xprobe <channel>` and
   `xprobe <no-X-channel>` by hand and confirm both verdicts match steps 1–3. `undernetxstatus`
   should then show one `usable` and one `unusable` entry.
5. With the relevant plugin's kill switch still ON, provoke a real match and confirm nothing is
   sent to X at all (kill switch is checked before the op/X-fallback check).
6. Kill switch off, deliberately deop the bot on the one X-capable channel, provoke a low-stakes
   real match, and watch the logs for the `BAN`/`KICK` PRIVMSGs to X, any denial-shaped reply
   demoting the cache, and the eventual `UNBAN` once the ban duration elapses.
7. Only then widen `preferXCommands` to other channels — `xprobe` each one first.

**Every kick/ban this produces is still logged exactly like a native one**, with a new `via` field
(`"x"` or `"native"`) in `data/enforcement_actions.jsonl` (Shild) / `data/spamguard_actions.jsonl`
(SpamGuard) so a later review can always tell which path fired.

## Configuration

| Value | Scope | Type | Default | Description |
|---|---|---|---|---|
| `plugins.UndernetX.modeXonID` | global | Boolean | `True` | Whether to `MODE +x` on successful X identify. |
| `plugins.UndernetX.auth.username` | global | String | `""` | X login username. |
| `plugins.UndernetX.auth.password` | global | String, **private** | `""` | X login password — masked in `@config` output (2026-08-14). Set via `xsetpass`, not `@config` directly. |
| `plugins.UndernetX.auth.xservice` | global | String | `X@channels.undernet.org` | Where login/commands are sent. |
| `plugins.UndernetX.auth.xserviceHostmask` | global | String | `X!cservice@undernet.org` | The FULL hostmask X actually authenticates from — used to detect a nick impersonating X. Deliberately more specific than `auth.xservice`. |
| `plugins.UndernetX.auth.noJoinsUntilAuthed` | global | Boolean | `True` | Hold JOINs until identified. **Set `False` in this deployment** (see CLAUDE.md) — blank credentials would otherwise block every Undernet join forever. |
| `plugins.UndernetX.commands.replyTimeoutSecs` | global | Positive integer | `10` | How long an `x*` command waits for X's NOTICE reply before reporting "no reply". |
| `plugins.UndernetX.commands.defaultBanDuration` | global | String | `0d` | Default `xban` duration when omitted. |
| `plugins.UndernetX.commands.defaultBanAccess` | global | Non-negative integer | `75` | Default `xban`/X-fallback ban severity level ("banlevel") when omitted — see `xban`'s own docs above. Confirmed live 2026-08-17; the old default of `0` was flatly rejected by X. |
| `plugins.UndernetX.enforcement.preferXCommands` | **channel** | Boolean | `False` | Per-channel opt-in for the X-routed enforcement fallback. Not op-settable. As of 2026-08-16 this has a real consumer (`x_enforcement_available()`) — see "X-routed enforcement fallback" above for the full gating and the required verification before setting this True live. |
| `plugins.UndernetX.enforcement.xFallbackEnabled` | global | Boolean | `False` | Master arm switch for the whole feature — separate from the per-channel opt-in specifically because the risk (an unverified reply-text classifier) is code-shaped, not per-channel; one flip backs the whole thing out. |
| `plugins.UndernetX.enforcement.minAccessLevel` | global | Non-negative integer | `100` | Minimum X access level the probe must see for the bot's own username before a channel counts as usable. UNVERIFIED against a live reply — see the verification steps above. |
| `plugins.UndernetX.enforcement.probeTtlSecs` | global | Positive integer | `3600` | How long a probe verdict is trusted before being re-checked. |
| `plugins.UndernetX.enforcement.probeMinIntervalSecs` | global | Positive integer | `60` | Floor between probes for the same channel, regardless of how often it's asked about. |

## When changes take effect

Every value above is read live, per event/command — no reload needed for a `@config` change. A
code change to any `plugins/UndernetX/*.py` file needs `@reload UndernetX`.

## Files it reads/writes

None of its own — credentials optionally come from `runtime/secrets.json` (read-only, loaded by
`scripts/bootstrap_runtime.py`); nothing here writes to it. `xsetpass` writes only to the live
Limnoria registry. The X-capability cache (2026-08-16) is in-memory only, per plugin instance —
wiped on every `@reload UndernetX`, same as `self.identified`; nothing persists it to disk.
