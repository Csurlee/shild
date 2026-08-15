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
`5m` through `365d`. The ban's access-level exemption comes from `commands.defaultBanAccess`, not
a command argument — X's own documentation of this parameter is thin (see `xcommands.py`'s module
docstring); verify against a live `/msg X help ban` before relying on a non-default value.

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

### `undernetxstatus`

```
takes no arguments
```

Read-only, no capability required. Reports whether the current network is UnderNet, whether the
bot is identified, and how many `x*` commands are still awaiting a reply. Never prints a
credential.

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
| `plugins.UndernetX.commands.defaultBanAccess` | global | Non-negative integer | `0` | Default `xban` access-level exemption when omitted — see `xban`'s own docs above. |
| `plugins.UndernetX.enforcement.preferXCommands` | **channel** | Boolean | `False` | Whether this channel's moderation should prefer X over raw MODE/KICK. Not op-settable. **Inspectable/settable but has no consumer yet as of 2026-08-14** — Shild's and SpamGuard's own enforcement doesn't read it. Exists so a follow-up that wires it in doesn't need to redesign the seam (`UndernetX.prefers_x_commands(irc, channel)`). |

## When changes take effect

Every value above is read live, per event/command — no reload needed for a `@config` change. A
code change to any `plugins/UndernetX/*.py` file needs `@reload UndernetX`.

## Files it reads/writes

None of its own — credentials optionally come from `runtime/secrets.json` (read-only, loaded by
`scripts/bootstrap_runtime.py`); nothing here writes to it. `xsetpass` writes only to the live
Limnoria registry.
