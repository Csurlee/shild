# Installing shild

## Quick install

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Csurlee/shild/main/install.sh)"
```

This clones the repo, creates a Python virtualenv, installs dependencies
(NOT including torch -- pass `--with-training` if you want to train your
own classifier later), runs an interactive setup wizard, and generates
the Limnoria config. Read `install.sh` before running it, especially if
you're piping it into `bash` directly -- it's short on purpose.

## What the wizard asks

Your bot's nick/ident/realname, which IRC network(s) to join and which
channels, which plugins to enable, and any API keys for the optional
reputation/weather providers. Every question has a sensible default and
every API key is skippable -- skipping just disables that one feature.
See `scripts/install_catalog.py` in the source for the exhaustive list of
what's configurable and why each value is or isn't asked at install time.

## API keys

**No API keys are bundled.** Each provider below is free-tier and you
register your own:

| Key | Used for | Get one at | Required? |
|---|---|---|---|
| `abuseipdb_key` | IP reputation | https://www.abuseipdb.com/register | No -- Shild's DNSBL evidence works without it |
| `scamalytics_username` + `scamalytics_key` | Fraud-score reputation | https://scamalytics.com/ip/api/enquiry | No |
| `openweathermap_key` | Weather plugin | https://openweathermap.org/api | Yes, for `weather`/`w` |
| `openaq_key` | Air quality | https://explore.openaq.org/register | No -- only for `aqi` |
| `github_token` | Private-repo GitHub announcements | https://github.com/settings/tokens | Only for private repos |

`runtime/secrets.json.example` lists all of these with empty values --
copy it to `runtime/secrets.json` and fill in what you want, or just
answer the wizard's prompts (it writes the same file for you).

**shild works with zero API keys**: SpamGuard's content/heuristic
matching and Shild's DNSBL-based evidence gate are both fully functional
without any third-party account.

## Getting the bot opped

Getting real enforcement working needs the bot to hold channel op, which
is manual, per-network infrastructure this installer can't do for you:

- **NickServ networks** (Libera and similar): register the bot's nick
  with NickServ, then grant it ChanServ `op` access on your channel(s).
  Put the NickServ password in `runtime/secrets.json` (or answer the
  wizard's NickServ prompt) -- the bundled `Services` plugin handles
  identifying and requesting op automatically from there.
- **Undernet**: register an X account for the bot, add it to your
  channel's CService access list, and put the credentials in
  `runtime/secrets.json` (or the wizard's Undernet X prompt) --
  `UndernetX` handles login automatically.

Until this is done, Shild/SpamGuard run in shadow mode only (they log
what they *would* do, never a real kick/ban) -- see each plugin's own
`protection.killSwitch`, which additionally defaults ON (safe) even once
the bot does hold op.

## No classifier model ships

Shild's ML classifier needs a trained `.npz` artifact this repo doesn't
include -- a model trained on someone else's server, in someone else's
channels, wouldn't transfer. The evidence gate (DNSBL/reputation lookups)
and SpamGuard both work fully without one. Once your bot has accumulated
real shadow-mode data (`data/shadow_decisions.jsonl`), train your own:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
python -m shildml.train --data data/shadow_decisions.jsonl --model models/shild_v2.npz
python -m shildml.evaluate --model models/shild_v2.npz
```

See `docs/SHILD.md`'s "Working with the classifier" section.

## Starting/stopping

```bash
scripts/botctl.sh start | stop | restart | status
```

Don't use raw `systemctl`/`kill`/`nohup` directly -- `botctl.sh` handles
the case where systemd's view of the process and reality have drifted
(see the script's own header for why).
