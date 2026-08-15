"""Generator for runtime/shildpy.conf -- reads runtime/install.json (produced
by scripts/install_wizard.py, or hand-written) and writes the Limnoria
registry file from it.

This replaces supybot-wizard (fully interactive, no non-interactive/scripted
mode) with a direct call to the same registry APIs the wizard itself uses
(conf.registerNetwork, registry.close), so the resulting .conf file is in
exactly the format Limnoria expects.

Usage:
    cd ~/shild-py && source .venv/bin/activate
    python scripts/install_wizard.py     # first time, or to change settings
    python scripts/bootstrap_runtime.py

Safe to re-run: it only WRITES runtime/shildpy.conf; it does not touch
runtime/data or runtime/logs. Re-running regenerates the conf from scratch
(does not merge with a hand-edited copy) -- if you've hand-edited
runtime/shildpy.conf, back it up first. ALWAYS STOP THE BOT before
regenerating -- Limnoria writes its live in-memory config back to this same
file on shutdown, which silently clobbers a fresh regen if the old process
is still running when it exits.

--- 2026-08-15: genericized ---
Until this date this file hardcoded one specific deployment (nick, both
networks, every channel list, the LAN bind IP) as ~230 lines of module-level
constants -- fine for a single-operator box, unusable as the basis for a
public installer. All deployment-specific values now live in
runtime/install.json (gitignored, one per install) instead; this script is
the same mechanical "spec -> registry -> file" generator for ANY install.
See docs/INSTALL.md and CLAUDE.md's "Public release" section for the full
two-repo (private dev / public release) story this enabled.

Values that are NOT deployment-specific -- universal hardening and
correctness fixes this project discovered the hard way (version-disclosure
quit/part messages, self-registration disabled, SSL cert verification,
the Undernet noJoinsUntilAuthed trap, the runtime/runtime/ path-doubling
bug, `list` reconnaissance hardening) -- stay hardcoded below rather than
becoming install.json knobs: they are correct for every deployment, and
exposing them as questions would just be more chances to pick the unsafe
answer. See each block's own comment for the specific incident that
justifies it; the incident history itself lives in CLAUDE.md, not repeated
here.
"""
from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Optional

RUNTIME_DIR = Path(__file__).resolve().parent.parent / "runtime"
CONF_PATH = RUNTIME_DIR / "shildpy.conf"
SECRETS_PATH = RUNTIME_DIR / "secrets.json"
INSTALL_JSON_PATH = RUNTIME_DIR / "install.json"

# DEFAULT_ALIASES lives in install_catalog.py -- the single source of
# truth, shared with install_wizard.py. Both scripts live in this same
# directory, so a plain import works without any sys.path change (Python
# already puts a directly-run script's own directory on sys.path[0]).
import install_catalog  # noqa: E402
from install_catalog import DEFAULT_ALIASES  # noqa: E402


def _load_secrets_file() -> dict:
    if SECRETS_PATH.exists():
        try:
            return json.loads(SECRETS_PATH.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _load_nickserv_secrets(network: str, default_nick: str) -> tuple[str, str]:
    """<network>_nickserv_nick/<network>_nickserv_password in
    runtime/secrets.json, env vars take precedence. The historical
    `libera_nickserv_*` names (from when this script only ever supported
    one NickServ network) are accepted as an alias for network=="libera",
    so an existing secrets.json needs no edit after this genericization.
    Returns ("", "") if no password is configured -- same as before.
    """
    data = _load_secrets_file()
    env_prefix = f"SHILD_{network.upper()}_NICKSERV"
    key_prefix = f"{network}_nickserv"
    nick = os.environ.get(f"{env_prefix}_NICK") or data.get(f"{key_prefix}_nick")
    password = os.environ.get(f"{env_prefix}_PASSWORD") or data.get(f"{key_prefix}_password")
    if network == "libera" and not password:
        # Legacy key names, pre-genericization -- see docstring above.
        nick = nick or os.environ.get("SHILD_LIBERA_NICKSERV_NICK") or data.get("libera_nickserv_nick")
        password = os.environ.get("SHILD_LIBERA_NICKSERV_PASSWORD") or data.get("libera_nickserv_password")
    return (nick or default_nick), (password or "")


def _load_undernetx_secrets() -> tuple[str, str]:
    """undernet_x_username/undernet_x_password in runtime/secrets.json,
    env vars take precedence. UndernetX is a single global plugin (one X
    login regardless of how many networks are configured), so this stays
    un-networked, unlike NickServ above. Returns ("", "") if unconfigured.
    """
    data = _load_secrets_file()
    username = os.environ.get("SHILD_UNDERNETX_USERNAME") or data.get("undernet_x_username") or ""
    password = os.environ.get("SHILD_UNDERNETX_PASSWORD") or data.get("undernet_x_password") or ""
    return username, password


def _webpanel_credentials_present() -> bool:
    """WebPanel's web_panel_user/web_panel_password_hash, UNLIKE every
    other secret this script loads, never enter the registry at all --
    plugins/WebPanel/secrets.py reads runtime/secrets.json directly at
    request time, specifically so an admin's `@config` dump can never
    leak them (see that module's docstring). This function exists only
    to WARN here if they're missing, because plugins/WebPanel/auth.py's
    fail-closed design means a missing credential doesn't error loudly
    at startup -- it just makes the panel 503 every request, silently.
    """
    data = _load_secrets_file()
    user = os.environ.get("SHILD_WEBPANEL_USER") or data.get("web_panel_user") or ""
    password_hash = (
        os.environ.get("SHILD_WEBPANEL_PASSWORD_HASH")
        or data.get("web_panel_password_hash")
        or ""
    )
    return bool(user and password_hash)


# --------------------------------------------------------------------------
# InstallSpec -- typed view over runtime/install.json. Deliberately loose
# (plain dicts with .get(..., default)) rather than a strict schema
# validator: a missing key should degrade to a sane default, not crash a
# regen, matching every other loader's fail-open convention in this repo.
# --------------------------------------------------------------------------


@dataclasses.dataclass
class NetworkSpec:
    name: str
    servers: list[str]
    ssl: bool
    channels: list[str]
    relay_channel: str
    services_type: str  # "nickserv" | "undernet_x" | "none"
    op_channels: list[str]


@dataclasses.dataclass
class InstallSpec:
    nick: str
    ident: str
    realname: str
    quit_msg: str
    part_msg: str
    networks: list[NetworkSpec]
    plugins: dict
    channellogger_enable: bool
    channellogger_exclude: dict
    aliases: dict
    advanced: dict


def load_install_spec(path: Path = INSTALL_JSON_PATH) -> InstallSpec:
    if not path.exists():
        raise SystemExit(
            f"{path} not found. Run `python scripts/install_wizard.py` first "
            "to generate it (or write one by hand -- see docs/INSTALL.md for "
            "the schema)."
        )
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        raise SystemExit(f"{path} is not valid JSON: {e}") from e

    bot = raw.get("bot", {})
    nick = bot.get("nick", "shild")
    networks = []
    for n in raw.get("networks", []):
        svc = n.get("services", {})
        networks.append(NetworkSpec(
            name=n["name"],
            servers=n.get("servers", []),
            ssl=bool(n.get("ssl", True)),
            channels=n.get("channels", []),
            relay_channel=n.get("relay_channel", ""),
            services_type=svc.get("type", "none"),
            op_channels=svc.get("op_channels", []),
        ))
    return InstallSpec(
        nick=nick,
        ident=bot.get("ident", nick),
        realname=bot.get("realname", nick),
        quit_msg=bot.get("quit_msg", "brb"),
        part_msg=bot.get("part_msg", "brb"),
        networks=networks,
        plugins=raw.get("plugins", {}),
        channellogger_enable=bool(raw.get("channellogger", {}).get("enable", True)),
        channellogger_exclude=raw.get("channellogger", {}).get("exclude", {}),
        aliases=raw.get("aliases", DEFAULT_ALIASES),
        advanced=raw.get("advanced", {}),
    )


def _plugin(spec: InstallSpec, name: str) -> dict:
    return spec.plugins.get(name, {})


_MISSING = object()


def _get_dotted(d: dict, path: str):
    node = d
    for part in path.split("."):
        if not isinstance(node, dict) or part not in node:
            return _MISSING
        node = node[part]
    return node


def _apply_catalog_values(conf, plugin_name: str, entry: dict) -> None:
    """Generic counterpart to install_wizard.py's `_set_dotted`: for every
    non-secret Ask(tier="plugin") entry in install_catalog.py, if
    install.json's plugin entry has a value at that same dotted path,
    apply it to the registry. This is what makes the wizard's catalog-
    driven writer and this script's reader share one schema instead of
    two hand-maintained, easily-divergent ones (a real mismatch here --
    messageAnalysis/protection.killSwitch vs. message_analysis/
    kill_switch -- was caught by tests/test_install_wizard.py before ever
    reaching a real install). Structural values (channels, relay_channel,
    load, bind4/port, repos, seed_words) are NOT in the catalog as
    plugin-tier Ask entries and are handled by main()'s own per-plugin
    code instead, same as before.
    """
    for cat_entry in install_catalog.CATALOG.get(plugin_name, []):
        if not isinstance(cat_entry, install_catalog.Ask) or cat_entry.secret:
            continue
        if cat_entry.tier not in ("plugin", "advanced"):
            continue
        val = _get_dotted(entry, cat_entry.path)
        if val is _MISSING:
            continue
        node = conf.supybot.plugins.get(plugin_name)
        for part in cat_entry.path.split("."):
            node = node.get(part)
        node.setValue(val)


def main() -> None:
    spec = load_install_spec()

    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    for sub in ("conf", "logs", "data", "backup"):
        (RUNTIME_DIR / sub).mkdir(exist_ok=True)

    # supybot.directories.* must be set before other registry values are
    # touched, and Limnoria resolves relative directory paths against the
    # process's cwd at import time -- so this script must be run with
    # cwd == ~/shild-py (see docstring usage). Rather than rely on that,
    # we set absolute paths explicitly.
    os.chdir(RUNTIME_DIR)

    import sys

    sys.path.insert(0, str(RUNTIME_DIR.parent / "plugins"))

    import supybot.conf as conf
    import supybot.registry as registry
    import supybot.plugins.Owner.config  # noqa: F401 -- registers conf.supybot.plugins.Owner.*
    import supybot.plugins.Anonymous.config  # noqa: F401 -- registers conf.supybot.plugins.Anonymous.*
    # ^ genuine bugfix found while genericizing (2026-08-15): the pre-existing
    # script set Anonymous.requireCapability/allowPrivateTarget below WITHOUT
    # ever importing Anonymous.config first, and crashed with
    # NonExistentRegistryEntry every time it was actually run after Anonymous
    # was added (2026-08-09) -- confirmed by re-running the exact prior
    # version verbatim. The live conf's correct values were set via a live
    # @config some time after, never by a successful regen. Added here so a
    # regen actually completes and reproduces the live values itself.
    import Shild.config  # noqa: F401 -- registers conf.supybot.plugins.Shild.*
    import UndernetX.config  # noqa: F401 -- registers conf.supybot.plugins.UndernetX.*
    import GitHubWatch.config  # noqa: F401 -- registers conf.supybot.plugins.GitHubWatch.*
    import ChannelStats.config  # noqa: F401 -- registers conf.supybot.plugins.ChannelStats.*
    import SpamGuard.config  # noqa: F401 -- registers conf.supybot.plugins.SpamGuard.*
    import WebPanel.config  # noqa: F401 -- registers conf.supybot.plugins.WebPanel.*
    import Weather.config  # noqa: F401 -- registers conf.supybot.plugins.Weather.*
    import supybot.plugins.Services.config  # noqa: F401 -- registers conf.supybot.plugins.Services.*
    import supybot.plugins.ChannelLogger.config  # noqa: F401 -- registers conf.supybot.plugins.ChannelLogger.*
    import supybot.plugins.Channel.config  # noqa: F401 -- registers conf.supybot.plugins.Channel.* (partMsg)
    import supybot.plugins.Alias.config  # noqa: F401 -- registers conf.supybot.plugins.Alias.*

    conf.supybot.directories.data.setValue(str(RUNTIME_DIR / "data"))
    conf.supybot.directories.conf.setValue(str(RUNTIME_DIR / "conf"))
    conf.supybot.directories.log.setValue(str(RUNTIME_DIR / "logs"))
    conf.supybot.directories.backup.setValue(str(RUNTIME_DIR / "backup"))
    conf.supybot.directories.plugins.setValue(
        [str(RUNTIME_DIR.parent / "plugins")]
    )

    conf.supybot.nick.setValue(spec.nick)
    conf.supybot.ident.setValue(spec.ident)
    conf.supybot.user.setValue(spec.realname)

    # Only load what shild-py actually needs. Owner/Admin/Config/User/Misc
    # are Limnoria's own built-ins needed for basic operation (e.g.
    # @config, @list) -- Shild is the one plugin doing actual work here.
    # conf.registerPlugin(name, True) is what actually flips a plugin's
    # load switch on (supybot.plugins.<Name>) -- it's what each plugin's
    # own configure() calls when the wizard runs it interactively.
    for plugin_name in ("Owner", "Admin", "Config", "User", "Misc"):
        conf.registerPlugin(plugin_name, True)

    # Default "Limnoria $version" quit/part messages disclose the exact
    # Limnoria version to anyone watching the channel/server -- a real
    # PART on this project's own dev box leaked this before it was fixed
    # (see CLAUDE.md). Must come after Owner is registered above --
    # supybot.plugins.Owner.* doesn't exist as a registry entry until then.
    conf.supybot.plugins.Owner.quitMsg.setValue(spec.quit_msg)
    conf.supybot.plugins.Channel.partMsg.setValue(spec.part_msg)

    # User self-registration disabled: User.plugin.py's `register` command
    # has no capability check at all -- anyone who can PM the bot could
    # create an ircdb account for themselves. @disable blocks it for
    # everyone including the owner, which is fine since the owner account
    # is created separately by install_wizard.py before this ever runs.
    # identify/hostmask/unregister are untouched.
    conf.supybot.commands.disabled.setValue(["User.register"])

    # Channel: bundled, unmodified. Hosts `part` (not in Admin, unlike
    # `join`) plus other channel-moderation commands (kick, mode, topic,
    # lobotomize, ...). Each command is still individually capability-gated
    # (channel op or 'admin') the same as vanilla Limnoria.
    conf.registerPlugin("Channel", True)

    # Anonymous: bundled, unmodified. Lets an authorized user have the bot
    # `say`/`tell`/`do` on their behalf. Its own docstring warns this is
    # easily abused ("if anyone could send private messages as the bot,
    # they could also access network services"), so both knobs it
    # explicitly recommends are set here rather than left at the
    # wide-open upstream defaults.
    conf.registerPlugin("Anonymous", True)
    conf.supybot.plugins.Anonymous.requireCapability.setValue("owner")
    conf.supybot.plugins.Anonymous.allowPrivateTarget.setValue(True)
    conf.supybot.plugins.get("Anonymous").public.setValue(False)

    conf.registerPlugin("Shild", True)

    # Status: bundled with Limnoria, unmodified. Read-only bot/process
    # stats (!status, !uptime, !cpu, !net, !threads, !commands, ...).
    conf.registerPlugin("Status", True)

    conf.registerPlugin("Services", True)   # bundled; NickServ/ChanServ
    conf.registerPlugin("UndernetX", True)  # vendored; plugins/UndernetX/
    conf.registerPlugin("GitHubWatch", True)

    # ChannelStats: bundled Limnoria plugin, vendored into plugins/ and
    # patched to key its stats DB by (network, channel) instead of just
    # channel -- vanilla ChannelStats would otherwise pool two same-named
    # channels on different networks together. Also adds `topstats`.
    conf.registerPlugin("ChannelStats", True)

    spamguard = _plugin(spec, "SpamGuard")
    if spamguard.get("load", True):
        conf.registerPlugin("SpamGuard", True)
        # First-deployment-only seed -- see plugins/SpamGuard/terms.py.
        # After the first start against an empty term store, this is a
        # no-op forever; manage terms live via `spamguard <cat> add/remove`.
        conf.supybot.plugins.SpamGuard.words.setValue(spamguard.get("seed_words", []))
        _apply_catalog_values(conf, "SpamGuard", spamguard)
        for network, channels in spamguard.get("channels", {}).items():
            for channel in channels:
                conf.supybot.plugins.SpamGuard.enabled.get(
                    ":" + network).get(channel).setValue(True)
        for n in spec.networks:
            chan = spamguard.get("relay_channel", {}).get(n.name, n.relay_channel)
            if chan:
                conf.supybot.plugins.SpamGuard.relayChannel.get(":" + n.name).setValue(chan)

    conf.registerPlugin("Alias", True)
    for name, command in spec.aliases.items():
        # A bare conf.registerGroup() child (aliases here) does NOT
        # auto-create entries on .get() the way a registerChannelValue's
        # per-channel override does -- each name needs its own explicit
        # registerGlobalValue first, exactly like Alias.plugin.py's own
        # addAlias() does it, or .get() raises NonExistentRegistryEntry.
        conf.registerGlobalValue(conf.supybot.plugins.Alias.aliases, name,
                                  registry.String(command, ""))
        conf.registerGlobalValue(conf.supybot.plugins.Alias.aliases.get(name),
                                  "locked", registry.Boolean(False, ""))
        conf.supybot.plugins.Alias.aliases.get(name).setValue(command)
        conf.supybot.plugins.Alias.aliases.get(name).locked.setValue(False)

    weather = _plugin(spec, "Weather")
    if weather.get("load", True):
        conf.registerPlugin("Weather", True)
        for network, place in weather.get("default_location", {}).items():
            conf.supybot.plugins.Weather.defaultLocation.get(":" + network).setValue(place)
        _apply_catalog_values(conf, "Weather", weather)

    # ChannelLogger: bundled, unmodified. Plain per-channel text logs, one
    # file per day (rotateLogs=True -- upstream default is False, which
    # would grow one file forever). Default-enabled globally so any
    # channel the bot joins gets logged automatically, including one added
    # later via a live @config channel-list change -- an explicit opt-in
    # list would otherwise miss it until this script is next re-run.
    conf.registerPlugin("ChannelLogger", True)
    cl = conf.supybot.plugins.ChannelLogger
    cl.rotateLogs.setValue(True)
    cl.filenameTimestamp.setValue("%Y-%m-%d")
    cl.enable.setValue(spec.channellogger_enable)
    for network, channels in spec.channellogger_exclude.items():
        for channel in channels:
            cl.enable.get(":" + network).get(channel).setValue(False)

    webpanel = _plugin(spec, "WebPanel")
    if webpanel.get("load", True):
        bind4 = webpanel.get("bind4", ["127.0.0.1"])
        bind6 = webpanel.get("bind6", [])
        port = webpanel.get("port", 8080)
        # Derived, never asked directly -- this is the entire DNS-rebinding
        # defense (see plugins/WebPanel/config.py's allowedHosts docstring)
        # and it must always exactly match bind4:port or every request 400s.
        allowed_hosts = sorted(set(
            [f"{h}:{port}" for h in bind4] + [f"127.0.0.1:{port}", f"localhost:{port}"]
        ))
        conf.registerPlugin("WebPanel", True)
        conf.supybot.plugins.get("WebPanel").public.setValue(False)
        conf.supybot.plugins.WebPanel.allowedHosts.setValue(allowed_hosts)
        conf.supybot.plugins.WebPanel.enable.setValue(True)
        # supybot.servers.http itself: Limnoria's own default is
        # 0.0.0.0/::0/8080 (bind everything). hosts6 empty is a real safety
        # property, not just "no IPv6 needed" -- httpserver.py binds one
        # server thread per address, and hooking the same callback into two
        # threads creates a real race on shared per-request state (see
        # plugins/WebPanel/http.py's module docstring). One bound address
        # means one thread, and the race can't happen at all.
        conf.supybot.servers.http.hosts4.setValue(bind4)
        conf.supybot.servers.http.hosts6.setValue(bind6)
        conf.supybot.servers.http.port.setValue(port)
        conf.supybot.servers.http.publicUrl.setValue("")  # never a public URL

    for n in spec.networks:
        net = conf.registerNetwork(n.name)
        net.servers.setValue(n.servers)
        net.channels.setValue(set(n.channels))
        net.ssl.setValue(n.ssl)
        if n.ssl:
            conf.supybot.protocols.ssl.verifyCertificates.setValue(True)

    # All configured networks run in ONE Limnoria process. They share a
    # single worker queue for anything expensive (Ollama, if ever
    # re-enabled) -- separate processes would only compete for the same
    # backend. All plugin state is already keyed by (network, channel).
    conf.supybot.networks.setValue([n.name for n in spec.networks])

    shild = _plugin(spec, "Shild")
    if shild.get("load", True):
        for network, channels in shild.get("channels", {}).items():
            for channel in channels:
                conf.supybot.plugins.Shild.enabled.get(
                    ":" + network).get(channel).setValue(True)
        _apply_catalog_values(conf, "Shild", shild)
        for n in spec.networks:
            chan = shild.get("relay_channel", {}).get(n.name, n.relay_channel)
            if chan:
                conf.supybot.plugins.Shild.relayChannel.get(":" + n.name).setValue(chan)
        conf.supybot.plugins.Shild.classifier.modelPath.setValue(
            str(RUNTIME_DIR.parent / "models" / "shild_v2.npz")
        )
        conf.supybot.plugins.Shild.shadowDataPath.setValue(
            str(RUNTIME_DIR.parent / "data" / "shadow_decisions.jsonl")
        )
        conf.supybot.plugins.Shild.report.dir.setValue(
            str(RUNTIME_DIR / "daily_analysis")
        )

    githubwatch = _plugin(spec, "GitHubWatch")
    if githubwatch.get("load", False):
        conf.supybot.plugins.GitHubWatch.repos.setValue(githubwatch.get("repos", []))
        for n in spec.networks:
            chan = githubwatch.get("channel", {}).get(n.name, n.relay_channel)
            if chan:
                conf.supybot.plugins.GitHubWatch.channel.get(":" + n.name).setValue(chan)

    # Per-network services (NickServ/ChanServ via bundled Services, or
    # X via UndernetX). Blank credentials are always safe: UndernetX's
    # do376 handler checks for a username+password before attempting
    # login and just logs a warning otherwise; Services' password command
    # equivalent below is simply skipped when no password is configured.
    for n in spec.networks:
        if n.services_type == "nickserv":
            nick, password = _load_nickserv_secrets(n.name, spec.nick)
            if password:
                conf.supybot.plugins.Services.nicks.get(":" + n.name).setValue([nick])
                supybot.plugins.Services.config.registerNick(nick, password)
            for channel in n.op_channels:
                conf.supybot.plugins.Services.ChanServ.op.get(channel).setValue(True)
        elif n.services_type == "undernet_x":
            username, password = _load_undernetx_secrets()
            if username:
                conf.supybot.plugins.UndernetX.auth.username.setValue(username)
            if password:
                conf.supybot.plugins.UndernetX.auth.password.setValue(password)
            # Upstream default True would silently block EVERY join on
            # this network forever while credentials are blank (since
            # self.identified can never become True without them) --
            # overridden so join coverage is unaffected either way.
            conf.supybot.plugins.UndernetX.auth.noJoinsUntilAuthed.setValue(False)

    # Arbitrary escape hatch: any registry dotted-path this script's own
    # schema doesn't cover. Applied last so it can override anything set
    # above. install_wizard.py's "advanced" section writes into this.
    for path, value in spec.advanced.items():
        node = conf.supybot
        for part in path.split(".")[1:]:  # skip leading "supybot"
            node = node.get(part) if hasattr(node, "get") else getattr(node, part)
        node.setValue(value)

    registry.close(conf.supybot, str(CONF_PATH))
    print(f"Wrote {CONF_PATH}")
    print(f"Start with: cd {RUNTIME_DIR} && supybot shildpy.conf")
    if webpanel.get("load", True) and not _webpanel_credentials_present():
        print(
            "WARNING: web_panel_user/web_panel_password_hash not set in "
            f"{SECRETS_PATH} -- WebPanel will refuse every request (503) "
            "until both are added. Generate a hash with: "
            "python plugins/WebPanel/auth.py (run directly, not via -m -- "
            "see that file's run_hash_cli() docstring for why)"
        )


if __name__ == "__main__":
    main()
