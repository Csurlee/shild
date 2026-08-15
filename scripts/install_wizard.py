"""Interactive setup wizard for shild-py -- writes runtime/install.json and
runtime/secrets.json, which scripts/bootstrap_runtime.py then turns into
the actual Limnoria registry file. See scripts/install_catalog.py for the
full list of what this can ask about, and docs/INSTALL.md for the overall
install flow (normally reached via install.sh, not run directly).

Usage:
    cd ~/shild-py && source .venv/bin/activate
    python scripts/install_wizard.py

Re-runnable: an existing runtime/install.json pre-fills every default (and
an existing runtime/secrets.json shows "already set" instead of asking
blind), so running this again is how you RECONFIGURE, not just how you
install the first time.

For scripted/CI use: run_wizard() takes an injectable Prompter (a queue of
canned answers) instead of real stdin -- see tests/test_install_wizard.py.
Nothing in this file talks to the network or imports supybot; it only
produces the two JSON files bootstrap_runtime.py reads.
"""
from __future__ import annotations

import getpass
import json
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
import install_catalog  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_DIR = REPO_ROOT / "runtime"
INSTALL_JSON_PATH = RUNTIME_DIR / "install.json"
SECRETS_PATH = RUNTIME_DIR / "secrets.json"

NETWORK_PRESETS = {
    "libera": {"servers": ["irc.libera.chat:6697"], "ssl": True, "services_type": "nickserv"},
    "undernet": {"servers": ["eu.undernet.org:6667", "us.undernet.org:6667"], "ssl": False,
                 "services_type": "undernet_x"},
}


# --------------------------------------------------------------------------
# Prompter -- the only thing that touches real stdin/stdout. Everything
# else in this file is pure and takes a Prompter as a parameter, so the
# whole flow is testable with a canned answer queue instead of a real TTY.
# --------------------------------------------------------------------------


class Prompter:
    """Wraps a line-reader so the wizard's flow can be driven by either a
    real terminal (default) or a pre-scripted list of answers (tests,
    --non-interactive). `secret_reader` defaults to getpass (never echoes)
    but is also swappable for tests.
    """

    def __init__(
        self,
        reader: Optional[Callable[[str], str]] = None,
        secret_reader: Optional[Callable[[str], str]] = None,
        writer: Optional[Callable[[str], None]] = None,
    ):
        self._reader = reader or input
        self._secret_reader = secret_reader or getpass.getpass
        self._writer = writer or print

    def say(self, text: str = "") -> None:
        self._writer(text)

    def ask_bool(self, question: str, default: bool) -> bool:
        hint = "Y/n" if default else "y/N"
        while True:
            raw = self._reader(f"{question} [{hint}] ").strip().lower()
            if not raw:
                return default
            if raw in ("y", "yes"):
                return True
            if raw in ("n", "no"):
                return False
            self.say("Please answer y or n.")

    def ask_str(self, question: str, default: str = "") -> str:
        suffix = f" [{default}]" if default else ""
        raw = self._reader(f"{question}{suffix}: ").strip()
        return raw or default

    def ask_secret(self, question: str, already_set: bool) -> str:
        """Returns "" to mean "leave whatever's already there unchanged"
        (only meaningful when already_set is True -- on a fresh install
        an empty answer just means "skip this provider")."""
        note = " (already set -- Enter to keep, or type a new value)" if already_set else " (Enter to skip)"
        return self._secret_reader(f"{question}{note}: ").strip()

    def ask_int(self, question: str, default: int) -> int:
        while True:
            raw = self._reader(f"{question} [{default}]: ").strip()
            if not raw:
                return default
            try:
                return int(raw)
            except ValueError:
                self.say("Please enter a whole number.")

    def ask_channels(self, question: str, default: list[str]) -> list[str]:
        suffix = f" [{' '.join(default)}]" if default else ""
        raw = self._reader(f"{question} (space-separated){suffix}: ").strip()
        return raw.split() if raw else list(default)

    def ask_choice(self, question: str, options: list[str], default: str) -> str:
        opts = "/".join(o if o != default else o.upper() for o in options)
        while True:
            raw = self._reader(f"{question} [{opts}]: ").strip().lower()
            if not raw:
                return default
            if raw in options:
                return raw
            self.say(f"Please choose one of: {', '.join(options)}")


# --------------------------------------------------------------------------
# The flow itself
# --------------------------------------------------------------------------


def _load_json(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _ask_network(p: Prompter, existing: Optional[dict] = None) -> dict:
    existing = existing or {}
    name = p.ask_str("Network name (e.g. libera, undernet)", existing.get("name", ""))
    preset = NETWORK_PRESETS.get(name.lower(), {})

    default_servers = existing.get("servers") or preset.get("servers", [])
    servers_str = p.ask_str(
        "Server(s), space-separated host:port", " ".join(default_servers)
    )
    servers = servers_str.split()

    default_ssl = existing.get("ssl", preset.get("ssl", True))
    ssl = p.ask_bool("Use TLS?", default_ssl)

    channels = p.ask_channels("Channels to join", existing.get("channels", []))
    relay_channel = p.ask_str(
        "Back channel for [shadow]/[spamguard] output and announcements "
        "(blank for none)",
        existing.get("relay_channel", channels[0] if channels else ""),
    )

    default_services = existing.get("services", {}).get("type", preset.get("services_type", "none"))
    services_type = p.ask_choice(
        "Services on this network", ["none", "nickserv", "undernet_x"], default_services
    )
    op_channels: list[str] = existing.get("services", {}).get("op_channels", [])
    if services_type == "nickserv":
        op_channels = p.ask_channels(
            "Request ChanServ op in which channels?", op_channels or channels[:1]
        )

    return {
        "name": name,
        "servers": servers,
        "ssl": ssl,
        "channels": channels,
        "relay_channel": relay_channel,
        "services": {"type": services_type, "op_channels": op_channels},
    }


def _ask_network_secrets(p: Prompter, network: dict, secrets: dict) -> None:
    name = network["name"]
    svc = network["services"]["type"]
    if svc == "nickserv":
        key_nick, key_pass = f"{name}_nickserv_nick", f"{name}_nickserv_password"
        nick = p.ask_str(f"NickServ nick to identify as on {name}", secrets.get(key_nick, ""))
        pw = p.ask_secret(f"NickServ password for {name}", already_set=bool(secrets.get(key_pass)))
        if nick:
            secrets[key_nick] = nick
        if pw:
            secrets[key_pass] = pw
    elif svc == "undernet_x":
        user = p.ask_str("Undernet X username", secrets.get("undernet_x_username", ""))
        pw = p.ask_secret("Undernet X password", already_set=bool(secrets.get("undernet_x_password")))
        if user:
            secrets["undernet_x_username"] = user
        if pw:
            secrets["undernet_x_password"] = pw


def _ask_ask_entry(p: Prompter, entry: install_catalog.Ask, secrets: dict) -> object:
    if entry.secret:
        key = entry.path.lstrip("_")
        hint = f" -- register at {entry.url}" if entry.url else ""
        val = p.ask_secret(f"{entry.question}{hint}", already_set=bool(secrets.get(key)))
        if val:
            secrets[key] = val
        return None  # secrets never enter install.json
    if entry.kind == "bool":
        return p.ask_bool(entry.question, bool(entry.default))
    if entry.kind == "int":
        return p.ask_int(entry.question, int(entry.default or 0))
    if entry.kind == "list":
        return p.ask_channels(entry.question, list(entry.default or []))
    return p.ask_str(entry.question, str(entry.default or ""))


def run_wizard(p: Prompter, existing_spec: Optional[dict] = None, existing_secrets: Optional[dict] = None) -> tuple[dict, dict]:
    spec = existing_spec or {}
    secrets = dict(existing_secrets or {})

    p.say("=== shild-py setup ===")
    p.say("Answer at any prompt with the shown default by pressing Enter.\n")

    bot = spec.get("bot", {})
    nick = p.ask_str("Bot nick (<=9 chars for Undernet)", bot.get("nick", "shild"))
    ident = p.ask_str("Ident", bot.get("ident", nick))
    realname = p.ask_str("Realname", bot.get("realname", nick))

    p.say("\n--- Networks ---")
    networks = []
    existing_networks = {n["name"]: n for n in spec.get("networks", [])}
    if existing_networks:
        p.say(f"Existing networks: {', '.join(existing_networks)}")
        keep = p.ask_bool("Keep them as-is (you can still add more)?", True)
        if keep:
            networks.extend(existing_networks.values())
    while True:
        if networks and not p.ask_bool("Add another network?", False):
            break
        if not networks and not p.ask_bool("Add a network now? (at least one is needed)", True):
            break
        networks.append(_ask_network(p))
    for n in networks:
        _ask_network_secrets(p, n, secrets)

    p.say("\n--- Plugins ---")
    plugins: dict = {}
    plugin_defaults = {
        "Shild": True, "SpamGuard": False, "WebPanel": False,
        "GitHubWatch": False, "Weather": True,
        "UndernetX": any(n["services"]["type"] == "undernet_x" for n in networks),
    }
    for plugin_name, default_on in plugin_defaults.items():
        load = p.ask_bool(f"Enable {plugin_name}?", default_on)
        entry: dict = {"load": load}
        if not load:
            plugins[plugin_name] = entry
            continue

        if plugin_name in ("Shild", "SpamGuard"):
            channels: dict = {}
            for n in networks:
                if n["channels"] and p.ask_bool(
                    f"  Analyze/watch traffic on {n['name']}?", plugin_name == "Shild"
                ):
                    channels[n["name"]] = p.ask_channels(
                        f"  Which {n['name']} channels", n["channels"]
                    )
            entry["channels"] = channels

        if plugin_name == "WebPanel":
            entry["bind4"] = [p.ask_str(
                "  Bind address (127.0.0.1 = local only; a LAN IP exposes "
                "it over plain HTTP, no TLS -- see docs/WEBPANEL.md)",
                "127.0.0.1",
            )]
            entry["bind6"] = []
            entry["port"] = p.ask_int("  Port", 8080)
            user = p.ask_str("  WebPanel username", secrets.get("web_panel_user", ""))
            pw = p.ask_secret("  WebPanel password", already_set=bool(secrets.get("web_panel_password_hash")))
            if user:
                secrets["web_panel_user"] = user
            if pw:
                secrets["web_panel_password_hash"] = _hash_webpanel_password(pw)

        for cat_entry in install_catalog.CATALOG.get(plugin_name, []):
            if isinstance(cat_entry, install_catalog.Ask) and cat_entry.tier == "plugin":
                val = _ask_ask_entry(p, cat_entry, secrets)
                if val is not None:
                    _set_dotted(entry, cat_entry.path, val)

        plugins[plugin_name] = entry

    if p.ask_bool("\nConfigure advanced settings?", False):
        p.say("--- Advanced ---")
        advanced = dict(spec.get("advanced", {}))
        for plugin_name, cat_entries in install_catalog.CATALOG.items():
            if not plugins.get(plugin_name, {}).get("load"):
                continue
            for cat_entry in cat_entries:
                if isinstance(cat_entry, install_catalog.Ask) and cat_entry.tier == "advanced":
                    val = _ask_ask_entry(p, cat_entry, secrets)
                    if val is not None:
                        advanced[f"supybot.plugins.{plugin_name}.{cat_entry.path}"] = val
    else:
        advanced = dict(spec.get("advanced", {}))

    new_spec = {
        "schema_version": 1,
        "bot": {"nick": nick, "ident": ident, "realname": realname,
                "quit_msg": bot.get("quit_msg", "brb"), "part_msg": bot.get("part_msg", "brb")},
        "networks": networks,
        "plugins": plugins,
        "channellogger": spec.get("channellogger", {"enable": True, "exclude": {}}),
        "aliases": spec.get("aliases", install_catalog.DEFAULT_ALIASES),
        "advanced": advanced,
    }
    return new_spec, secrets


def _set_dotted(d: dict, path: str, value: object) -> None:
    parts = path.split(".")
    for part in parts[:-1]:
        d = d.setdefault(part, {})
    d[parts[-1]] = value


def _hash_webpanel_password(password: str) -> str:
    sys.path.insert(0, str(REPO_ROOT / "plugins"))
    from WebPanel.auth import hash_password  # noqa: E402  -- pure, no supybot import
    return hash_password(password)


def _create_owner_account(p: Prompter, secrets: dict) -> None:
    if not p.ask_bool("\nCreate the bot owner account now?", True):
        return
    users_conf = RUNTIME_DIR / "conf" / "users.conf"
    users_conf.parent.mkdir(parents=True, exist_ok=True)
    name = p.ask_str("Owner username", "")
    if not name:
        p.say("Skipped -- no username given.")
        return
    pw = p.ask_secret("Owner password", already_set=False)
    if not pw:
        p.say("Skipped -- no password given.")
        return
    result = subprocess.run(
        [sys.executable, "-m", "supybot.scripts.limnoria_adduser",
         "-u", name, "-p", pw, "-c", "owner", str(users_conf)],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        p.say(f"Owner account '{name}' created. Identify with: /msg <botnick> identify {name} <password>")
    else:
        p.say(f"Could not create the owner account automatically: {result.stderr.strip()}")
        p.say(f"You can do it later with: supybot-adduser -u {name} -p <password> -c owner {users_conf}")


def _validate_written_json(path: Path) -> None:
    """runtime/secrets.json has broken with a JSON syntax error on four
    separate occasions in this project's history and fails closed to {}
    SILENTLY (see plugins/Shild/reputation.py's load_secrets) -- this
    wizard must never be a fifth. Re-read and re-parse everything it just
    wrote before declaring success."""
    json.loads(path.read_text())


def main() -> None:
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    existing_spec = _load_json(INSTALL_JSON_PATH)
    existing_secrets = _load_json(SECRETS_PATH)

    p = Prompter()
    spec, secrets = run_wizard(p, existing_spec, existing_secrets)
    _create_owner_account(p, secrets)

    INSTALL_JSON_PATH.write_text(json.dumps(spec, indent=2) + "\n")
    _validate_written_json(INSTALL_JSON_PATH)

    SECRETS_PATH.write_text(json.dumps(secrets, indent=2) + "\n")
    SECRETS_PATH.chmod(0o600)
    _validate_written_json(SECRETS_PATH)

    p.say(f"\nWrote {INSTALL_JSON_PATH} and {SECRETS_PATH}.")
    p.say("Next: python scripts/bootstrap_runtime.py")


if __name__ == "__main__":
    main()
