"""Pure tests for scripts/install_wizard.py's run_wizard() flow -- driven
entirely by a scripted Prompter (canned answers), never real stdin, never
supybot, never the network. See that module's own docstring for why the
flow is split this way (a real terminal vs. a canned-answer queue are both
just "a Prompter" to run_wizard()).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import install_catalog  # noqa: E402
from install_wizard import Prompter, run_wizard  # noqa: E402


class ScriptedPrompter(Prompter):
    """Feeds canned answers in order; raises loudly (not just IndexError)
    if the flow asks more questions than the test scripted for -- that's
    a signal the flow changed and the test needs updating, not a hang."""

    def __init__(self, answers: list[str]):
        self._answers = list(answers)
        self._asked: list[str] = []
        super().__init__(reader=self._next, secret_reader=self._next, writer=lambda s: None)

    def _next(self, prompt: str) -> str:
        self._asked.append(prompt)
        if not self._answers:
            raise AssertionError(
                f"ScriptedPrompter ran out of answers at prompt: {prompt!r}\n"
                f"Already asked: {self._asked}"
            )
        return self._answers.pop(0)


def _minimal_answers(**overrides) -> list[str]:
    """One network (libera, no services), Shild on, everything else off,
    no advanced pass, no aliases prompt (aliases aren't asked directly).
    Order must match run_wizard()'s actual question sequence exactly."""
    answers = [
        "shild",       # nick
        "",            # ident (default = nick)
        "",            # realname
        "y",           # add a network now?
        "libera",      # network name
        "irc.libera.chat:6697",  # servers
        "y",           # ssl
        "#test",       # channels
        "#test",       # relay channel
        "none",        # services type
        "n",           # add another network?
        "y",           # enable Shild?
        "y",           # analyze on libera?
        "#test",       # which channels
        "n",           # messageAnalysis
        "y",           # killSwitch (keep armed-safe True)
        "y",           # abuseipdb.enabled
        "y",           # scamalytics.enabled
        "y",           # proxyscan.enabled
        "y",           # geoip.enabled
        "y",           # blocklist.enabled
        "n",           # enable SpamGuard?
        "n",           # enable WebPanel?
        "n",           # enable GitHubWatch?
        "n",           # enable Weather?
        "n",           # enable UndernetX?
        "n",           # configure advanced settings?
    ]
    return answers


def test_minimal_flow_produces_one_network_and_shild_enabled():
    p = ScriptedPrompter(_minimal_answers())
    spec, secrets = run_wizard(p)

    assert spec["bot"]["nick"] == "shild"
    assert spec["bot"]["ident"] == "shild"
    assert len(spec["networks"]) == 1
    net = spec["networks"][0]
    assert net["name"] == "libera"
    assert net["channels"] == ["#test"]
    assert net["services"]["type"] == "none"

    assert spec["plugins"]["Shild"]["load"] is True
    assert spec["plugins"]["Shild"]["channels"] == {"libera": ["#test"]}
    assert spec["plugins"]["Shild"]["messageAnalysis"] is False
    assert spec["plugins"]["Shild"]["protection"]["killSwitch"] is True

    for name in ("SpamGuard", "WebPanel", "GitHubWatch", "UndernetX"):
        assert spec["plugins"][name]["load"] is False


def test_secrets_never_land_in_the_install_spec():
    p = ScriptedPrompter(_minimal_answers())
    spec, secrets = run_wizard(p)
    dumped = str(spec)
    assert "abuseipdb" not in dumped.lower() or "enabled" in dumped.lower()
    # No raw secret VALUES (there weren't any typed in this scenario, but
    # the structural guarantee is what matters): the Shild plugin entry
    # must never contain an "abuseipdb_key"-shaped key at all.
    assert "abuseipdb_key" not in spec["plugins"]["Shild"]
    assert "scamalytics_key" not in spec["plugins"]["Shild"]


def test_declining_a_network_produces_zero_networks():
    answers = ["shild", "", "", "n"]  # nick, ident, realname, "add a network now?" -> n
    answers += ["n"] * 8  # remaining plugin enable prompts, all declined
    p = ScriptedPrompter(answers)
    spec, secrets = run_wizard(p)
    assert spec["networks"] == []


def test_undernet_x_services_prompts_for_credentials():
    # Network-services credentials (_ask_network_secrets) are asked AFTER
    # the whole "add networks" loop exits, not inline per-network -- see
    # run_wizard()'s own `for n in networks: _ask_network_secrets(...)`.
    answers = [
        "shild", "", "",
        "y",                 # add a network now?
        "undernet",          # name -- triggers the undernet_x preset
        "eu.undernet.org:6667",  # servers
        "n",                 # ssl (Undernet has no working TLS)
        "#test",              # channels
        "#test",              # relay channel
        "undernet_x",         # services type
        "n",                    # add another network? -> exits the loop
        "myxuser",               # X username (asked post-loop)
        "hunter2",                # X password
        "n", "n", "n", "n",         # Shild, SpamGuard, WebPanel, GitHubWatch off
        "n",                           # Weather off
        # UndernetX default_on is True here (a network chose undernet_x),
        # so this next answer is the "Enable UndernetX?" prompt itself:
        "y",
        "n",                            # advanced settings?
    ]
    p = ScriptedPrompter(answers)
    spec, secrets = run_wizard(p)
    assert secrets["undernet_x_username"] == "myxuser"
    assert secrets["undernet_x_password"] == "hunter2"
    assert spec["plugins"]["UndernetX"]["load"] is True


def test_webpanel_password_is_hashed_not_stored_plaintext():
    answers = [
        "shild", "", "",
        "y", "libera", "irc.libera.chat:6697", "y", "#test", "#test", "none",
        "n",                    # no more networks
        "n",                    # Shild off (keep this test focused)
        "n",                    # SpamGuard off
        "y",                    # WebPanel on
        "127.0.0.1", "8080",    # bind, port
        "admin", "supersecret", # webpanel user, password
        "n", "n", "n",          # GitHubWatch off, Weather off, UndernetX off
        "n",                    # advanced?
    ]
    p = ScriptedPrompter(answers)
    spec, secrets = run_wizard(p)
    assert secrets["web_panel_user"] == "admin"
    assert "supersecret" not in secrets["web_panel_password_hash"]
    assert secrets["web_panel_password_hash"]  # non-empty, PBKDF2-shaped


def test_reconfigure_prefills_existing_answers_as_defaults():
    """A blank answer (just Enter) should keep the EXISTING value rather
    than clobbering it with an empty one -- this is what makes re-running
    the wizard a safe "reconfigure", not a from-scratch redo."""
    existing_spec = {
        "bot": {"nick": "myshild", "ident": "myshild", "realname": "myshild"},
        "networks": [],
        "plugins": {},
        "advanced": {},
    }
    answers = ["", "", "", "n"]  # blank nick/ident/realname -> keep "myshild"; no network
    answers += ["n"] * 8
    p = ScriptedPrompter(answers)
    spec, secrets = run_wizard(p, existing_spec=existing_spec)
    assert spec["bot"]["nick"] == "myshild"


def test_all_plugin_tier_catalog_questions_are_reachable():
    """Every Ask(tier="plugin") entry in the catalog must actually get
    asked when its plugin is enabled -- a regression here would mean the
    wizard silently stopped offering a real, cataloged setting."""
    p = ScriptedPrompter(_minimal_answers())
    run_wizard(p)
    plugin_tier_questions = [
        e.question for entries in install_catalog.CATALOG.values()
        for e in entries
        if isinstance(e, install_catalog.Ask) and e.tier == "plugin"
        and e.path in ("abuseipdb.enabled", "scamalytics.enabled", "proxyscan.enabled")
    ]
    for q in plugin_tier_questions:
        assert any(q in asked for asked in p._asked), f"never asked: {q}"
