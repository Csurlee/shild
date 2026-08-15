"""Unit tests for plugins/Shild/plugin.py's IRC-display-only formatting
helpers (_irc_compact_reason, _irc_colorize_action) -- the abbreviation/
color logic added so a verbose evidence summary reads shorter on IRC
without touching fused.reason/evidence.summary() themselves (those stay
verbatim in shadow_decisions.jsonl and any future Ollama prompt).
"""
import supybot.ircutils as ircutils

from plugins.Shild.plugin import _irc_colorize_action, _irc_compact_reason


def test_compact_reason_abbreviates_known_phrases():
    reason = (
        "classifier ban (61%) capped to warn -- only soft evidence (geo_proxy) "
        "corroborates, no hard signal: IP 212.56.52.124 | network: GTT "
        "Communications Inc. AS3257 GTT Communications Inc. | country: CA | "
        "flagged as proxy/VPN | AbuseIPDB abuse confidence: 11/100 | "
        "Scamalytics fraud score: 62/100 | proxy port scan: clean | "
        "clean on all blocklists checked"
    )
    compact = _irc_compact_reason(reason)
    assert " -- only " not in compact
    assert "capped to warn - soft evidence" in compact
    assert "AbuseIPDB: 11/100" in compact
    assert "Scamalytics: 62/100" in compact
    assert "Flag: proxy/VPN" in compact
    assert "Country: CA" in compact
    assert "proxy scan: clean" in compact
    assert "clean on all blocklists" in compact
    assert "checked" not in compact
    # Untouched: not one of the abbreviated phrases.
    assert "network: GTT Communications Inc. AS3257 GTT Communications Inc." in compact


def test_compact_reason_leaves_unrelated_text_untouched():
    reason = "cloak example/username/someone (registered services account) -- no IP checks performed"
    assert _irc_compact_reason(reason) == reason


def test_colorize_action_ban_is_bold_and_red():
    colored = _irc_colorize_action("ban")
    assert colored == ircutils.bold(ircutils.mircColor("BAN", "red"))


def test_colorize_action_warn_is_green_not_bold():
    colored = _irc_colorize_action("warn")
    assert colored == ircutils.mircColor("WARN", "green")
    assert "\x02" not in colored  # no bold control character


def test_colorize_action_allow_is_green_not_bold():
    colored = _irc_colorize_action("allow")
    assert colored == ircutils.mircColor("ALLOW", "green")
