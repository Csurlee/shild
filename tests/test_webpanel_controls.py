"""Pure unit tests for plugins/WebPanel/controls.py -- no supybot
import, no plugin test harness needed. Registry nodes are faked with a
minimal object matching just the shape controls.py actually touches
(`._children`, `._wasSet`, `__call__`, `.setValue`, `.get`) -- not a real
supybot.registry.Value, since the whole point of controls.py is to work
against that shape without depending on supybot at all.
"""
from plugins.WebPanel.controls import (
    CHANNEL_TOGGLES,
    GLOBAL_SWITCHES,
    channel_nodes_ready,
    channel_toggle_by_key,
    flash_for,
    global_switch_by_key,
    parse_bool,
    peek_channel_value,
    warm_channel_nodes,
    write_channel_value,
)


class FakeNode:
    """Mimics just enough of registry.Value's shape for these tests:
    calling it returns the current value; `.get(key)` creates (and
    caches) a child seeded with THIS node's own current value, unset --
    same "inherits from parent until explicitly set" semantics the real
    registry.Value._makeChild has."""

    def __init__(self, value=False):
        self.value = value
        self._wasSet = False
        self._children: dict = {}

    def __call__(self):
        return self.value

    def setValue(self, v):
        self.value = v
        self._wasSet = True

    def get(self, key):
        if key not in self._children:
            self._children[key] = FakeNode(value=self.value)
        return self._children[key]


# --- parse_bool -----------------------------------------------------------

def test_parse_bool_true_spellings():
    for s in ("1", "true", "True", "TRUE", "yes", "Yes", "on", "On"):
        assert parse_bool(s) is True


def test_parse_bool_false_spellings():
    for s in ("0", "false", "False", "no", "No", "off", "Off"):
        assert parse_bool(s) is False


def test_parse_bool_rejects_toggle():
    # Regression: registry.Boolean.set("toggle") would flip whatever the
    # CURRENT value is -- a real footgun for a form that might be
    # re-submitted or replayed. parse_bool must never accept it.
    assert parse_bool("toggle") is None


def test_parse_bool_rejects_garbage_and_empty():
    assert parse_bool("maybe") is None
    assert parse_bool("") is None
    assert parse_bool(None) is None
    assert parse_bool("  ") is None


# --- allowlist pinning ------------------------------------------------------

def test_global_switches_has_exactly_three_entries():
    assert len(GLOBAL_SWITCHES) == 3


def test_global_switches_keys_are_unique():
    keys = [s.key for s in GLOBAL_SWITCHES]
    assert len(keys) == len(set(keys))


def test_global_switches_polarity_is_exactly_expected():
    # The load-bearing regression test for the polarity design decision:
    # both killSwitches are True=safe, the X-fallback switch is
    # True=armed. If this table ever gets edited carelessly, this must
    # fail loudly rather than silently mislabel a switch in the UI.
    polarities = [s.true_means_armed for s in GLOBAL_SWITCHES]
    assert polarities == [False, False, True]


def test_global_switch_by_key_resolves_and_misses_cleanly():
    assert global_switch_by_key("shild_kill_switch") is not None
    assert global_switch_by_key("not-a-real-key") is None


def test_channel_toggles_has_exactly_thirteen_entries():
    assert len(CHANNEL_TOGGLES) == 13


def test_channel_toggles_keys_are_unique():
    keys = [t.key for t in CHANNEL_TOGGLES]
    assert len(keys) == len(set(keys))


def test_channel_toggles_includes_quit_part():
    # Regression: shildconfig's own read set was found missing
    # quitPartEnabled during this same change -- pin it here too so the
    # web surface can't silently drift the same way.
    assert channel_toggle_by_key("spamguard_quit_part") is not None


def test_channel_toggle_by_key_misses_cleanly():
    assert channel_toggle_by_key("not-a-real-key") is None


# --- peek_channel_value: the four registry.getSpecific() precedence cases ---

def test_peek_nothing_set_anywhere_returns_top_value():
    node = FakeNode(value=True)
    assert peek_channel_value(node, "libera", "#windrop") is True


def test_peek_legacy_bare_channel_fallback():
    node = FakeNode(value=False)
    node.get("#windrop").setValue(True)  # only the bare-channel node set
    assert peek_channel_value(node, "libera", "#windrop") is True


def test_peek_network_qualified_wins_over_bare_channel():
    node = FakeNode(value=False)
    node.get("#windrop").setValue(True)               # legacy bare value: True
    node.get(":libera").setValue(False)                # network-level value: False
    # network_value._wasSet -> case 1/2 wins over the legacy channel fallback
    assert peek_channel_value(node, "libera", "#windrop") is False


def test_peek_network_channel_qualified_is_most_specific():
    node = FakeNode(value=False)
    node.get("#windrop").setValue(False)
    node.get(":libera").setValue(False)
    node.get(":libera").get("#windrop").setValue(True)
    assert peek_channel_value(node, "libera", "#windrop") is True


def test_peek_never_creates_a_node():
    node = FakeNode(value=False)
    assert peek_channel_value(node, "libera", "#windrop") is False
    assert ":libera" not in node._children
    assert "#windrop" not in node._children


# --- channel_nodes_ready / warm_channel_nodes / write_channel_value ---------

def test_write_refused_when_unwarmed():
    node = FakeNode(value=False)
    assert channel_nodes_ready(node, "libera", "#windrop") is False
    assert write_channel_value(node, "libera", "#windrop", True) is False
    # And nothing was created as a side effect of the failed attempt.
    assert ":libera" not in node._children


def test_write_succeeds_after_warming_and_writes_both_nodes():
    node = FakeNode(value=False)
    warm_channel_nodes(node, "libera", "#windrop")
    assert channel_nodes_ready(node, "libera", "#windrop") is True
    assert write_channel_value(node, "libera", "#windrop", True) is True
    assert node._children["#windrop"]() is True
    assert node._children[":libera"]._children["#windrop"]() is True


def test_write_does_not_shadow_a_channel_it_does_not_touch():
    node = FakeNode(value=False)
    warm_channel_nodes(node, "libera", "#windrop")
    warm_channel_nodes(node, "libera", "#other")
    write_channel_value(node, "libera", "#windrop", True)
    assert peek_channel_value(node, "libera", "#other") is False


# --- flash_for --------------------------------------------------------------

def test_flash_for_known_code():
    result = flash_for("killswitch_set")
    assert result == ("ok", "Kill switch updated.")


def test_flash_for_unknown_code_is_none():
    assert flash_for("not-a-real-code") is None


def test_flash_for_none_code_is_none():
    assert flash_for(None) is None


def test_flash_for_substitutes_and_caps_arg_length():
    level, message = flash_for("ignore_added", "203.0.113.5")
    assert level == "ok"
    assert "203.0.113.5" in message

    long_arg = "x" * 500
    level, message = flash_for("ignore_added", long_arg)
    assert len(message) < 200  # capped, not a 500-char reflection
