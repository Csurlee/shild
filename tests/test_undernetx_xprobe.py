"""Pure unit tests for plugins/UndernetX/xprobe.py -- no supybot import.

Every NEGATIVE_MARKERS/positive-row test doubles as a fail-closed
assertion: the module's whole design is that USABLE can only ever come
from a recognized, specific positive match -- anything else, including
something that merely isn't recognized as negative, must land UNUSABLE.
"""
from plugins.UndernetX.xprobe import (
    UNKNOWN,
    USABLE,
    UNUSABLE,
    NEGATIVE_MARKERS,
    XCapabilityCache,
    classify_access_line,
    classify_access_reply,
    is_terminator,
    looks_like_denial,
)


# ---- looks_like_denial / is_terminator ----

def test_looks_like_denial_confirmed_live_string():
    # The one marker actually confirmed against a real X reply
    # (2026-08-14, xaccess on a nick with no matching X username).
    assert looks_like_denial("No Match!") is True


def test_looks_like_denial_confirmed_live_unregistered_channel_string():
    # Real, exact X reply captured live 2026-08-16 for "xaccess #windrop
    # =shild" on an Undernet channel genuinely not registered with X.
    assert looks_like_denial("The channel #windrop doesn't appear to be registered") is True


def test_classify_line_confirmed_live_positive_reply_shape():
    # Real, exact X reply captured live 2026-08-16 for "xaccess #erdely
    # =shild" -- confirms the username-then-plain-integer pattern with
    # zero code changes needed.
    v = classify_access_line("USER: ExampleAccount ACCESS: 100 L",
                              username="ExampleAccount", min_access=100)
    assert v.state == USABLE
    assert v.access_level == 100


def test_looks_like_denial_case_insensitive_and_embedded():
    assert looks_like_denial("Error: channel is not registered with X.") is True


def test_looks_like_denial_false_for_unrelated_text():
    assert looks_like_denial("Hello, this is X.") is False


def test_every_negative_marker_triggers_denial():
    for marker in NEGATIVE_MARKERS:
        assert looks_like_denial(f"prefix {marker} suffix") is True, marker


def test_is_terminator_positive_and_negative():
    assert is_terminator("End of access list.") is True
    assert is_terminator("End of ACCESS.") is True
    assert is_terminator("csurlee (csurlee) has access 500 in #windrop.") is False


# ---- classify_access_line ----

def test_classify_line_denial():
    v = classify_access_line("No Match!", username="shild", min_access=100)
    assert v.state == UNUSABLE
    assert v.matched_marker == "No Match!"


def test_classify_line_positive_access_row():
    v = classify_access_line("shild (shild) has access 500 in #windrop.",
                              username="shild", min_access=100)
    assert v.state == USABLE
    assert v.access_level == 500


def test_classify_line_access_below_minimum_is_unusable():
    v = classify_access_line("shild (shild) has access 10 in #windrop.",
                              username="shild", min_access=100)
    assert v.state == UNUSABLE
    assert v.access_level == 10


def test_classify_line_access_exactly_at_minimum_is_usable():
    v = classify_access_line("shild (shild) has access 100 in #windrop.",
                              username="shild", min_access=100)
    assert v.state == USABLE


def test_classify_line_someone_elses_access_never_authorizes_us():
    # A row for a DIFFERENT username, even at a very high level, must
    # never be read as our own access.
    v = classify_access_line("someoneelse (someoneelse) has access 500 in #windrop.",
                              username="shild", min_access=100)
    assert v.state == UNKNOWN


def test_classify_line_empty_string():
    v = classify_access_line("", username="shild", min_access=100)
    assert v.state == UNKNOWN


def test_classify_line_gibberish_is_unknown_not_positive():
    v = classify_access_line("asdkjhaskjdh 12345 zxczxc", username="shild", min_access=100)
    # A bare number near garbage text without our username adjacent
    # must not resolve positive.
    assert v.state != USABLE


def test_classify_line_no_username_configured_never_matches_positive():
    v = classify_access_line("shild (shild) has access 500 in #windrop.",
                              username="", min_access=100)
    assert v.state != USABLE


# ---- classify_access_reply (the fail-closed floor) ----

def test_reply_positive_row_wins():
    lines = [
        "-- #windrop access list --",
        "shild (shild) has access 500 in #windrop.",
        "End of access list.",
    ]
    v = classify_access_reply(lines, username="shild", min_access=100)
    assert v.state == USABLE
    assert v.access_level == 500


def test_reply_negative_marker_wins():
    lines = ["No Match!"]
    v = classify_access_reply(lines, username="shild", min_access=100)
    assert v.state == UNUSABLE


def test_reply_empty_collection_is_unusable():
    v = classify_access_reply([], username="shild", min_access=100)
    assert v.state == UNUSABLE


def test_reply_header_and_terminator_only_no_data_row_is_unusable():
    lines = ["-- #windrop access list --", "End of access list."]
    v = classify_access_reply(lines, username="shild", min_access=100)
    assert v.state == UNUSABLE


def test_reply_total_gibberish_is_unusable():
    lines = ["zzz qqq 999999999999", "??? ???"]
    v = classify_access_reply(lines, username="shild", min_access=100)
    assert v.state == UNUSABLE


def test_reply_someone_elses_row_only_is_unusable():
    lines = ["otheruser (othernick) has access 500 in #windrop.", "End of access list."]
    v = classify_access_reply(lines, username="shild", min_access=100)
    assert v.state == UNUSABLE


# ---- XCapabilityCache ----

def test_is_usable_false_for_missing_entry():
    c = XCapabilityCache()
    assert c.is_usable("undernet", "#windrop", ttl=3600, now=0.0) is False


def test_is_usable_true_for_fresh_usable_entry():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(USABLE, 500), ["line"], now=0.0)
    assert c.is_usable("undernet", "#windrop", ttl=3600, now=100.0) is True


def test_is_usable_false_once_ttl_elapses():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(USABLE, 500), ["line"], now=0.0)
    assert c.is_usable("undernet", "#windrop", ttl=3600, now=3601.0) is False


def test_is_usable_false_for_unusable_entry():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(UNUSABLE), ["No Match!"], now=0.0)
    assert c.is_usable("undernet", "#windrop", ttl=3600, now=0.0) is False


def test_is_usable_false_while_in_flight():
    c = XCapabilityCache()
    c.mark_in_flight("undernet", "#windrop", now=0.0)
    assert c.is_usable("undernet", "#windrop", ttl=3600, now=0.0) is False


def test_should_probe_true_for_never_checked_channel():
    c = XCapabilityCache()
    assert c.should_probe("undernet", "#windrop", ttl=3600, min_interval=60, now=0.0) is True


def test_should_probe_false_while_in_flight():
    c = XCapabilityCache()
    c.mark_in_flight("undernet", "#windrop", now=0.0)
    assert c.should_probe("undernet", "#windrop", ttl=3600, min_interval=60, now=1.0) is False


def test_should_probe_false_within_min_interval_after_a_result():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(UNUSABLE), [], now=0.0)
    assert c.should_probe("undernet", "#windrop", ttl=3600, min_interval=60, now=30.0) is False


def test_should_probe_true_after_min_interval_even_if_unusable():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(UNUSABLE), [], now=0.0)
    assert c.should_probe("undernet", "#windrop", ttl=3600, min_interval=60, now=61.0) is True


def test_should_probe_false_for_fresh_usable_entry():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(USABLE, 500), [], now=0.0)
    assert c.should_probe("undernet", "#windrop", ttl=3600, min_interval=60, now=100.0) is False


def test_should_probe_true_once_usable_entry_expires():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(USABLE, 500), [], now=0.0)
    assert c.should_probe("undernet", "#windrop", ttl=3600, min_interval=60, now=3601.0) is True


def test_invalidate_demotes_a_usable_entry():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(USABLE, 500), [], now=0.0)
    c.invalidate("undernet", "#windrop")
    assert c.is_usable("undernet", "#windrop", ttl=3600, now=0.0) is False
    assert c.get("undernet", "#windrop").state == UNUSABLE


def test_invalidate_is_a_noop_for_a_missing_entry():
    c = XCapabilityCache()
    c.invalidate("undernet", "#nowhere")  # must not raise
    assert c.get("undernet", "#nowhere") is None


def test_clear_all_networks():
    c = XCapabilityCache()
    c.record("undernet", "#a", _verdict(USABLE, 500), [], now=0.0)
    c.record("libera", "#b", _verdict(USABLE, 500), [], now=0.0)
    c.clear()
    assert c.get("undernet", "#a") is None
    assert c.get("libera", "#b") is None


def test_clear_scoped_to_one_network():
    c = XCapabilityCache()
    c.record("undernet", "#a", _verdict(USABLE, 500), [], now=0.0)
    c.record("libera", "#b", _verdict(USABLE, 500), [], now=0.0)
    c.clear("undernet")
    assert c.get("undernet", "#a") is None
    assert c.get("libera", "#b") is not None


def test_two_networks_with_the_same_channel_name_are_independent():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(USABLE, 500), [], now=0.0)
    c.record("libera", "#windrop", _verdict(UNUSABLE), [], now=0.0)
    assert c.is_usable("undernet", "#windrop", ttl=3600, now=0.0) is True
    assert c.is_usable("libera", "#windrop", ttl=3600, now=0.0) is False


def test_snapshot_reflects_recorded_entries():
    c = XCapabilityCache()
    c.record("undernet", "#windrop", _verdict(USABLE, 500), ["line"], now=0.0)
    snap = c.snapshot()
    assert len(snap) == 1
    net, chan, entry = snap[0]
    assert (net, chan) == ("undernet", "#windrop")
    assert entry.state == USABLE
    assert entry.access_level == 500


def _verdict(state, access_level=None):
    from plugins.UndernetX.xprobe import ProbeVerdict
    return ProbeVerdict(state=state, access_level=access_level)
