"""Unit tests for the small pure helper(s) in plugins/WebPanel/http.py.
http.py is otherwise supybot-glue and mainly covered by
plugins/WebPanel/test.py's HTTP integration tests, but `_clamp_int` is a
plain function worth pinning directly -- it's also where a real bug was
caught during development (see the "lower must never exceed upper" case
below): if an admin configures logTailLines below the request-side
floor, the floor must not silently push the effective ceiling back up
past what the admin configured.
"""
from plugins.WebPanel.http import _clamp_int


def test_clamp_int_none_returns_default():
    assert _clamp_int(None, default=300, lower=50, upper=300) == 300


def test_clamp_int_non_numeric_returns_default():
    assert _clamp_int("not-a-number", default=300, lower=50, upper=300) == 300


def test_clamp_int_within_range_passes_through():
    assert _clamp_int("100", default=300, lower=50, upper=300) == 100


def test_clamp_int_above_upper_is_clamped():
    assert _clamp_int("99999", default=300, lower=50, upper=300) == 300


def test_clamp_int_below_lower_is_clamped():
    assert _clamp_int("1", default=300, lower=50, upper=300) == 50


def test_clamp_int_negative_is_clamped_to_lower():
    assert _clamp_int("-5", default=300, lower=50, upper=300) == 50


def test_clamp_int_lower_never_exceeds_a_smaller_upper():
    # The regression this test pins: if the caller passes lower > upper
    # (e.g. an admin-configured ceiling below the usual request floor),
    # the result must respect upper, not silently exceed it.
    assert _clamp_int("999", default=2, lower=2, upper=2) == 2
    assert _clamp_int(None, default=2, lower=2, upper=2) == 2
