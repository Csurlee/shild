"""Unit tests for plugins/Shild/plugin.py's short-kick-message helpers
(2026-08-11) -- pure functions, but the module imports supybot (unlike
shildml/), so this only works under pytest's real import machinery, not
a bare `python -c` (see CLAUDE.md's __main__.__file__ gotcha).
"""
from shildml.evidence import HostEvidence

from plugins.Shild.plugin import (
    _short_ban_cause,
    _short_ban_score,
    _top_reputation_score,
)


def test_top_reputation_score_picks_highest_of_three():
    ev = HostEvidence(abuseipdb_score=40, scamalytics_score=90, ipqs_fraud_score=60)
    assert _top_reputation_score(ev) == 90


def test_top_reputation_score_none_when_none_ran():
    assert _top_reputation_score(HostEvidence()) is None


def test_top_reputation_score_none_evidence_object():
    assert _top_reputation_score(None) is None


def test_short_ban_cause_proxy_and_fraud_score():
    # The real 2026-08-11 incident this format was built from.
    ev = HostEvidence(geo_proxy=True, scamalytics_score=100)
    assert _short_ban_cause(ev) == "appears to be on a proxy and be fraudulent"


def test_short_ban_cause_dnsbl_hit_takes_priority_over_proxy():
    ev = HostEvidence(geo_proxy=True, scamalytics_score=100, dronebl_type="Botnet IP")
    assert _short_ban_cause(ev) == "appears to be a listed botnet/proxy host"


def test_short_ban_cause_bogon():
    ev = HostEvidence(is_bogon=True)
    assert _short_ban_cause(ev) == "is on an unallocated (bogon) IP range"


def test_short_ban_cause_proxy_alone_no_score():
    ev = HostEvidence(geo_proxy=True)
    assert _short_ban_cause(ev) == "appears to be on a proxy/VPN"


def test_short_ban_cause_open_proxy_port():
    ev = HostEvidence(open_proxy_ports=[8080])
    assert _short_ban_cause(ev) == "has an open proxy port"


def test_short_ban_cause_score_only_no_proxy_flag():
    ev = HostEvidence(abuseipdb_score=95)
    assert _short_ban_cause(ev) == "appears to be fraudulent"


def test_short_ban_cause_no_evidence_object_falls_back():
    assert _short_ban_cause(None) == "matches known abuse patterns"


def test_short_ban_cause_empty_evidence_falls_back():
    assert _short_ban_cause(HostEvidence()) == "matches known abuse patterns"


def test_short_ban_score_prefers_reputation_score_over_confidence():
    ev = HostEvidence(scamalytics_score=100)
    assert _short_ban_score(ev, classifier_confidence=0.57) == 100


def test_short_ban_score_falls_back_to_classifier_confidence():
    assert _short_ban_score(None, classifier_confidence=0.57) == 57
    assert _short_ban_score(HostEvidence(), classifier_confidence=0.734) == 73
