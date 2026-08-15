from shildml.evidence import (
    EvidenceThresholds,
    HostEvidence,
    TRUST_NONE,
    TRUST_REGISTERED,
    TRUST_STRONG,
    classify_cloak,
)
from shildml.fusion import ClassifierResult, Thresholds, decide


# ---- classify_cloak ----

def test_libera_staff_is_strong_trust():
    cloak, tier, tor = classify_cloak("libera/staff/jess")
    assert cloak == "libera/staff/jess"
    assert tier == TRUST_STRONG
    assert not tor


def test_user_cloak_is_registered():
    cloak, tier, tor = classify_cloak("user/alice")
    assert tier == TRUST_REGISTERED
    assert not tor


def test_undernet_x_login_is_registered():
    _, tier, _ = classify_cloak("alice.users.undernet.org")
    assert tier == TRUST_REGISTERED


def test_tor_gateway_is_registered_and_flagged():
    _, tier, tor = classify_cloak("gateway/tor-sasl/alice")
    assert tier == TRUST_REGISTERED
    assert tor


def test_web_gateway_is_untrusted():
    _, tier, _ = classify_cloak("gateway/web/freenode/ip.1.2.3.4")
    assert tier == TRUST_NONE


def test_raw_ip_has_no_cloak():
    cloak, tier, _ = classify_cloak("203.0.113.9")
    assert cloak is None
    assert tier == TRUST_NONE


def test_unrecognized_cloak_namespace_gets_no_trust():
    cloak, tier, _ = classify_cloak("some-other-network/weird/thing")
    assert cloak == "some-other-network/weird/thing"
    assert tier == TRUST_NONE


# ---- HostEvidence verdicts ----

def test_dnsbl_hit_corroborates():
    ev = HostEvidence(resolved_ip="1.2.3.4", dnsbl_hits=["dnsbl.dronebl.org"], checks_run=["dronebl"])
    assert ev.verdict() == "corroborates"


def test_clean_resolved_ip_contradicts():
    ev = HostEvidence(resolved_ip="1.2.3.4", checks_run=["dronebl", "spamcop", "ipapi"])
    assert ev.verdict() == "contradicts"


def test_clean_but_hosting_ip_is_unknown_not_contradicting():
    """A clean-but-datacenter IP must NOT count as evidence of legitimacy
    — that's exactly where drones live."""
    ev = HostEvidence(resolved_ip="1.2.3.4", checks_run=["dronebl"], geo_hosting=True)
    assert ev.verdict() == "unknown"


def test_failed_checks_do_not_contradict():
    ev = HostEvidence(resolved_ip="1.2.3.4", checks_run=["dronebl"], checks_failed=["ipapi"])
    assert ev.verdict() == "unknown"


def test_no_ip_no_cloak_is_unknown():
    ev = HostEvidence()
    assert ev.verdict() == "unknown"


def test_trusted_cloak_contradicts_even_without_ip():
    ev = HostEvidence(cloak="user/alice", trust_tier=TRUST_REGISTERED)
    assert ev.verdict() == "contradicts"


def test_account_present_contradicts():
    ev = HostEvidence(account_present=True)
    assert ev.verdict() == "contradicts"


def test_corroboration_wins_over_trusted_cloak():
    """A registered account whose IP is nonetheless DNSBL-listed is a
    compromised machine — the compromise must win."""
    ev = HostEvidence(
        cloak="user/alice", trust_tier=TRUST_REGISTERED,
        resolved_ip="1.2.3.4", dnsbl_hits=["dnsbl.dronebl.org"],
    )
    assert ev.verdict() == "corroborates"


def test_open_proxy_corroborates():
    ev = HostEvidence(resolved_ip="1.2.3.4", checks_run=["proxyscan"], open_proxy_ports=[1080])
    assert ev.verdict() == "corroborates"


def test_tor_exit_alone_does_not_corroborate():
    """Libera runs an official Tor gateway; Tor status alone must never be
    grounds to ban. (It's also not evidence of innocence on its own here —
    checks_failed keeps this from separately triggering the "fully clean
    host" contradiction rule, isolating just the corroboration check.)"""
    ev = HostEvidence(
        resolved_ip="1.2.3.4", checks_run=["torexit"], checks_failed=["dronebl"],
        is_tor_exit=True,
    )
    assert ev.verdict() != "corroborates"


def test_abuseipdb_over_threshold_corroborates():
    ev = HostEvidence(resolved_ip="1.2.3.4", abuseipdb_score=80)
    assert ev.verdict(EvidenceThresholds(abuseipdb_bad=50)) == "corroborates"


def test_abuseipdb_under_threshold_does_not_corroborate():
    ev = HostEvidence(
        resolved_ip="1.2.3.4", checks_run=["abuseipdb"], checks_failed=["dronebl"],
        abuseipdb_score=10,
    )
    assert ev.verdict(EvidenceThresholds(abuseipdb_bad=50)) != "corroborates"


# ---- hard vs. soft corroboration (added 2026-08-10) ----

def test_geo_proxy_alone_is_not_hard_corroboration():
    """The core fix: geo_proxy (ip-api's proxy/VPN/hosting flag) must not
    count as hard evidence on its own -- it flags a legitimate VPN/VPS
    subscriber identically to a known open relay. corroborates_bad()
    still returns True (unchanged external contract); only
    hard_corroborates_bad() excludes it."""
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True)
    assert ev.corroborates_bad() is True
    assert ev.hard_corroborates_bad() is False


def test_dnsbl_hit_is_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", dnsbl_hits=["rbl.ircbl.org"])
    assert ev.hard_corroborates_bad() is True


def test_dronebl_type_is_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", dronebl_type="Open Wingate Proxy")
    assert ev.hard_corroborates_bad() is True


def test_bogon_is_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", is_bogon=True)
    assert ev.hard_corroborates_bad() is True


def test_open_proxy_port_is_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", open_proxy_ports=[1080])
    assert ev.hard_corroborates_bad() is True


def test_abuseipdb_over_threshold_is_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", abuseipdb_score=80)
    assert ev.hard_corroborates_bad(EvidenceThresholds(abuseipdb_bad=50)) is True


def test_ipqs_over_threshold_is_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", ipqs_fraud_score=90)
    assert ev.hard_corroborates_bad(EvidenceThresholds(ipqs_bad=85)) is True


def test_scamalytics_over_threshold_is_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=80)
    assert ev.hard_corroborates_bad(EvidenceThresholds(scamalytics_bad=75)) is True


def test_scamalytics_under_threshold_is_not_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=10)
    assert ev.hard_corroborates_bad(EvidenceThresholds(scamalytics_bad=75)) is False


def test_scamalytics_blacklisted_is_hard_corroboration_regardless_of_score():
    """is_blacklisted_external is a real external blacklist flag,
    independent of the fraud score -- must count on its own, same as
    dnsbl_hits/is_bogon."""
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=0, scamalytics_blacklisted=True)
    assert ev.hard_corroborates_bad() is True


def test_geo_proxy_plus_a_hard_signal_is_hard_corroboration():
    """The real incident that motivated escalation in the first place
    (idefix's ban, 91.239.206.69) had geo_proxy AND an open proxy port --
    geo_proxy riding alongside real evidence must not weaken it."""
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True, open_proxy_ports=[8080])
    assert ev.hard_corroborates_bad() is True


def test_nothing_at_all_is_not_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4")
    assert ev.hard_corroborates_bad() is False


# ---- the fusion gate itself ----

def test_gate_downgrades_uncorroborated_ban_to_warn():
    ev = HostEvidence()  # no evidence either way
    d = decide(ClassifierResult("ban", 0.9), None, evidence=ev)
    assert d.action == "warn"
    assert d.gate_applied
    assert d.gate_rule == "ban_not_corroborated"


def test_gate_leaves_corroborated_ban_alone():
    ev = HostEvidence(resolved_ip="1.2.3.4", dnsbl_hits=["dnsbl.dronebl.org"])
    d = decide(ClassifierResult("ban", 0.9), None, evidence=ev)
    assert d.action == "ban"
    assert not d.gate_applied


def test_gate_caps_ban_to_warn_when_only_soft_evidence_corroborates():
    """2026-08-10: the "corroborates" branch used to be a pure pass-through
    (raw ban stayed ban). geo_proxy alone is now insufficient for a raw
    ban to survive the gate either, same policy as the escalation path.
    Currently unreachable in production (classifier has never crossed
    thresholds.classifier_act live) but must be correct regardless."""
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True)
    d = decide(ClassifierResult("ban", 0.9), None, evidence=ev)
    assert d.action == "warn"
    assert d.gate_applied
    assert d.gate_rule == "soft_evidence_only"


def test_gate_soft_cap_can_be_disabled_via_threshold():
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True)
    lenient = EvidenceThresholds(require_hard_evidence_for_ban=False)
    d = decide(ClassifierResult("ban", 0.9), None, evidence=ev, evidence_thresholds=lenient)
    assert d.action == "ban"
    assert not d.gate_applied


def test_gate_downgrades_ban_to_allow_when_contradicted():
    ev = HostEvidence(cloak="user/alice", trust_tier=TRUST_REGISTERED)
    d = decide(ClassifierResult("ban", 0.9), None, evidence=ev)
    assert d.action == "allow"
    assert d.gate_rule == "contradicted"


def test_gate_downgrades_warn_to_allow_when_contradicted():
    ev = HostEvidence(account_present=True)
    d = decide(ClassifierResult("warn", 0.9), None, evidence=ev)
    assert d.action == "allow"
    assert d.gate_rule == "contradicted"


def test_gate_never_touches_allow():
    ev = HostEvidence(resolved_ip="1.2.3.4", dnsbl_hits=["x"])
    d = decide(ClassifierResult("allow", 0.9), None, evidence=ev)
    assert d.action == "allow"
    assert not d.gate_applied


def test_gate_never_applied_to_degraded_decisions():
    """A degraded (fail-open) decision is already 'allow' — the gate must
    not touch it or fabricate gate metadata on a non-decision."""
    d = decide(None, None, evidence=HostEvidence(dnsbl_hits=["x"]))
    assert d.action == "allow"
    assert d.degraded
    assert not d.gate_applied


def test_evidence_none_is_fully_backward_compatible():
    """decide() without evidence must reproduce byte-for-byte the same
    result as before this parameter existed -- this is what lets replay.py
    reproduce decisions recorded before Phase 1.5."""
    d = decide(ClassifierResult("ban", 0.9), None)
    assert d.action == "ban"
    assert not d.gate_applied
    assert d.gate_rule == ""


def test_gate_never_escalates_past_an_already_confident_classifier():
    """Property check across every (raw_action, verdict) combination for an
    ALREADY-CONFIDENT classifier (0.9 >= classifier_act): the gated action's
    severity must never exceed the raw action's. This is the downgrade-only
    `_apply_gate` path, unaffected by the 2026-08-09 escalation addition —
    see the `test_escalation_*` tests below for that separate, narrower
    path, which only ever fires on a classifier read that was NOT already
    confident enough to act on its own.
    """
    severity = {"allow": 0, "warn": 1, "ban": 2}
    evidences = [
        HostEvidence(),  # unknown
        HostEvidence(resolved_ip="1.2.3.4", dnsbl_hits=["x"]),  # corroborates
        HostEvidence(account_present=True),  # contradicts
    ]
    for raw_action in ("allow", "warn", "ban"):
        for ev in evidences:
            d = decide(ClassifierResult(raw_action, 0.9), None, evidence=ev)
            assert severity[d.action] <= severity[raw_action]


# ---- the evidence-corroborated escalation path (added 2026-08-09) ----
# Real incident: idefix (a real op) banned 91.239.206.69 on Undernet
# #windrop -- hosting IP, geo_proxy, an open proxy port -- while Shild's
# own classifier read the same join as ban at only 0.60 confidence
# (under classifier_act's 0.85) and, with Ollama disabled, resolved
# straight to a silent allow with the corroborating evidence unused.

# All of these pass ollama_disabled=True, matching the live 2026-08-06
# deploy state (plugins.Shild.ollama.enabled=False) and the exact
# incident scenario: without it, decide_raw's "ollama wasn't consulted"
# branch marks the result `degraded`/`unusable` before evidence is ever
# considered, same as the pre-existing downgrade gate's
# test_gate_never_applied_to_degraded_decisions above -- escalation
# deliberately never touches a degraded decision either.

def test_escalation_promotes_unconfident_ban_when_corroborated():
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_hosting=True, geo_proxy=True,
                       open_proxy_ports=[8080])
    d = decide(ClassifierResult("ban", 0.60), None, evidence=ev, ollama_disabled=True)
    assert d.action == "ban"
    assert d.source == "classifier+evidence"
    assert d.gate_applied
    assert d.gate_rule == "evidence_corroborated_escalation"
    assert not d.degraded
    assert d.label_quality == "ok"


def test_escalation_caps_ban_to_warn_when_only_geo_proxy_corroborates():
    """2026-08-10 fix: this is the exact production pattern found in the
    corpus review (68% of escalations, including a real ProtonVPN ban) --
    classifier says ban, geo_proxy is the only corroborating signal, no
    real DNSBL/proxy-port/abuse-score evidence. Must resolve to warn, not
    ban, even though the classifier's own top pick was ban."""
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True)
    d = decide(ClassifierResult("ban", 0.60), None, evidence=ev, ollama_disabled=True)
    assert d.action == "warn"
    assert d.source == "classifier+evidence"
    assert d.gate_applied
    assert d.gate_rule == "evidence_corroborated_escalation_soft_capped"
    assert not d.degraded
    assert d.label_quality == "ok"


def test_escalation_does_not_cap_a_classifier_warn_pick():
    """A classifier `warn` pick is already the milder tier -- the cap only
    ever applies to `ban`, never touches `warn`."""
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True)
    d = decide(ClassifierResult("warn", 0.60), None, evidence=ev, ollama_disabled=True)
    assert d.action == "warn"
    assert d.gate_rule == "evidence_corroborated_escalation"


def test_escalation_soft_cap_can_be_disabled_via_threshold():
    """require_hard_evidence_for_ban=False reverts to the pre-2026-08-10
    behavior -- a documented safety valve, not the default."""
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True)
    lenient = EvidenceThresholds(require_hard_evidence_for_ban=False)
    d = decide(ClassifierResult("ban", 0.60), None, evidence=ev, ollama_disabled=True,
                evidence_thresholds=lenient)
    assert d.action == "ban"
    assert d.gate_rule == "evidence_corroborated_escalation"


def test_escalation_promotes_unconfident_warn_when_corroborated():
    ev = HostEvidence(resolved_ip="1.2.3.4", dnsbl_hits=["dnsbl.dronebl.org"])
    d = decide(ClassifierResult("warn", 0.60), None, evidence=ev, ollama_disabled=True)
    assert d.action == "warn"
    assert d.gate_applied
    assert d.gate_rule == "evidence_corroborated_escalation"


def test_escalation_does_not_fire_below_the_lower_threshold():
    ev = HostEvidence(resolved_ip="1.2.3.4", dnsbl_hits=["x"])  # corroborates
    d = decide(ClassifierResult("ban", 0.50), None, evidence=ev, ollama_disabled=True,
                thresholds=Thresholds(classifier_act_with_evidence=0.55))
    assert d.action == "allow"
    assert not d.gate_applied


def test_escalation_does_not_fire_without_corroborating_evidence():
    """A merely-unknown verdict (nothing corroborates, nothing contradicts)
    must not be enough to escalate — only hard, independent evidence can."""
    ev = HostEvidence()  # unknown: no IP, no cloak, nothing gathered
    d = decide(ClassifierResult("ban", 0.60), None, evidence=ev, ollama_disabled=True)
    assert d.action == "allow"
    assert not d.gate_applied


def test_escalation_does_not_fire_when_classifier_itself_says_allow():
    """Evidence alone, however bad, must never manufacture a ban/warn the
    classifier didn't itself already lean toward — see the module
    docstring's "neither signal escalates alone" rule."""
    ev = HostEvidence(resolved_ip="1.2.3.4", dnsbl_hits=["x"], open_proxy_ports=[1080])
    d = decide(ClassifierResult("allow", 0.99), None, evidence=ev, ollama_disabled=True)
    assert d.action == "allow"
    assert not d.gate_applied


def test_escalation_does_not_fire_when_evidence_is_none():
    d = decide(ClassifierResult("ban", 0.60), None, evidence=None, ollama_disabled=True)
    assert d.action == "allow"
    assert not d.gate_applied


def test_escalation_never_touches_a_degraded_decision():
    """Regression guard for the bug this test file caught during review:
    without ollama_disabled=True (e.g. Ollama enabled but never actually
    consulted, an unexpected code path), the raw decision is `degraded`
    and escalation must not override that — same convention as the
    downgrade gate."""
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True)
    d = decide(ClassifierResult("ban", 0.60), None, evidence=ev)  # ollama_disabled defaults False
    assert d.action == "allow"
    assert d.degraded
    assert not d.gate_applied


def test_escalation_respects_configured_threshold():
    """A caller-tuned classifier_act_with_evidence is honored, both when it
    excludes and when it admits a given confidence."""
    ev = HostEvidence(resolved_ip="1.2.3.4", dnsbl_hits=["x"])
    strict = Thresholds(classifier_act_with_evidence=0.99)
    d = decide(ClassifierResult("ban", 0.60), None, evidence=ev, ollama_disabled=True,
                thresholds=strict)
    assert d.action == "allow"

    lenient = Thresholds(classifier_act_with_evidence=0.10)
    d = decide(ClassifierResult("ban", 0.60), None, evidence=ev, ollama_disabled=True,
                thresholds=lenient)
    assert d.action == "ban"


# ---- blocklist_hits / FireHOL (2026-08-15) ----

def test_blocklist_hit_corroborates():
    ev = HostEvidence(resolved_ip="1.2.3.4", blocklist_hits=["socks_proxy_30d"])
    assert ev.verdict() == "corroborates"


def test_blocklist_hit_is_hard_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", blocklist_hits=["cybercrime"])
    assert ev.hard_corroborates_bad()


def test_blocklist_hit_alone_is_not_extreme_corroboration():
    """One hard signal alone (blocklist hit, no score) is real corroboration
    but not enough on its own to skip the classifier's own ranking — same
    treatment as a lone DroneBL hit."""
    ev = HostEvidence(resolved_ip="1.2.3.4", blocklist_hits=["cybercrime"])
    assert not ev.extreme_corroborates_bad()


def test_blocklist_hit_plus_another_hard_signal_is_extreme_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", blocklist_hits=["cybercrime"],
                       scamalytics_blacklisted=True)
    assert ev.extreme_corroborates_bad()


def test_blocklist_hits_round_trip_through_to_dict_from_dict():
    ev = HostEvidence(resolved_ip="1.2.3.4", blocklist_hits=["socks_proxy_30d", "cybercrime"])
    rebuilt = HostEvidence.from_dict(ev.to_dict())
    assert rebuilt.blocklist_hits == ["socks_proxy_30d", "cybercrime"]
    assert rebuilt.hard_corroborates_bad()


# ---- extreme_corroborates_bad (2026-08-14) ----

def test_extreme_scamalytics_score_is_extreme_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=82)  # real batis610 value
    assert ev.extreme_corroborates_bad()


def test_scamalytics_at_hard_but_not_extreme_is_not_extreme_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=76)  # over hard (75), under extreme (80)
    assert ev.hard_corroborates_bad()
    assert not ev.extreme_corroborates_bad()


def test_extreme_abuseipdb_score_is_extreme_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", abuseipdb_score=90)
    assert ev.extreme_corroborates_bad()


def test_extreme_ipqs_score_is_extreme_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", ipqs_fraud_score=95)
    assert ev.extreme_corroborates_bad()


def test_two_independent_hard_signals_is_extreme_corroboration_even_without_a_high_score():
    ev = HostEvidence(resolved_ip="1.2.3.4", dronebl_type="Spam Drone",
                       scamalytics_blacklisted=True)
    assert ev.extreme_corroborates_bad()


def test_single_moderate_hard_signal_alone_is_not_extreme_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", dronebl_type="Spam Drone")
    assert ev.hard_corroborates_bad()
    assert not ev.extreme_corroborates_bad()


def test_geo_proxy_never_counts_toward_extreme_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True, scamalytics_score=76)
    assert not ev.extreme_corroborates_bad()


def test_nothing_at_all_is_not_extreme_corroboration():
    ev = HostEvidence(resolved_ip="1.2.3.4")
    assert not ev.extreme_corroborates_bad()


# ---- secondary ban escalation sub-rules (2026-08-14) ----
#
# Both use real corpus examples from 2026-08-14: Spike77777/fietanre/tanami_
# (ban as the classifier's 2nd choice, hard evidence) for the secondary-rank
# rule, and batis610 (Scamalytics 82/100, ban ranked BELOW allow) for the
# extreme-evidence override.

def test_secondary_rank_floor_promotes_warn_to_ban():
    """Spike77777: classifier top pick warn (54%), ban 2nd choice (39%,
    ahead of allow's 7%), corroborated by a hard signal (open proxy
    port)."""
    ev = HostEvidence(resolved_ip="1.2.3.4", open_proxy_ports=[8080])
    clf = ClassifierResult("warn", 0.542, probs=[0.070, 0.542, 0.388])
    d = decide(clf, None, evidence=ev, ollama_disabled=True)
    assert d.action == "ban"
    assert d.source == "classifier+evidence"
    assert d.gate_rule == "evidence_corroborated_escalation_secondary_ban"
    assert not d.degraded
    assert d.label_quality == "ok"


def test_secondary_rank_floor_does_not_fire_with_only_soft_evidence():
    """Same probs as above, but geo_proxy is the only corroborating
    signal -- the secondary rule requires HARD evidence, same bar as the
    original ban cap."""
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True)
    clf = ClassifierResult("warn", 0.542, probs=[0.070, 0.542, 0.388])
    d = decide(clf, None, evidence=ev, ollama_disabled=True)
    assert d.action == "warn"
    assert d.gate_rule == "evidence_corroborated_escalation"


def test_secondary_rank_floor_does_not_fire_below_the_floor():
    ev = HostEvidence(resolved_ip="1.2.3.4", open_proxy_ports=[8080])
    clf = ClassifierResult("warn", 0.60, probs=[0.30, 0.60, 0.10])  # ban only 10%
    d = decide(clf, None, evidence=ev, ollama_disabled=True)
    assert d.action == "warn"
    assert d.gate_rule == "evidence_corroborated_escalation"


def test_secondary_rank_floor_does_not_fire_when_ban_ranked_below_allow():
    """batis610-shaped probs (allow beats ban) must not satisfy the
    secondary-rank rule even though ban technically clears the floor in
    isolation -- rank matters, not just magnitude. (It may still qualify
    for the separate extreme-evidence rule -- see below.)"""
    ev = HostEvidence(resolved_ip="1.2.3.4", open_proxy_ports=[8080])
    clf = ClassifierResult("warn", 0.55, probs=[0.40, 0.55, 0.05])
    d = decide(clf, None, evidence=ev, ollama_disabled=True)
    assert d.action == "warn"
    assert d.gate_rule == "evidence_corroborated_escalation"


def test_extreme_evidence_override_promotes_warn_to_ban_despite_low_ban_rank():
    """batis610: classifier top pick warn (55%), ban ranked BELOW allow
    (12% vs 33%) -- the secondary-rank rule can't reach this at all, but
    Scamalytics 82/100 clears the extreme bar on its own."""
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=82)
    clf = ClassifierResult("warn", 0.551, probs=[0.333, 0.551, 0.116])
    d = decide(clf, None, evidence=ev, ollama_disabled=True)
    assert d.action == "ban"
    assert d.gate_rule == "evidence_corroborated_escalation_extreme_evidence"
    assert not d.degraded
    assert d.label_quality == "ok"


def test_extreme_evidence_override_does_not_fire_at_merely_hard_evidence():
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=76)  # hard, not extreme
    clf = ClassifierResult("warn", 0.551, probs=[0.333, 0.551, 0.116])
    d = decide(clf, None, evidence=ev, ollama_disabled=True)
    assert d.action == "warn"
    assert d.gate_rule == "evidence_corroborated_escalation"


def test_secondary_escalation_can_be_disabled_via_threshold():
    """enable_secondary_ban_escalation=False reverts both new sub-rules --
    a documented safety valve, not the default."""
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=82)
    clf = ClassifierResult("warn", 0.551, probs=[0.333, 0.551, 0.116])
    lenient = EvidenceThresholds(enable_secondary_ban_escalation=False)
    d = decide(clf, None, evidence=ev, ollama_disabled=True, evidence_thresholds=lenient)
    assert d.action == "warn"
    assert d.gate_rule == "evidence_corroborated_escalation"


def test_secondary_escalation_never_fires_without_probs():
    """A ClassifierResult with no probs recorded (probs=[], the
    dataclass default) must not crash and must not attempt either new
    sub-rule -- only the original top-pick escalation applies."""
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=82)
    clf = ClassifierResult("warn", 0.60)  # probs defaults to []
    d = decide(clf, None, evidence=ev, ollama_disabled=True)
    assert d.action == "warn"
    assert d.gate_rule == "evidence_corroborated_escalation"


def test_secondary_escalation_never_touches_an_already_soft_capped_ban():
    """A raw classifier BAN pick that got soft-capped to warn (geo_proxy
    only) must not then be re-escalated to ban by the secondary rules --
    those require hard/extreme evidence, which soft-capped-by-definition
    doesn't have."""
    ev = HostEvidence(resolved_ip="1.2.3.4", geo_proxy=True)
    clf = ClassifierResult("ban", 0.60, probs=[0.10, 0.20, 0.70])
    d = decide(clf, None, evidence=ev, ollama_disabled=True)
    assert d.action == "warn"
    assert d.gate_rule == "evidence_corroborated_escalation_soft_capped"


def test_secondary_rank_floor_respects_configured_floor():
    ev = HostEvidence(resolved_ip="1.2.3.4", open_proxy_ports=[8080])
    clf = ClassifierResult("warn", 0.60, probs=[0.05, 0.60, 0.35])

    strict = Thresholds(classifier_ban_secondary_floor=0.99)
    d = decide(clf, None, evidence=ev, ollama_disabled=True, thresholds=strict)
    assert d.action == "warn"

    lenient = Thresholds(classifier_ban_secondary_floor=0.01)
    d = decide(clf, None, evidence=ev, ollama_disabled=True, thresholds=lenient)
    assert d.action == "ban"


def test_scamalytics_fields_round_trip_through_to_dict_and_from_dict():
    ev = HostEvidence(resolved_ip="1.2.3.4", scamalytics_score=67, scamalytics_blacklisted=True)
    rebuilt = HostEvidence.from_dict(ev.to_dict())
    assert rebuilt.scamalytics_score == 67
    assert rebuilt.scamalytics_blacklisted is True
