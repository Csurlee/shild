"""Host evidence — the facts we can gather about *where a user is
connecting from*, and the pure rules that turn those facts into a verdict
on whether an action is justified.

Why this exists: before this module, a decision was made almost entirely
from string shape — nick entropy, ident, hostname patterns. A legitimate
user with an unusual nick is indistinguishable from a drone under that
regime, which is exactly how false positives get manufactured. Evidence
adds ground facts (DNSBL listings, IP reputation, proxy status, cloak
trust) so a decision can be checked against reality.

The gate built on this (see fusion.decide) mostly *softens* a decision:
evidence that's missing or contradicts a ban/warn downgrades it toward
allow, and that direction needs no help from the classifier to fire.
Since 2026-08-09, evidence gathered here can also do the opposite in one
narrow case (fusion._apply_escalation): when the classifier's own top
action already agrees (ban/warn, above a lower confidence bar) AND
independent evidence corroborates it — e.g. an IP that's DNSBL-listed,
geo-flagged as proxy/hosting, or has an open proxy port. Neither signal
escalates alone; an evidence source that could escalate on its own would
turn every DNSBL false positive into a new false positive of our own,
which is exactly what this module's `corroborates_bad()` (hard,
independent signals only, never a mere absence of contradiction) is
designed to resist.

**Hard vs. soft evidence (2026-08-10).** A corpus check of every
evidence-corroborated escalation found 68% had `geo_proxy` as the ONLY
corroborating signal — including a real ban of a ProtonVPN connection.
`geo_proxy` (ip-api.com's proxy/VPN/hosting flag) is infrastructure
classification, not evidence of abuse: it flags a legitimate VPN
subscriber or someone's own VPS identically to a known open relay.
`corroborates_bad()` still treats it as sufficient (its contract is
unchanged — see below), but `hard_corroborates_bad()` excludes it, and
fusion.py now requires the *hard* set specifically before a `ban` (never
a `warn`) is allowed to stand — `geo_proxy` alone caps the action at
`warn`. This is what actually fixes the "bans everyone with a VPN/VPS"
failure mode, not just adding more signals to the corroborating set.

**Secondary ban escalation (2026-08-14).** Even with the hard/soft split
above, `_apply_escalation` (fusion.py) originally only ever promoted a
decision to the classifier's own TOP-ranked action — a real host
(batis610, Scamalytics 82/100, hosting IP, 2026-08-14) resolved to `warn`
because the classifier ranked `warn` above `ban`, even though `ban` was a
real contender for other hosts in the same corpus slice (2nd choice at
35-39%) and, for batis610 specifically, the evidence alone was extreme
enough to be suspicious regardless of the classifier's ranking.
`extreme_corroborates_bad()` below, plus a secondary-rank check in
fusion.py, add two narrow, independently-gated ways evidence can push a
`warn` up to `ban` without the classifier having picked `ban` outright —
see fusion.py's `_apply_escalation` docstring for exactly how each is
gated and why they're kept separate from the original, more conservative
escalation path.

**FireHOL blocklist hits (2026-08-15).** `blocklist_hits` -- names of
locally-downloaded, curated FireHOL community IP blocklists (open SOCKS/
SSL proxies, known botnet C&C trackers -- see plugins/Shild/blocklist.py
and scripts/update_blocklists.py) that contain the host's IP. Treated the
same as `dnsbl_hits`: a hard, independent signal (counted in
`hard_corroborates_bad()` and `extreme_corroborates_bad()`'s signal count),
never geo/infrastructure-classification like `geo_proxy`. Deliberately a
small, curated set of specific low-cardinality sources (a few thousand
IPs total), not FireHOL's giant multi-million-IP composite aggregates --
this box has only ~3.4GB RAM, and those single-purpose sources have a
much lower false-positive profile than a blind aggregate anyway.

=====================================================================
CRITICAL — evidence must NEVER become a classifier feature.
=====================================================================
Evidence gates the fused decision, and the fused decision becomes the
classifier's training label. If an evidence field were also fed to the
classifier as an input feature, the classifier would simply learn to read
the leak rather than learn anything about the user — precisely the
`in_global_bad` bug that motivated the entire v2 feature set (see
features.py). So: FEATURE_VERSION stays 2, FEATURE_NAMES is unchanged,
and nothing in this module is ever passed to features.extract(). Evidence
is recorded in the JSONL for analysis and rendered into the Ollama prompt
— both fine, neither is a feature.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------
# Cloak trust tiering (Tier 0 — free, local, no network I/O)
# ---------------------------------------------------------------------
# 56% of the hosts this bot actually sees are `user/...` Libera cloaks,
# which have no resolvable IP at all — no amount of IP reputation can say
# anything about them. But the cloak itself is the signal: it means a
# registered, identified services account. Handling this tier well is a
# bigger false-positive win than every IP check combined, and it costs
# nothing.

TRUST_STRONG = "strong"
TRUST_REGISTERED = "registered"
TRUST_NONE = "none"

# Network staff / operator cloaks.
_STRONG_PREFIXES = (
    "libera/staff/",
    "libera/founder/",
    "freenode/staff/",
)

# Cloaks that require a registered, identified account to obtain.
_REGISTERED_PREFIXES = (
    "user/",              # Libera's generic registered-user cloak
    "fedora/", "debian/", "ubuntu/", "archlinux/", "gentoo/", "opensuse/",
    "alpine/", "nixos/", "kde/", "gnome/", "mozilla/", "wikimedia/",
    "wikipedia/", "apache/", "python/", "perl/", "haskell/", "postgresql/",
)

# Undernet has no cloak namespace; instead, users logged in to the X
# service get their host replaced with <account>.users.undernet.org.
# Same meaning as a Libera `user/` cloak: an authenticated account.
_REGISTERED_SUFFIXES = (".users.undernet.org",)

# Gateways: web clients and Tor. `gateway/tor-sasl/` is special — Libera
# requires SASL authentication to use it, so those users ARE authenticated
# even though they are anonymous at the network layer. Treated as
# registered but flagged Tor, so the flag is available for reporting
# without being a de-facto ban trigger.
_TOR_PREFIXES = ("gateway/tor-sasl/",)
_UNTRUSTED_GATEWAY_PREFIXES = ("gateway/web/", "gateway/vpn/")


def classify_cloak(host: str) -> tuple[Optional[str], str, bool]:
    """Return (cloak, trust_tier, is_tor) for a host string.

    `cloak` is the host itself when it looks like a cloak (contains '/'
    or matches a known account-host suffix), else None. A host with no
    cloak — a raw IP or an ISP hostname — gets TRUST_NONE, which is what
    makes it eligible for the external lookups in reputation.py.
    """
    h = host.lower()

    for prefix in _TOR_PREFIXES:
        if h.startswith(prefix):
            return host, TRUST_REGISTERED, True

    for prefix in _STRONG_PREFIXES:
        if h.startswith(prefix):
            return host, TRUST_STRONG, False

    for prefix in _UNTRUSTED_GATEWAY_PREFIXES:
        if h.startswith(prefix):
            return host, TRUST_NONE, False

    for prefix in _REGISTERED_PREFIXES:
        if h.startswith(prefix):
            return host, TRUST_REGISTERED, False

    for suffix in _REGISTERED_SUFFIXES:
        if h.endswith(suffix):
            return host, TRUST_REGISTERED, False

    if "/" in host:
        # An unrecognized cloak namespace. It is still a cloak, which
        # means the network assigned it, but we don't know its policy —
        # so no trust is granted.
        return host, TRUST_NONE, False

    return None, TRUST_NONE, False


@dataclass
class EvidenceThresholds:
    """Kept as data (not constants) so the plugin can drive them from the
    Limnoria registry and so tests can pin them explicitly."""

    abuseipdb_bad: int = 50   # AbuseIPDB confidence-of-abuse score, 0-100
    ipqs_bad: int = 85        # IPQS fraud_score, 0-100; 75+ is "high risk",
                              # 85 chosen to stay well clear of VPN-only hits
    scamalytics_bad: int = 75  # scamalytics_score, 0-100; Scamalytics' own
                              # "high"/"very high" risk tiers start around
                              # here -- tunable once real corpus data exists
                              # to check against, same as the others above.
    require_hard_evidence_for_ban: bool = True

    # 2026-08-14: a second, higher bar used ONLY by extreme_corroborates_bad()
    # below -- see fusion.py's _apply_escalation for the two sub-rules built
    # on top of these. Not confirmed against Scamalytics' own exact tier
    # boundaries (their docs describe low/medium/high/very high without
    # publishing the cutoffs) -- 80 is chosen from real corpus examples: a
    # score of 82 (batis610, 2026-08-14) is meaningfully past the existing
    # "hard" bar (75) and close to a separately-observed 100/"very high"
    # case, so treated as extreme; tune once more real data exists.
    scamalytics_extreme: int = 80
    abuseipdb_extreme: int = 90
    ipqs_extreme: int = 95
    # Safety valve for BOTH new 2026-08-14 sub-rules in
    # fusion._apply_escalation (secondary-rank floor and extreme-evidence
    # override) -- independent of require_hard_evidence_for_ban above,
    # which only governs the pre-existing hard/soft cap. Set False to
    # revert to the pre-2026-08-14 behavior where evidence can only ever
    # confirm the classifier's own TOP-ranked action, never its second
    # choice or override its top pick outright.
    enable_secondary_ban_escalation: bool = True
    # 2026-08-10: safety valve for the hard/soft evidence split below --
    # when True (the default), a `ban` must be corroborated by
    # hard_corroborates_bad(), not merely corroborates_bad(); geo_proxy
    # alone caps the action at `warn`. Set via
    # plugins.Shild.evidence.requireHardEvidenceForBan -- unlike
    # classifier_act_with_evidence, this is captured once into
    # EvidenceThresholds at plugin __init__ (plugin.py:125-128), so a
    # live @config change needs `@reload Shild`, not a full restart
    # (this dataclass itself lives outside shildml/'s restart rule too).


@dataclass
class HostEvidence:
    """Everything gathered about one host for one event. Every field is
    optional/absent-tolerant: a lookup that failed leaves its field at the
    default and records the failure in `checks_failed`, so "we don't know"
    is always distinguishable from "we checked and it was clean".
    """

    resolved_ip: Optional[str] = None
    cloak: Optional[str] = None
    trust_tier: str = TRUST_NONE
    account_present: bool = False

    dnsbl_hits: list[str] = field(default_factory=list)
    dronebl_type: Optional[str] = None
    is_bogon: bool = False
    is_tor_exit: bool = False
    blocklist_hits: list[str] = field(default_factory=list)

    geo_proxy: bool = False
    geo_hosting: bool = False
    asn: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None

    abuseipdb_score: Optional[int] = None
    ipqs_fraud_score: Optional[int] = None
    scamalytics_score: Optional[int] = None
    scamalytics_blacklisted: bool = False  # is_blacklisted_external

    open_proxy_ports: Optional[list[int]] = None  # None = not scanned

    checks_run: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    lookup_ms: float = 0.0

    # ---- derived verdicts ----

    def hard_corroborates_bad(self, th: EvidenceThresholds = EvidenceThresholds()) -> bool:
        """Same as corroborates_bad() but excludes geo_proxy. ip-api's
        proxy/VPN/hosting flag is infrastructure classification, not
        evidence of abuse -- it flags a legitimate VPN subscriber (a real
        ProtonVPN connection was banned on this signal alone, 2026-08-10
        corpus review) identically to a known open relay. A `ban` must
        never rest on this signal alone; see fusion.py's use of this
        method vs. corroborates_bad(). Tor-exit status is deliberately
        NOT included either, for the same "informational, not evidence
        of intent" reason documented on corroborates_bad() below.
        """
        if self.dnsbl_hits:
            return True
        if self.dronebl_type:
            return True
        if self.is_bogon:
            return True
        if self.blocklist_hits:
            return True
        if self.abuseipdb_score is not None and self.abuseipdb_score >= th.abuseipdb_bad:
            return True
        if self.ipqs_fraud_score is not None and self.ipqs_fraud_score >= th.ipqs_bad:
            return True
        if self.scamalytics_score is not None and self.scamalytics_score >= th.scamalytics_bad:
            return True
        if self.scamalytics_blacklisted:
            return True
        if self.open_proxy_ports:
            return True
        return False

    def extreme_corroborates_bad(self, th: EvidenceThresholds = EvidenceThresholds()) -> bool:
        """A higher bar than hard_corroborates_bad(): evidence strong
        enough to justify escalating to `ban` even when the classifier's
        OWN probability distribution ranked ban below allow -- i.e. the
        classifier itself did not consider ban a plausible second choice.
        See fusion.py's _apply_escalation, "extreme-evidence override" --
        the more permissive-on-classifier, stricter-on-evidence of the two
        2026-08-14 secondary escalation rules (the other being the
        secondary-rank floor, which stays within hard_corroborates_bad()
        and requires ban to be the classifier's #2 choice).

        True when either a single score clears a much higher bar than the
        ordinary "hard" threshold (scamalytics/abuseipdb/ipqs_extreme), or
        at least TWO independent hard signals agree (e.g. a real DroneBL
        listing plus an external blacklist hit) -- one moderately-high
        score alone is not enough here; either genuine extremity or
        independent corroboration is required. geo_proxy is never counted,
        same as hard_corroborates_bad().
        """
        if self.scamalytics_score is not None and self.scamalytics_score >= th.scamalytics_extreme:
            return True
        if self.abuseipdb_score is not None and self.abuseipdb_score >= th.abuseipdb_extreme:
            return True
        if self.ipqs_fraud_score is not None and self.ipqs_fraud_score >= th.ipqs_extreme:
            return True

        hard_signal_count = 0
        if self.dnsbl_hits:
            hard_signal_count += 1
        if self.dronebl_type:
            hard_signal_count += 1
        if self.is_bogon:
            hard_signal_count += 1
        if self.blocklist_hits:
            hard_signal_count += 1
        if self.open_proxy_ports:
            hard_signal_count += 1
        if self.abuseipdb_score is not None and self.abuseipdb_score >= th.abuseipdb_bad:
            hard_signal_count += 1
        if self.ipqs_fraud_score is not None and self.ipqs_fraud_score >= th.ipqs_bad:
            hard_signal_count += 1
        if self.scamalytics_score is not None and self.scamalytics_score >= th.scamalytics_bad:
            hard_signal_count += 1
        if self.scamalytics_blacklisted:
            hard_signal_count += 1
        return hard_signal_count >= 2

    def corroborates_bad(self, th: EvidenceThresholds = EvidenceThresholds()) -> bool:
        """Hard, independent evidence that this host is a genuine abuse
        source -- OR the softer geo_proxy signal alone. This method's
        external behavior is unchanged from before the 2026-08-10 hard/soft
        split (still True whenever geo_proxy alone is true) -- it still
        gates whether escalation is attempted at all, and still feeds
        verdict()'s "corroborates" classification. What changed is what a
        `ban` is allowed to become once this returns True: see
        hard_corroborates_bad() above and fusion.py's
        require_hard_evidence_for_ban handling. Tor-exit status is
        deliberately NOT included: Libera runs an official Tor gateway,
        so 'is a Tor exit' says nothing about intent and using it as
        corroboration would ban legitimate users.
        """
        if self.geo_proxy:
            return True
        return self.hard_corroborates_bad(th)

    def contradicts_bad(self, th: EvidenceThresholds = EvidenceThresholds()) -> bool:
        """Hard evidence that this host is a legitimate user. Checked only
        when nothing corroborates badness — see `verdict()`.
        """
        if self.trust_tier in (TRUST_STRONG, TRUST_REGISTERED):
            return True
        if self.account_present:
            return True
        # A host we actually managed to check, on every configured source,
        # with nothing flagged and not sitting in a datacenter. Datacenter
        # IPs are excluded because that is where drones actually live —
        # "clean but hosted" is not positive evidence of legitimacy.
        if (
            self.resolved_ip
            and self.checks_run
            and not self.checks_failed
            and not self.geo_hosting
        ):
            return True
        return False

    def verdict(self, th: EvidenceThresholds = EvidenceThresholds()) -> str:
        """One of "corroborates" | "contradicts" | "unknown".

        Corroboration wins over contradiction: a registered account whose
        IP is nonetheless listed on DroneBL is a compromised machine, and
        the compromise is the more important fact.
        """
        if self.corroborates_bad(th):
            return "corroborates"
        if self.contradicts_bad(th):
            return "contradicts"
        return "unknown"

    # ---- rendering ----

    def summary(self) -> str:
        """One-line human/LLM-readable summary, injected into the Ollama
        prompt (prompts.py). Giving the model facts instead of leaving it
        to guess from a nick is the cheapest false-positive reduction
        available. This is prompt text, never a classifier feature.
        """
        if self.trust_tier == TRUST_STRONG:
            return f"cloak {self.cloak} (NETWORK STAFF — trusted) — no IP checks performed"
        if self.trust_tier == TRUST_REGISTERED:
            tor = " via Tor gateway, SASL-authenticated" if self.is_tor_exit else ""
            return (f"cloak {self.cloak} (registered services account{tor}) "
                    f"— no IP checks performed")

        if not self.resolved_ip:
            return "no resolvable IP and no recognized cloak — no host evidence available"

        parts = [f"IP {self.resolved_ip}"]
        if self.dronebl_type:
            parts.append(f"DroneBL: {self.dronebl_type}")
        if self.dnsbl_hits:
            parts.append(f"DNSBL listed on: {', '.join(self.dnsbl_hits)}")
        if self.blocklist_hits:
            parts.append(f"blocklisted on: {', '.join(self.blocklist_hits)}")
        if self.is_bogon:
            parts.append("BOGON source address (spoofed or misconfigured)")
        if self.is_tor_exit:
            parts.append("Tor exit node (informational — not itself suspicious)")
        if self.asn or self.isp:
            parts.append(f"network: {self.isp or ''} {self.asn or ''}".strip())
        if self.country:
            parts.append(f"country: {self.country}")
        if self.geo_proxy:
            parts.append("flagged as proxy/VPN")
        if self.geo_hosting:
            parts.append("datacenter/hosting IP (not residential)")
        if self.abuseipdb_score is not None:
            parts.append(f"AbuseIPDB abuse confidence: {self.abuseipdb_score}/100")
        if self.ipqs_fraud_score is not None:
            parts.append(f"IPQS fraud score: {self.ipqs_fraud_score}/100")
        if self.scamalytics_score is not None:
            parts.append(f"Scamalytics fraud score: {self.scamalytics_score}/100")
        if self.scamalytics_blacklisted:
            parts.append("Scamalytics: on an external blacklist")
        if self.open_proxy_ports:
            parts.append(f"OPEN PROXY on port(s): "
                         f"{', '.join(str(p) for p in self.open_proxy_ports)}")
        elif self.open_proxy_ports == []:
            parts.append("proxy port scan: clean")
        if not self.dnsbl_hits and not self.dronebl_type and self.checks_run:
            parts.append("clean on all blocklists checked")
        if self.checks_failed:
            parts.append(f"(lookups that failed: {', '.join(self.checks_failed)})")
        return " | ".join(parts)

    def to_dict(self) -> dict:
        return {
            "resolved_ip": self.resolved_ip,
            "cloak": self.cloak,
            "trust_tier": self.trust_tier,
            "account_present": self.account_present,
            "dnsbl_hits": list(self.dnsbl_hits),
            "dronebl_type": self.dronebl_type,
            "is_bogon": self.is_bogon,
            "is_tor_exit": self.is_tor_exit,
            "blocklist_hits": list(self.blocklist_hits),
            "geo_proxy": self.geo_proxy,
            "geo_hosting": self.geo_hosting,
            "asn": self.asn,
            "isp": self.isp,
            "country": self.country,
            "abuseipdb_score": self.abuseipdb_score,
            "ipqs_fraud_score": self.ipqs_fraud_score,
            "scamalytics_score": self.scamalytics_score,
            "scamalytics_blacklisted": self.scamalytics_blacklisted,
            "open_proxy_ports": self.open_proxy_ports,
            "checks_run": list(self.checks_run),
            "checks_failed": list(self.checks_failed),
            "lookup_ms": self.lookup_ms,
            "verdict": self.verdict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "HostEvidence":
        """Rebuild from a recorded JSONL block, so gate_report.py and
        replay can re-derive verdicts offline. Unknown/extra keys (like
        the derived "verdict") are ignored.
        """
        return cls(
            resolved_ip=d.get("resolved_ip"),
            cloak=d.get("cloak"),
            trust_tier=d.get("trust_tier", TRUST_NONE),
            account_present=bool(d.get("account_present", False)),
            dnsbl_hits=list(d.get("dnsbl_hits") or []),
            dronebl_type=d.get("dronebl_type"),
            is_bogon=bool(d.get("is_bogon", False)),
            is_tor_exit=bool(d.get("is_tor_exit", False)),
            blocklist_hits=list(d.get("blocklist_hits") or []),
            geo_proxy=bool(d.get("geo_proxy", False)),
            geo_hosting=bool(d.get("geo_hosting", False)),
            asn=d.get("asn"),
            isp=d.get("isp"),
            country=d.get("country"),
            abuseipdb_score=d.get("abuseipdb_score"),
            ipqs_fraud_score=d.get("ipqs_fraud_score"),
            scamalytics_score=d.get("scamalytics_score"),
            scamalytics_blacklisted=bool(d.get("scamalytics_blacklisted", False)),
            open_proxy_ports=d.get("open_proxy_ports"),
            checks_run=list(d.get("checks_run") or []),
            checks_failed=list(d.get("checks_failed") or []),
            lookup_ms=float(d.get("lookup_ms") or 0.0),
        )
