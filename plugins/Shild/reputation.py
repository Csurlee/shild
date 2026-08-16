"""Async host-reputation providers: DNSBL, ip-api.com geo/proxy, AbuseIPDB,
IPQualityScore, Scamalytics. Everything here runs inside the existing
worker.py asyncio thread -- nothing in this module may block Limnoria's
main loop.

Tiered by cost, per the Phase 1.5 plan:
  Tier 0 (free, local)   -- cloak trust (evidence.classify_cloak), no I/O.
  Tier 1 (free, unkeyed) -- DNSBL zones + ip-api.com + local FireHOL
                            blocklist membership (blocklist.py -- offline,
                            no network call at all). Only when the host
                            resolved to an IP AND has no cloak trust.
  Tier 2 (keyed, budgeted) -- AbuseIPDB / IPQS / Scamalytics. Only when
                            Tier 1 didn't already corroborate badness
                            (hard evidence only -- see the 2026-08-10
                            gather() comment for why this used to also
                            skip on geo_proxy alone), and only when the
                            caller says a ban/warn is actually on the table
                            (see plugin.py) -- never called speculatively.

Scamalytics added 2026-08-10 as a second Tier 2 fraud-score provider
alongside IPQS, found while investigating why Armour (a TCL bot sharing
channels with us) banned a host Shild only warned on -- Armour's kick
reason ("fraudulent, score: 100") is IPQS's own terminology, and Shild's
own IPQS key has had 0 usable credits since 2026-08-02 despite multiple
key rotations (see CLAUDE.md). Scamalytics is a genuinely different
service/account, not a fallback for the same dead key. API reference
fetched live from docs.scamalytics.com/ip-fraud-risk-api/v3/ (2026-08-10;
WebFetch was blocked by Cloudflare, verified instead via curl with a
browser User-Agent) -- response is wrapped in a top-level "scamalytics"
key, `status` is "ok"/"error", `scamalytics_score` is 0-100,
`is_blacklisted_external` is a real hard blacklist flag independent of
the score. Free tier: 5,000 credits/month, does not roll over -- tighter
than AbuseIPDB's effective ~30,000/month, so budget it more carefully
(see config.py's scamalytics.dailyLimit).

A second, independent Scamalytics account (own username+key, own
"scamalytics2" budget counter -- config.py's scamalytics.dailyLimit2) can
optionally be configured as a same-day fallback: ReputationGatherer only
reaches for it once the PRIMARY account's own daily budget is exhausted
(`budget.try_consume("scamalytics")` returns False), never on a network
failure or an "unknown" API response -- a transient error on the primary
doesn't make the secondary any more likely to succeed, and doubling the
outbound request on every transient failure would waste the secondary's
own limited quota for nothing. Silently unused (not an error) if
scamalytics_username2/scamalytics_key2 aren't both present, same
"optional provider, fails open to skip" convention as every other
optional check in this module.

**Scamalytics call tiered on AbuseIPDB's own result, added 2026-08-16.**
Real budget pressure, not a hypothetical: both Scamalytics accounts
(161/day each, 322/day combined) were observed hitting their daily cap by
mid-afternoon on a real traffic day, while AbuseIPDB (1000/day) still had
real headroom -- Scamalytics was being spent on every single Tier 2
event regardless of what AbuseIPDB already found. `_tier2()` now runs
AbuseIPDB and IPQS concurrently first (same "max not sum" latency
reasoning as everything else in this module), then only calls
Scamalytics if AbuseIPDB's own score lands in the "genuinely ambiguous"
middle band -- `scamalytics_tier_min_abuseipdb` (default 5) to
`scamalytics_tier_max_abuseipdb` (default 50, exclusive) -- rather than
on every event. A score below the low bound is clean enough that a
second opinion rarely changes anything; a score at/above the high bound
already gives AbuseIPDB's own hard-corroborating signal on its own
(see evidence.py's hard_corroborates_bad()), so a second provider isn't
needed to justify the same conclusion. Deliberately fails OPEN toward
MORE checking, not less, whenever AbuseIPDB's own score isn't available
to tier on at all (disabled, no key, budget-exhausted, or a genuine
network failure) -- there is no data to make a skip decision from, so
the safe default is to still ask Scamalytics rather than silently
losing coverage. `scamalytics.tieringEnabled` (default True) is the
escape hatch back to "always call both" if this tradeoff (fewer
Scamalytics-corroborated escalations on already-AbuseIPDB-flagged hosts,
in exchange for the budget lasting through the whole day) turns out to
be the wrong one. A tiered-out skip is NOT recorded in checks_run or
checks_failed -- same convention as scamalytics.enabled=False or a
missing key (not applicable this time, not a failure); checks_failed
specifically must stay reserved for genuine failures, since
evidence.py's own "confirmed clean" path depends on checks_failed being
empty.

Trusted cloaks and unresolvable hosts never reach Tier 1/2 at all: this is
both the privacy decision (never send a registered user's traffic to a
third party) and the budget decision (don't spend AbuseIPDB/ip-api quota
on the 56% of hosts a cloak already answers for).

DNSBL zones used (see docs/DOCUMENTATION.md for the verification history —
several previously-configured zones, including all of Eggdrop's Cymru
entries and Spamhaus's zen/sbl/pbl, were tested live and dropped):
  dnsbl.dronebl.org  -- IRC-focused drone/proxy scanner, decodes to a type.
  bl.spamcop.net     -- general spam-source list, RFC5782-compliant, low FP.
  bogons.cymru.com   -- reserved/unallocated address space (spoofed source).
  torexit.dan.me.uk  -- Tor exit nodes. Informational only -- see
                        evidence.HostEvidence.corroborates_bad for why this
                        never corroborates on its own (Libera runs an
                        official Tor gateway).
  rbl.ircbl.org      -- added 2026-08-10, found while investigating the
                        Armour TCL bot (which shares channels with us and
                        queries this same zone in its own rbl:score).
                        A genuinely independent community blacklist, not
                        an ip-api heuristic -- verified live via the
                        RFC5782 test address (2.0.0.127.rbl.ircbl.org ->
                        127.0.0.2; a real clean IP -> NXDOMAIN). Read-only
                        lookup only -- ircbl.org's separate add/remove API
                        needs a key and is out of scope; we never submit.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import socket
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import aiohttp

from shildml.evidence import TRUST_NONE, HostEvidence, classify_cloak

from . import blocklist, geoip, proxyscan
from .budget import BudgetManager

DRONEBL_ZONE = "dnsbl.dronebl.org"
SPAMCOP_ZONE = "bl.spamcop.net"
BOGON_ZONE = "bogons.cymru.com"
TOREXIT_ZONE = "torexit.dan.me.uk"
IRCBL_ZONE = "rbl.ircbl.org"

DRONEBL_TYPES = {
    3: "IRC Drone", 5: "Bottler", 6: "Spam Drone", 7: "DDOS Drone",
    8: "SOCKS Proxy", 9: "HTTP Proxy", 10: "ProxyChecker",
    11: "Web Page Proxy", 13: "Brute Force Attacker",
    14: "Open Wingate Proxy", 15: "Compromised Router",
    17: "Botnet IP", 18: "DNS/MX Abuse", 19: "Abused VPN",
    255: "Unknown Threat",
}

IPAPI_URL = "http://ip-api.com/json/{ip}"
IPAPI_FIELDS = "status,message,countryCode,regionName,city,org,as,isp,proxy,hosting"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
IPQS_URL = "https://ipqualityscore.com/api/json/ip/{key}/{ip}"
SCAMALYTICS_URL = "https://api12.scamalytics.com/v3/{username}"
# EU node -- verified live 2026-08-10 against the real configured account
# (api11/US returned a bare 404, not a credentials error; api12 returned a
# real 200 with account data). Which node an account lives on is set at
# signup and isn't documented anywhere discoverable from the key/username
# alone, so this was found by trying both, not read from docs.


def load_secrets(path: str) -> dict:
    """API keys come from a gitignored local JSON file, never from the
    Limnoria registry (an admin's `@config` dump would otherwise leak
    them -- see config.py). Environment variables take precedence, for
    deployments that prefer not to keep a secrets file on disk at all.
    """
    data: dict = {}
    p = Path(path)
    if p.exists():
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            data = {}
    return {
        "abuseipdb_key": os.environ.get("SHILD_ABUSEIPDB_KEY") or data.get("abuseipdb_key") or None,
        "ipqs_key": os.environ.get("SHILD_IPQS_KEY") or data.get("ipqs_key") or None,
        "scamalytics_username": (
            os.environ.get("SHILD_SCAMALYTICS_USERNAME") or data.get("scamalytics_username") or None
        ),
        "scamalytics_key": (
            os.environ.get("SHILD_SCAMALYTICS_KEY") or data.get("scamalytics_key") or None
        ),
        "scamalytics_username2": (
            os.environ.get("SHILD_SCAMALYTICS_USERNAME2") or data.get("scamalytics_username2") or None
        ),
        "scamalytics_key2": (
            os.environ.get("SHILD_SCAMALYTICS_KEY2") or data.get("scamalytics_key2") or None
        ),
    }


@dataclass
class ReputationConfig:
    dns_timeout: float = 5.0
    http_timeout: float = 8.0
    dnsbl_ttl: float = 6 * 3600.0
    geo_ttl: float = 24 * 3600.0
    tier2_ttl: float = 24 * 3600.0
    abuseipdb_enabled: bool = True
    abuseipdb_key: Optional[str] = None
    ipqs_enabled: bool = False  # ships disabled: the provided key has 0 credits
    ipqs_key: Optional[str] = None
    scamalytics_enabled: bool = False  # ships disabled until real credentials exist
    scamalytics_username: Optional[str] = None
    scamalytics_key: Optional[str] = None
    scamalytics_username2: Optional[str] = None  # optional fallback account
    scamalytics_key2: Optional[str] = None
    scamalytics_tiering_enabled: bool = True
    scamalytics_tier_min_abuseipdb: int = 5
    scamalytics_tier_max_abuseipdb: int = 50
    geoip_enabled: bool = True
    geoip_db_path: str = "geoip/dbip-city-lite.mmdb"
    blocklist_enabled: bool = True
    blocklist_dir: str = "blocklists"
    blocklist_names: tuple[str, ...] = (
        "socks_proxy_30d", "sslproxies_30d", "cybercrime", "feodo_badips",
    )


class TTLCache:
    """Small in-process LRU+TTL cache. Only successful lookups are cached
    (see module docstring) -- a transient network failure should be
    retried on the next event, not remembered.
    """

    def __init__(self, maxsize: int = 4000):
        self.maxsize = maxsize
        self._store: "OrderedDict[tuple, tuple[float, object]]" = OrderedDict()

    def get(self, key: tuple) -> tuple[object, bool]:
        item = self._store.get(key)
        if item is None:
            return None, False
        expires, value = item
        if time.monotonic() >= expires:
            del self._store[key]
            return None, False
        self._store.move_to_end(key)
        return value, True

    def set(self, key: tuple, value: object, ttl: float) -> None:
        self._store[key] = (time.monotonic() + ttl, value)
        self._store.move_to_end(key)
        while len(self._store) > self.maxsize:
            self._store.popitem(last=False)

    def __len__(self) -> int:
        return len(self._store)


def _reverse_ipv4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


async def _dnsbl_query(loop, query: str, timeout: float) -> tuple[bool, Optional[str]]:
    """(ok, hit_address). ok=False only for a timeout/network error --
    those are real failures, recorded in checks_failed. An NXDOMAIN
    (gaierror) is the normal "not listed" answer for a DNSBL and is
    ok=True with hit=None, exactly as it would be for a dig/host client.
    """
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(query, None, family=socket.AF_INET, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return False, None
    except socket.gaierror:
        return True, None
    except OSError:
        return False, None
    for info in infos:
        addr = info[4][0]
        if addr.startswith("127."):
            return True, addr
    return True, None


async def _resolve_ip(loop, host: str, timeout: float) -> Optional[str]:
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, None, family=socket.AF_INET),
            timeout=timeout,
        )
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return None
    return infos[0][4][0] if infos else None


async def _check_dronebl(loop, ip: str, timeout: float) -> tuple[Optional[str], bool]:
    ok, hit = await _dnsbl_query(loop, f"{_reverse_ipv4(ip)}.{DRONEBL_ZONE}", timeout)
    if not ok:
        return None, True
    if not hit:
        return None, False
    try:
        code = int(hit.rsplit(".", 1)[-1])
    except ValueError:
        return "Unknown Threat", False
    return DRONEBL_TYPES.get(code, f"DroneBL type #{code}"), False


async def _check_spamcop(loop, ip: str, timeout: float) -> tuple[bool, bool]:
    ok, hit = await _dnsbl_query(loop, f"{_reverse_ipv4(ip)}.{SPAMCOP_ZONE}", timeout)
    return (bool(hit), False) if ok else (False, True)


async def _check_bogon(loop, ip: str, timeout: float) -> tuple[bool, bool]:
    ok, hit = await _dnsbl_query(loop, f"{_reverse_ipv4(ip)}.{BOGON_ZONE}", timeout)
    return (bool(hit), False) if ok else (False, True)


async def _check_torexit(loop, ip: str, timeout: float) -> tuple[bool, bool]:
    ok, hit = await _dnsbl_query(loop, f"{_reverse_ipv4(ip)}.{TOREXIT_ZONE}", timeout)
    return (bool(hit), False) if ok else (False, True)


async def _check_ircbl(loop, ip: str, timeout: float) -> tuple[bool, bool]:
    ok, hit = await _dnsbl_query(loop, f"{_reverse_ipv4(ip)}.{IRCBL_ZONE}", timeout)
    return (bool(hit), False) if ok else (False, True)


async def _check_ipapi(session: aiohttp.ClientSession, ip: str, timeout: float) -> tuple[Optional[dict], bool]:
    try:
        async with session.get(
            IPAPI_URL.format(ip=ip), params={"fields": IPAPI_FIELDS},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status != 200:
                return None, True
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None, True
    if data.get("status") != "success":
        return None, True
    return data, False


async def _check_abuseipdb(
    session: aiohttp.ClientSession, ip: str, api_key: str, timeout: float
) -> tuple[Optional[int], bool]:
    try:
        async with session.get(
            ABUSEIPDB_URL, params={"ipAddress": ip, "maxAgeInDays": "90"},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status != 200:
                return None, True
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None, True
    try:
        return int(data["data"]["abuseConfidenceScore"]), False
    except (KeyError, TypeError, ValueError):
        return None, True


async def _check_ipqs(
    session: aiohttp.ClientSession, ip: str, api_key: str, timeout: float
) -> tuple[Optional[int], bool]:
    try:
        async with session.get(
            IPQS_URL.format(key=api_key, ip=ip), params={"strictness": "1"},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None, True
    if not data.get("success"):
        return None, True
    try:
        return int(data["fraud_score"]), False
    except (KeyError, TypeError, ValueError):
        return None, True


async def _check_scamalytics(
    session: aiohttp.ClientSession, ip: str, username: str, api_key: str, timeout: float
) -> tuple[Optional[int], bool, bool]:
    """Returns (fraud_score, is_blacklisted, failed) -- a 3-tuple, since
    Scamalytics carries two independent hard signals per response, unlike
    AbuseIPDB/IPQS's single score. The response is wrapped in a top-level
    "scamalytics" key with its own status field -- see module docstring
    for where this shape was confirmed.
    """
    try:
        async with session.get(
            SCAMALYTICS_URL.format(username=username), params={"key": api_key, "ip": ip},
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as resp:
            if resp.status != 200:
                return None, False, True
            data = await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None, False, True
    block = data.get("scamalytics") or {}
    if block.get("status") != "ok":
        return None, False, True
    try:
        score = int(block["scamalytics_score"])
    except (KeyError, TypeError, ValueError):
        return None, False, True
    return score, bool(block.get("is_blacklisted_external")), False


class ReputationGatherer:
    """One instance per Shild plugin instance, created alongside Worker
    (see plugin.py). Not thread-safe by itself, but only ever called from
    inside the single worker thread's event loop, same as ollama.py.
    """

    def __init__(self, config: ReputationConfig, budget: BudgetManager):
        self.config = config
        self.budget = budget
        self._cache = TTLCache()

    async def gather(
        self,
        session: aiohttp.ClientSession,
        host: str,
        account: Optional[str],
        allow_tier2: bool,
        proxyscan_cfg: Optional[proxyscan.ProxyScanConfig] = None,
        include_ircbl: bool = True,
    ) -> HostEvidence:
        t0 = time.monotonic()
        cloak, trust_tier, is_tor_gateway = classify_cloak(host)
        ev = HostEvidence(
            cloak=cloak, trust_tier=trust_tier,
            account_present=bool(account), is_tor_exit=is_tor_gateway,
        )

        if trust_tier != TRUST_NONE or account:
            # Already contradicts (see evidence.py) -- spend nothing.
            ev.lookup_ms = (time.monotonic() - t0) * 1000
            return ev

        loop = asyncio.get_event_loop()
        ev.resolved_ip = await _resolve_ip(loop, host, self.config.dns_timeout)
        if ev.resolved_ip is None:
            ev.lookup_ms = (time.monotonic() - t0) * 1000
            return ev

        # Tier 3 (proxyscan) depends on nothing Tier 1/2 produce -- only
        # the resolved IP and trust tier already known above -- so it's
        # kicked off here and run CONCURRENTLY with the Tier 1/2 chain
        # rather than strictly after it. Previously plugin.py ran it as a
        # separate, sequential `await proxyscan.scan(...)` once gather()
        # returned; with a real overall_timeout of up to 6s, that was
        # fully additive on top of Tier 1/2 and the single largest
        # contributor to the multi-second join-to-ban latency reported
        # live 2026-08-13 (max(tier1+tier2, proxyscan) instead of sum).
        proxyscan_task = None
        if proxyscan_cfg is not None and proxyscan_cfg.enabled:
            proxyscan_task = asyncio.ensure_future(proxyscan.scan(ev.resolved_ip, proxyscan_cfg))

        await self._tier1(loop, session, ev, include_ircbl)
        # 2026-08-10: was `not ev.corroborates_bad()` -- but geo_proxy alone
        # already makes that True (see evidence.py's hard/soft split), so
        # Tier 1 finding ONLY geo_proxy was skipping Tier 2 entirely, the
        # one place that could actually confirm or clear it with real abuse
        # history. hard_corroborates_bad() excludes geo_proxy, so a
        # geo_proxy-only Tier 1 result now correctly falls through to
        # Tier 2 instead of stopping early.
        if allow_tier2 and not ev.hard_corroborates_bad():
            await self._tier2(session, ev)

        if proxyscan_task is not None:
            ev.open_proxy_ports = await proxyscan_task
            ev.checks_run.append("proxyscan")

        ev.lookup_ms = (time.monotonic() - t0) * 1000
        return ev

    async def _tier1(self, loop, session: aiohttp.ClientSession, ev: HostEvidence,
                      include_ircbl: bool = True) -> None:
        # DNSBL (4-5 zones) and ip-api are fully independent of each other --
        # only sequential because of how this used to be written. Kicking
        # both off before awaiting either turns "sum of both" into "max of
        # both", which is most of the multi-second real-world join-to-ban
        # latency this was found to shave off (2026-08-13, reported live as
        # a ~6s Shild kick vs. ~3s from a single-check bot on the same
        # channel).
        ip = ev.resolved_ip
        await asyncio.gather(self._dnsbl(loop, ip, ev, include_ircbl), self._geo(session, ip, ev))
        # Local FireHOL blocklist membership -- synchronous, no I/O wait
        # (in-memory set lookup + a stat() call), so it doesn't need to be
        # part of the async gather above; see blocklist.py's own docstring.
        self._blocklist(ip, ev)

    def _blocklist(self, ip: str, ev: HostEvidence) -> None:
        if not self.config.blocklist_enabled or not ip:
            return
        blocklist_dir = Path(self.config.blocklist_dir)
        lists = {name: str(blocklist_dir / f"{name}.txt") for name in self.config.blocklist_names}
        if not blocklist.any_list_present(lists):
            ev.checks_failed.append("blocklist_unavailable")
            return
        hits = blocklist.lookup(ip, lists)
        ev.blocklist_hits.extend(hits)
        ev.checks_run.append("blocklist")

    async def _dnsbl(self, loop, ip: str, ev: HostEvidence, include_ircbl: bool = True) -> None:
        # IRCBL is split into its own cache entry/query, separate from the
        # other 4 zones (2026-08-16) -- it's optionally skipped entirely on
        # the live path (see config.py's dnsbl.ircblEnabled docstring for
        # why: it's the one zone consistently slow enough to drag the other
        # 4 down when fired together, and Undernet's own X already g-lines
        # off the same list) but must still be queryable from a manual
        # !shildcheck regardless of the live setting. Folding it into the
        # shared 4-zone cache tuple would mean a live call that skips it
        # could poison the cache for a later manual call that wants it (or
        # vice versa) -- a separate cache key avoids that entirely.
        dnsbl_key = ("dnsbl", ip)
        cached, hit = self._cache.get(dnsbl_key)
        if hit:
            is_bogon, dronebl_type, spamcop_hit, is_tor = cached
            ev.checks_run.extend(["dronebl", "spamcop", "bogon", "torexit"])
        else:
            (dronebl_type, dronebl_failed), (spamcop_hit, spamcop_failed), \
                (is_bogon, bogon_failed), (tor_hit, tor_failed) = await asyncio.gather(
                _check_dronebl(loop, ip, self.config.dns_timeout),
                _check_spamcop(loop, ip, self.config.dns_timeout),
                _check_bogon(loop, ip, self.config.dns_timeout),
                _check_torexit(loop, ip, self.config.dns_timeout),
            )
            is_tor = tor_hit or ev.is_tor_exit
            for name, failed in (
                ("dronebl", dronebl_failed), ("spamcop", spamcop_failed),
                ("bogon", bogon_failed), ("torexit", tor_failed),
            ):
                (ev.checks_failed if failed else ev.checks_run).append(name)
            if not (dronebl_failed or spamcop_failed or bogon_failed or tor_failed):
                self._cache.set(dnsbl_key,
                                 (is_bogon, dronebl_type, spamcop_hit, is_tor),
                                 self.config.dnsbl_ttl)

        ev.dronebl_type = dronebl_type
        ev.is_bogon = is_bogon
        ev.is_tor_exit = is_tor
        if spamcop_hit:
            ev.dnsbl_hits.append(SPAMCOP_ZONE)

        if not include_ircbl:
            return
        ircbl_key = ("ircbl", ip)
        cached_ircbl, ircbl_cache_hit = self._cache.get(ircbl_key)
        if ircbl_cache_hit:
            ircbl_hit = cached_ircbl
            ev.checks_run.append("ircbl")
        else:
            ircbl_hit, ircbl_failed = await _check_ircbl(loop, ip, self.config.dns_timeout)
            (ev.checks_failed if ircbl_failed else ev.checks_run).append("ircbl")
            if not ircbl_failed:
                self._cache.set(ircbl_key, ircbl_hit, self.config.dnsbl_ttl)
        if ircbl_hit:
            ev.dnsbl_hits.append(IRCBL_ZONE)

    async def _geo(self, session: aiohttp.ClientSession, ip: str, ev: HostEvidence) -> None:
        # Country comes from a local, offline MMDB first (see geoip.py) --
        # no network call, no budget, works even when ip-api.com is slow,
        # down, or budget-exhausted for the day. ip-api's own countryCode
        # is only ever used as a fallback (_apply_geo below), e.g. on a
        # fresh install that hasn't run scripts/update_geoip_db.py yet.
        # This does NOT remove the ip-api call itself -- proxy/hosting/
        # ASN/ISP have no free local equivalent, see this module's and
        # geoip.py's docstrings for why.
        if self.config.geoip_enabled:
            local_country = geoip.lookup_country(ip, self.config.geoip_db_path)
            if local_country:
                ev.country = local_country
                ev.checks_run.append("geoip_local")
            else:
                ev.checks_failed.append("geoip_local_unavailable")

        geo_key = ("geo", ip)
        cached_geo, geo_hit = self._cache.get(geo_key)
        if geo_hit:
            self._apply_geo(ev, cached_geo)
            ev.checks_run.append("ipapi")
        elif self.budget.try_consume("ipapi"):
            data, failed = await _check_ipapi(session, ip, self.config.http_timeout)
            if failed:
                ev.checks_failed.append("ipapi")
            else:
                self._apply_geo(ev, data)
                ev.checks_run.append("ipapi")
                self._cache.set(geo_key, data, self.config.geo_ttl)
        else:
            ev.checks_failed.append("ipapi_budget_exhausted")

    @staticmethod
    def _apply_geo(ev: HostEvidence, data: dict) -> None:
        ev.geo_proxy = bool(data.get("proxy"))
        ev.geo_hosting = bool(data.get("hosting"))
        ev.asn = data.get("as") or None
        ev.isp = data.get("isp") or None
        if not ev.country:  # local geoip lookup already populated this, if it succeeded
            ev.country = data.get("countryCode") or None

    async def _tier2(self, session: aiohttp.ClientSession, ev: HostEvidence) -> None:
        # AbuseIPDB and IPQS are independent providers writing independent
        # HostEvidence fields -- run concurrently, same "max not sum"
        # latency fix as _tier1 above (2026-08-13). Scamalytics
        # (2026-08-16) is now TIERED on AbuseIPDB's own result -- see this
        # module's docstring -- so it can no longer join that same gather
        # unconditionally; it runs after, only when actually worth the
        # budget.
        await asyncio.gather(
            self._tier2_abuseipdb(session, ev),
            self._tier2_ipqs(session, ev),
        )
        if self._scamalytics_worth_checking(ev):
            await self._tier2_scamalytics(session, ev)

    def _scamalytics_worth_checking(self, ev: HostEvidence) -> bool:
        cfg = self.config
        if not cfg.scamalytics_tiering_enabled:
            return True
        if ev.abuseipdb_score is None:
            # AbuseIPDB didn't run, had no key, was budget-exhausted, or
            # genuinely failed -- no data to tier on, so fail toward MORE
            # checking, not less.
            return True
        return cfg.scamalytics_tier_min_abuseipdb <= ev.abuseipdb_score < cfg.scamalytics_tier_max_abuseipdb

    async def _tier2_abuseipdb(self, session: aiohttp.ClientSession, ev: HostEvidence) -> None:
        cfg = self.config
        if not (cfg.abuseipdb_enabled and cfg.abuseipdb_key):
            return
        ip = ev.resolved_ip
        key = ("abuseipdb", ip)
        cached, hit = self._cache.get(key)
        if hit:
            ev.abuseipdb_score = cached
            ev.checks_run.append("abuseipdb")
            return
        if not self.budget.try_consume("abuseipdb"):
            ev.checks_failed.append("abuseipdb_budget_exhausted")
            return
        score, failed = await _check_abuseipdb(session, ip, cfg.abuseipdb_key, cfg.http_timeout)
        if failed:
            ev.checks_failed.append("abuseipdb")
        else:
            ev.abuseipdb_score = score
            ev.checks_run.append("abuseipdb")
            self._cache.set(key, score, cfg.tier2_ttl)

    async def _tier2_ipqs(self, session: aiohttp.ClientSession, ev: HostEvidence) -> None:
        cfg = self.config
        if not (cfg.ipqs_enabled and cfg.ipqs_key):
            return
        ip = ev.resolved_ip
        key = ("ipqs", ip)
        cached, hit = self._cache.get(key)
        if hit:
            ev.ipqs_fraud_score = cached
            ev.checks_run.append("ipqs")
            return
        if not self.budget.try_consume("ipqs"):
            ev.checks_failed.append("ipqs_budget_exhausted")
            return
        score, failed = await _check_ipqs(session, ip, cfg.ipqs_key, cfg.http_timeout)
        if failed:
            ev.checks_failed.append("ipqs")
        else:
            ev.ipqs_fraud_score = score
            ev.checks_run.append("ipqs")
            self._cache.set(key, score, cfg.tier2_ttl)

    async def _tier2_scamalytics(self, session: aiohttp.ClientSession, ev: HostEvidence) -> None:
        cfg = self.config
        if not (cfg.scamalytics_enabled and cfg.scamalytics_username and cfg.scamalytics_key):
            return
        ip = ev.resolved_ip
        cache_key = ("scamalytics", ip)
        cached, hit = self._cache.get(cache_key)
        if hit:
            ev.scamalytics_score, ev.scamalytics_blacklisted = cached
            ev.checks_run.append("scamalytics")
            return
        ran = await self._try_scamalytics_account(
            session, ip, cfg.scamalytics_username, cfg.scamalytics_key, "scamalytics", ev)
        if not ran and cfg.scamalytics_username2 and cfg.scamalytics_key2:
            # Primary's daily budget was exhausted -- fall back to a
            # second, independent account rather than giving up for the
            # rest of the day.
            ran = await self._try_scamalytics_account(
                session, ip, cfg.scamalytics_username2, cfg.scamalytics_key2, "scamalytics2", ev)
        if not ran:
            ev.checks_failed.append("scamalytics_budget_exhausted")

    async def _try_scamalytics_account(
        self, session: aiohttp.ClientSession, ip: str, username: str, api_key: str,
        budget_name: str, ev: HostEvidence,
    ) -> bool:
        """Attempts one Scamalytics account under its own budget counter
        (`budget_name` -- "scamalytics" for the primary, "scamalytics2" for
        the optional fallback). Returns False ONLY on budget exhaustion, so
        the caller can tell "try the next account" apart from "this account
        answered (however it answered)" -- a real network/API failure still
        returns True (recorded via checks_failed) since retrying the same
        request against a second account wouldn't fix a malformed response
        or a timeout, only wastes its quota too.
        """
        if not self.budget.try_consume(budget_name):
            return False
        score, is_blacklisted, failed = await _check_scamalytics(
            session, ip, username, api_key, self.config.http_timeout)
        if failed:
            ev.checks_failed.append(budget_name)
        else:
            ev.scamalytics_score = score
            ev.scamalytics_blacklisted = is_blacklisted
            ev.checks_run.append(budget_name)
            self._cache.set(("scamalytics", ip), (score, is_blacklisted), self.config.tier2_ttl)
        return True

    def cache_size(self) -> int:
        return len(self._cache)
