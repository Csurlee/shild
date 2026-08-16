import asyncio

from plugins.Shild import reputation
from plugins.Shild.budget import BudgetManager, ProviderLimits
from plugins.Shild.reputation import (
    ReputationConfig,
    ReputationGatherer,
    TTLCache,
    _reverse_ipv4,
    load_secrets,
)


def test_reverse_ipv4():
    assert _reverse_ipv4("203.0.113.9") == "9.113.0.203"


def test_ttl_cache_expires():
    c = TTLCache()
    c.set(("k",), "v", ttl=0.01)
    value, hit = c.get(("k",))
    assert hit and value == "v"
    import time
    time.sleep(0.02)
    value, hit = c.get(("k",))
    assert not hit


def test_ttl_cache_lru_eviction():
    c = TTLCache(maxsize=2)
    c.set(("a",), 1, ttl=10)
    c.set(("b",), 2, ttl=10)
    c.set(("c",), 3, ttl=10)  # evicts "a"
    assert c.get(("a",))[1] is False
    assert c.get(("b",))[1] is True
    assert c.get(("c",))[1] is True


def test_load_secrets_env_overrides_file(tmp_path, monkeypatch):
    p = tmp_path / "secrets.json"
    p.write_text('{"abuseipdb_key": "from-file", "ipqs_key": "from-file-2"}')
    monkeypatch.setenv("SHILD_ABUSEIPDB_KEY", "from-env")
    monkeypatch.delenv("SHILD_IPQS_KEY", raising=False)
    secrets = load_secrets(str(p))
    assert secrets["abuseipdb_key"] == "from-env"
    assert secrets["ipqs_key"] == "from-file-2"


def test_load_secrets_missing_file_returns_none(tmp_path):
    secrets = load_secrets(str(tmp_path / "nope.json"))
    assert secrets == {
        "abuseipdb_key": None, "ipqs_key": None,
        "scamalytics_username": None, "scamalytics_key": None,
        "scamalytics_username2": None, "scamalytics_key2": None,
    }


def test_load_secrets_corrupt_file_does_not_crash(tmp_path):
    p = tmp_path / "secrets.json"
    p.write_text("{not json")
    secrets = load_secrets(str(p))
    assert secrets["abuseipdb_key"] is None


# ---- ReputationGatherer, with all network calls monkeypatched ----

def _gatherer(tmp_path, **cfg_kwargs) -> ReputationGatherer:
    budget = BudgetManager(
        str(tmp_path / "budget.json"),
        limits={"ipapi": ProviderLimits(rate_per_min=1000)},
    )
    # Off by default here so every pre-existing test in this file stays
    # hermetic/unaffected by the 2026-08-15 local-geoip/blocklist additions;
    # the dedicated tests below opt back in explicitly.
    cfg_kwargs.setdefault("geoip_enabled", False)
    cfg_kwargs.setdefault("blocklist_enabled", False)
    return ReputationGatherer(ReputationConfig(**cfg_kwargs), budget)


def test_trusted_cloak_never_triggers_a_lookup(tmp_path, monkeypatch):
    async def boom(*a, **kw):
        raise AssertionError("must not perform network I/O for a trusted cloak")

    monkeypatch.setattr(reputation, "_resolve_ip", boom)
    monkeypatch.setattr(reputation, "_check_dronebl", boom)

    g = _gatherer(tmp_path)

    async def run():
        return await g.gather(session=None, host="user/alice", account=None, allow_tier2=True)

    ev = asyncio.run(run())
    assert ev.trust_tier == "registered"
    assert ev.resolved_ip is None
    assert ev.checks_run == []


def test_unresolvable_host_never_reaches_tier1(tmp_path, monkeypatch):
    async def resolve_none(loop, host, timeout):
        return None

    async def boom(*a, **kw):
        raise AssertionError("must not run DNSBL checks without a resolved IP")

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_none)
    monkeypatch.setattr(reputation, "_check_dronebl", boom)

    g = _gatherer(tmp_path)

    async def run():
        return await g.gather(session=None, host="some.unresolvable.example", account=None, allow_tier2=True)

    ev = asyncio.run(run())
    assert ev.resolved_ip is None
    assert ev.checks_run == []


def test_dronebl_hit_populates_evidence(tmp_path, monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def dronebl_hit(loop, ip, timeout):
        return "SOCKS Proxy", False

    async def clean(loop, ip, timeout):
        return False, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False,
                "as": "AS1234", "isp": "Some ISP", "countryCode": "US"}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_hit)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)

    g = _gatherer(tmp_path)

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)

    ev = asyncio.run(run())
    assert ev.dronebl_type == "SOCKS Proxy"
    assert ev.verdict() == "corroborates"
    assert "dronebl" in ev.checks_run
    assert ev.isp == "Some ISP"


def test_geoip_local_country_used_when_available(tmp_path, monkeypatch):
    """2026-08-15: local MMDB lookup takes priority over ip-api's own
    countryCode when both are available -- see reputation.py's _geo/
    _apply_geo for why (no network/budget dependency for country)."""
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def ipapi_says_us(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False,
                "as": "AS1234", "isp": "Some ISP", "countryCode": "US"}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_says_us)
    monkeypatch.setattr(reputation.geoip, "lookup_country", lambda ip, path: "DE")

    g = _gatherer(tmp_path, geoip_enabled=True, geoip_db_path="unused-in-this-test")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)

    ev = asyncio.run(run())
    assert ev.country == "DE"  # local wins, not ip-api's "US"
    assert "geoip_local" in ev.checks_run
    assert ev.isp == "Some ISP"  # ip-api's own fields are untouched


def test_geoip_falls_back_to_ipapi_when_local_unavailable(tmp_path, monkeypatch):
    """A fresh install (or a lookup miss) should never lose country data --
    ip-api's countryCode is still the fallback."""
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def ipapi_says_fr(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False,
                "as": "AS1234", "isp": "Some ISP", "countryCode": "FR"}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_says_fr)
    monkeypatch.setattr(reputation.geoip, "lookup_country", lambda ip, path: None)

    g = _gatherer(tmp_path, geoip_enabled=True, geoip_db_path="unused-in-this-test")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)

    ev = asyncio.run(run())
    assert ev.country == "FR"
    assert "geoip_local_unavailable" in ev.checks_failed


def test_geoip_disabled_never_calls_local_lookup(tmp_path, monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def ipapi_says_jp(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False,
                "as": "AS1234", "isp": "Some ISP", "countryCode": "JP"}, False

    def boom(ip, path):
        raise AssertionError("must not call local geoip lookup when disabled")

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_says_jp)
    monkeypatch.setattr(reputation.geoip, "lookup_country", boom)

    g = _gatherer(tmp_path, geoip_enabled=False)

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)

    ev = asyncio.run(run())
    assert ev.country == "JP"
    assert "geoip_local" not in ev.checks_run
    assert "geoip_local_unavailable" not in ev.checks_failed


def test_blocklist_hit_populates_evidence(tmp_path, monkeypatch):
    """2026-08-15: local FireHOL blocklist membership -- a real hard
    evidence signal, unlike geoip's descriptive-only country."""
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False,
                "as": "AS1234", "isp": "Some ISP", "countryCode": "US"}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)
    monkeypatch.setattr(reputation.blocklist, "any_list_present", lambda lists: True)
    monkeypatch.setattr(reputation.blocklist, "lookup", lambda ip, lists: ["cybercrime"])

    g = _gatherer(tmp_path, blocklist_enabled=True, blocklist_dir="unused-in-this-test",
                  blocklist_names=("cybercrime",))

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)

    ev = asyncio.run(run())
    assert ev.blocklist_hits == ["cybercrime"]
    assert ev.hard_corroborates_bad()
    assert "blocklist" in ev.checks_run


def test_blocklist_no_files_downloaded_yet_fails_open(tmp_path, monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False,
                "as": "AS1234", "isp": "Some ISP", "countryCode": "US"}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)

    g = _gatherer(tmp_path, blocklist_enabled=True,
                  blocklist_dir=str(tmp_path / "nonexistent-blocklists-dir"))

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)

    ev = asyncio.run(run())
    assert ev.blocklist_hits == []
    assert "blocklist_unavailable" in ev.checks_failed
    assert ev.verdict() != "corroborates"  # must not falsely corroborate on missing data


def test_blocklist_disabled_never_checks(tmp_path, monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False,
                "as": "AS1234", "isp": "Some ISP", "countryCode": "US"}, False

    def boom(*a, **kw):
        raise AssertionError("must not check blocklists when disabled")

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)
    monkeypatch.setattr(reputation.blocklist, "any_list_present", boom)
    monkeypatch.setattr(reputation.blocklist, "lookup", boom)

    g = _gatherer(tmp_path, blocklist_enabled=False)

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)

    ev = asyncio.run(run())
    assert ev.blocklist_hits == []
    assert "blocklist" not in ev.checks_run
    assert "blocklist_unavailable" not in ev.checks_failed


def test_ircbl_hit_populates_dnsbl_hits(tmp_path, monkeypatch):
    """Added 2026-08-10: rbl.ircbl.org, verified live via RFC5782 while
    investigating the Armour TCL bot -- a genuinely independent community
    blacklist, wired in the same shape as SpamCop (appends its zone name
    to dnsbl_hits, a hard corroborating signal)."""
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def ircbl_hit(loop, ip, timeout):
        return True, False

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", ircbl_hit)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)

    g = _gatherer(tmp_path)

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)

    ev = asyncio.run(run())
    assert ev.dnsbl_hits == [reputation.IRCBL_ZONE]
    assert "ircbl" in ev.checks_run
    assert ev.verdict() == "corroborates"
    assert ev.hard_corroborates_bad()


def test_include_ircbl_false_skips_ircbl_query_entirely(tmp_path, monkeypatch):
    """2026-08-16: dnsbl.ircblEnabled=False on the live path -- IRCBL must
    not be queried at all (not run, not failed, not in dnsbl_hits) when
    include_ircbl=False is passed through, and the other 4 zones must be
    completely unaffected."""
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    called = {"ircbl": False}

    async def ircbl_would_hit(loop, ip, timeout):
        called["ircbl"] = True
        return True, False

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", ircbl_would_hit)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)

    g = _gatherer(tmp_path)

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None,
                               allow_tier2=False, include_ircbl=False)

    ev = asyncio.run(run())
    assert called["ircbl"] is False
    assert ev.dnsbl_hits == []
    assert "ircbl" not in ev.checks_run
    assert "ircbl" not in ev.checks_failed
    # the other 4 zones still ran normally
    assert "dronebl" in ev.checks_run
    assert "spamcop" in ev.checks_run
    assert "bogon" in ev.checks_run
    assert "torexit" in ev.checks_run


def test_include_ircbl_false_then_true_both_get_fresh_correct_answers(tmp_path, monkeypatch):
    """The main dnsbl cache tuple no longer carries ircbl_hit (split into
    its own cache key, 2026-08-16) -- a live call with include_ircbl=False
    followed by a manual !shildcheck-style call with include_ircbl=True for
    the SAME ip must not reuse a stale/absent ircbl answer from the first
    call's cache entry; it must actually query ircbl on the second call."""
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    ircbl_calls = {"n": 0}

    async def ircbl_hit(loop, ip, timeout):
        ircbl_calls["n"] += 1
        return True, False

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", ircbl_hit)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)

    g = _gatherer(tmp_path)

    async def run():
        live = await g.gather(session=object(), host="203.0.113.9", account=None,
                               allow_tier2=False, include_ircbl=False)
        manual = await g.gather(session=object(), host="203.0.113.9", account=None,
                                 allow_tier2=False, include_ircbl=True)
        return live, manual

    live_ev, manual_ev = asyncio.run(run())
    assert live_ev.dnsbl_hits == []
    assert manual_ev.dnsbl_hits == [reputation.IRCBL_ZONE]
    assert ircbl_calls["n"] == 1  # only the manual call actually queried it
    # the other 4 zones' cache DID help the second call (no re-query needed
    # to still get the right, consistent answer)
    assert manual_ev.is_bogon == live_ev.is_bogon
    assert manual_ev.dronebl_type == live_ev.dronebl_type


def test_tier2_skipped_when_tier1_already_corroborates(tmp_path, monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def dronebl_hit(loop, ip, timeout):
        return "SOCKS Proxy", False

    async def clean(loop, ip, timeout):
        return False, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    async def boom_tier2(*a, **kw):
        raise AssertionError("tier 2 must not run when tier 1 already corroborates")

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_hit)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)
    monkeypatch.setattr(reputation, "_check_abuseipdb", boom_tier2)

    g = _gatherer(tmp_path, abuseipdb_enabled=True, abuseipdb_key="fake-key")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    asyncio.run(run())  # would have raised via boom_tier2 if tier 2 ran


def test_tier2_runs_when_tier1_only_has_soft_evidence(tmp_path, monkeypatch):
    """2026-08-10 fix: geo_proxy alone used to skip Tier 2 entirely (it
    satisfied the old corroborates_bad() check) -- meaning the one case
    that most needs a second, harder look (nothing but "hosted somewhere")
    never got one. hard_corroborates_bad() excludes geo_proxy, so Tier 2
    must now run and get a real chance to confirm or clear it."""
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_proxy_only(session, ip, timeout):
        return {"status": "success", "proxy": True, "hosting": True}, False

    async def abuseipdb_hit(session, ip, key, timeout):
        return 95, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_proxy_only)
    monkeypatch.setattr(reputation, "_check_abuseipdb", abuseipdb_hit)

    g = _gatherer(tmp_path, abuseipdb_enabled=True, abuseipdb_key="fake-key")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    ev = asyncio.run(run())
    assert ev.geo_proxy is True
    assert ev.abuseipdb_score == 95  # Tier 2 actually ran this time
    assert ev.hard_corroborates_bad()  # now hard, thanks to the AbuseIPDB hit


def test_tier2_runs_when_tier1_inconclusive(tmp_path, monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    async def abuseipdb_hit(session, ip, key, timeout):
        assert key == "fake-key"
        return 90, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)
    monkeypatch.setattr(reputation, "_check_abuseipdb", abuseipdb_hit)

    g = _gatherer(tmp_path, abuseipdb_enabled=True, abuseipdb_key="fake-key")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    ev = asyncio.run(run())
    assert ev.abuseipdb_score == 90
    assert ev.verdict() == "corroborates"


def test_disabled_ipqs_never_called_even_with_key(tmp_path, monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    async def boom(*a, **kw):
        raise AssertionError("ipqs must not be called while disabled")

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)
    monkeypatch.setattr(reputation, "_check_ipqs", boom)

    g = _gatherer(tmp_path, ipqs_enabled=False, ipqs_key="present-but-should-not-be-used")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    asyncio.run(run())


def test_scamalytics_hit_populates_score_and_blacklist_flag(tmp_path, monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    async def scamalytics_hit(session, ip, username, key, timeout):
        assert username == "fake-user"
        assert key == "fake-key"
        return 91, True, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)
    monkeypatch.setattr(reputation, "_check_scamalytics", scamalytics_hit)

    g = _gatherer(tmp_path, scamalytics_enabled=True,
                  scamalytics_username="fake-user", scamalytics_key="fake-key")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    ev = asyncio.run(run())
    assert ev.scamalytics_score == 91
    assert ev.scamalytics_blacklisted is True
    assert "scamalytics" in ev.checks_run
    assert ev.hard_corroborates_bad()


def test_scamalytics_disabled_never_called_even_with_credentials(tmp_path, monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    async def boom(*a, **kw):
        raise AssertionError("scamalytics must not be called while disabled")

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)
    monkeypatch.setattr(reputation, "_check_scamalytics", boom)

    g = _gatherer(tmp_path, scamalytics_enabled=False,
                  scamalytics_username="present", scamalytics_key="present-but-unused")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    asyncio.run(run())


def test_scamalytics_skipped_without_username_even_if_enabled_and_keyed(tmp_path, monkeypatch):
    """Scamalytics needs BOTH username and key, unlike AbuseIPDB/IPQS
    which only need a key -- a configured key with no username must not
    fire (would 404/malformed-URL against the real API)."""
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    async def boom(*a, **kw):
        raise AssertionError("scamalytics must not be called without a username")

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)
    monkeypatch.setattr(reputation, "_check_scamalytics", boom)

    g = _gatherer(tmp_path, scamalytics_enabled=True,
                  scamalytics_username=None, scamalytics_key="present-but-unused")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    asyncio.run(run())


def test_scamalytics_repeat_lookup_hits_cache_not_network(tmp_path, monkeypatch):
    calls = {"scamalytics": 0}

    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    async def scamalytics_counting(session, ip, username, key, timeout):
        calls["scamalytics"] += 1
        return 42, False, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)
    monkeypatch.setattr(reputation, "_check_scamalytics", scamalytics_counting)

    g = _gatherer(tmp_path, scamalytics_enabled=True,
                  scamalytics_username="fake-user", scamalytics_key="fake-key")

    async def run_twice():
        await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)
        await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    asyncio.run(run_twice())
    assert calls["scamalytics"] == 1  # second call served from cache


def _scamalytics_fallback_gatherer(tmp_path, *, primary_limit, secondary_limit, username2, key2):
    """Unlike _gatherer(), gives scamalytics/scamalytics2 real (possibly
    zero) budgets rather than leaving them untracked, so a test can force
    the primary account's budget to be exhausted and assert fallback
    behavior."""
    budget = BudgetManager(
        str(tmp_path / "budget.json"),
        limits={
            "ipapi": ProviderLimits(rate_per_min=1000),
            "scamalytics": ProviderLimits(daily_limit=primary_limit),
            "scamalytics2": ProviderLimits(daily_limit=secondary_limit),
        },
    )
    cfg = ReputationConfig(
        scamalytics_enabled=True,
        scamalytics_username="fake-user", scamalytics_key="fake-key",
        scamalytics_username2=username2, scamalytics_key2=key2,
    )
    return ReputationGatherer(cfg, budget)


def _patch_clean_tier1(monkeypatch):
    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def clean(loop, ip, timeout):
        return False, False

    async def dronebl_clean(loop, ip, timeout):
        return None, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_clean)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)


def test_scamalytics_falls_back_to_second_account_when_primary_budget_exhausted(tmp_path, monkeypatch):
    calls = []

    async def scamalytics_recording(session, ip, username, key, timeout):
        calls.append(username)
        assert username == "fake-user-2"
        assert key == "fake-key-2"
        return 77, False, False

    _patch_clean_tier1(monkeypatch)
    monkeypatch.setattr(reputation, "_check_scamalytics", scamalytics_recording)

    g = _scamalytics_fallback_gatherer(
        tmp_path, primary_limit=0, secondary_limit=10,
        username2="fake-user-2", key2="fake-key-2")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    ev = asyncio.run(run())
    assert calls == ["fake-user-2"]  # primary never called -- budget denied before the request
    assert ev.scamalytics_score == 77
    assert "scamalytics2" in ev.checks_run
    assert "scamalytics" not in ev.checks_run


def test_scamalytics_budget_exhausted_with_no_second_account_configured(tmp_path, monkeypatch):
    async def boom(*a, **kw):
        raise AssertionError("scamalytics must not be called once budget is exhausted")

    _patch_clean_tier1(monkeypatch)
    monkeypatch.setattr(reputation, "_check_scamalytics", boom)

    g = _scamalytics_fallback_gatherer(
        tmp_path, primary_limit=0, secondary_limit=10,
        username2=None, key2=None)

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    ev = asyncio.run(run())
    assert ev.scamalytics_score is None
    assert "scamalytics_budget_exhausted" in ev.checks_failed


def test_scamalytics_budget_exhausted_records_failure_when_both_accounts_exhausted(tmp_path, monkeypatch):
    async def boom(*a, **kw):
        raise AssertionError("scamalytics must not be called once both budgets are exhausted")

    _patch_clean_tier1(monkeypatch)
    monkeypatch.setattr(reputation, "_check_scamalytics", boom)

    g = _scamalytics_fallback_gatherer(
        tmp_path, primary_limit=0, secondary_limit=0,
        username2="fake-user-2", key2="fake-key-2")

    async def run():
        return await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=True)

    ev = asyncio.run(run())
    assert ev.scamalytics_score is None
    assert "scamalytics_budget_exhausted" in ev.checks_failed


def test_repeat_lookup_hits_cache_not_network(tmp_path, monkeypatch):
    calls = {"dronebl": 0}

    async def resolve_ip(loop, host, timeout):
        return "203.0.113.9"

    async def dronebl_counting(loop, ip, timeout):
        calls["dronebl"] += 1
        return "SOCKS Proxy", False

    async def clean(loop, ip, timeout):
        return False, False

    async def ipapi_clean(session, ip, timeout):
        return {"status": "success", "proxy": False, "hosting": False}, False

    monkeypatch.setattr(reputation, "_resolve_ip", resolve_ip)
    monkeypatch.setattr(reputation, "_check_dronebl", dronebl_counting)
    monkeypatch.setattr(reputation, "_check_spamcop", clean)
    monkeypatch.setattr(reputation, "_check_bogon", clean)
    monkeypatch.setattr(reputation, "_check_torexit", clean)
    monkeypatch.setattr(reputation, "_check_ircbl", clean)
    monkeypatch.setattr(reputation, "_check_ipapi", ipapi_clean)

    g = _gatherer(tmp_path)

    async def run_twice():
        await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)
        await g.gather(session=object(), host="203.0.113.9", account=None, allow_tier2=False)

    asyncio.run(run_twice())
    assert calls["dronebl"] == 1  # second call served from cache
