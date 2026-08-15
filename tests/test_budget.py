import json
import time

from plugins.Shild.budget import BudgetManager, ProviderLimits, TokenBucket


def test_token_bucket_allows_up_to_capacity():
    b = TokenBucket(rate_per_min=60, capacity=3)
    assert b.try_acquire()
    assert b.try_acquire()
    assert b.try_acquire()
    assert not b.try_acquire()


def test_token_bucket_refills_over_time():
    b = TokenBucket(rate_per_min=6000, capacity=1)  # 100/sec refill
    assert b.try_acquire()
    assert not b.try_acquire()
    time.sleep(0.05)
    assert b.try_acquire()


def test_untracked_provider_always_allowed(tmp_path):
    bm = BudgetManager(str(tmp_path / "budget.json"), limits={})
    for _ in range(50):
        assert bm.try_consume("unknown-provider")


def test_daily_limit_enforced_and_persisted(tmp_path):
    path = tmp_path / "budget.json"
    bm = BudgetManager(str(path), limits={"abuseipdb": ProviderLimits(daily_limit=2)})
    assert bm.try_consume("abuseipdb")
    assert bm.try_consume("abuseipdb")
    assert not bm.try_consume("abuseipdb")

    on_disk = json.loads(path.read_text())
    assert on_disk["abuseipdb"]["daily"] == 2

    # A fresh BudgetManager reading the same file must not reset the count
    # -- this is the whole point of persisting: a restart must not grant a
    # fresh quota.
    bm2 = BudgetManager(str(path), limits={"abuseipdb": ProviderLimits(daily_limit=2)})
    assert not bm2.try_consume("abuseipdb")


def test_lifetime_limit_enforced(tmp_path):
    bm = BudgetManager(str(tmp_path / "b.json"), limits={"ipqs": ProviderLimits(lifetime_limit=1)})
    assert bm.try_consume("ipqs")
    assert not bm.try_consume("ipqs")


def test_rate_limit_enforced(tmp_path):
    bm = BudgetManager(str(tmp_path / "b.json"), limits={"ipapi": ProviderLimits(rate_per_min=2)})
    assert bm.try_consume("ipapi")
    assert bm.try_consume("ipapi")
    assert not bm.try_consume("ipapi")


def test_stats_reports_per_provider_counts(tmp_path):
    bm = BudgetManager(str(tmp_path / "b.json"), limits={"abuseipdb": ProviderLimits(daily_limit=100)})
    bm.try_consume("abuseipdb")
    bm.try_consume("abuseipdb")
    stats = bm.stats()
    assert stats["abuseipdb"]["daily"] == 2
    assert stats["abuseipdb"]["lifetime"] == 2


def test_corrupt_budget_file_does_not_crash(tmp_path):
    path = tmp_path / "b.json"
    path.write_text("{not valid json")
    bm = BudgetManager(str(path), limits={"abuseipdb": ProviderLimits(daily_limit=5)})
    assert bm.try_consume("abuseipdb")  # falls back to empty state, doesn't raise
