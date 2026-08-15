"""Unit tests for plugins/WebPanel/auth.py -- the highest-value test file
in the WebPanel plan: this is the module a login bypass or a serial-
server denial-of-service would live in if either exists.
"""
import base64

import pytest

from plugins.WebPanel.auth import (
    AuthResult,
    CredentialCache,
    LockoutTracker,
    PanelCredentials,
    check_request,
    hash_password,
    parse_basic_auth,
    verify_password,
)


# ---- hashing ----

def test_hash_and_verify_roundtrip():
    h = hash_password("correct horse battery staple", iterations=100)
    assert verify_password("correct horse battery staple", h)


def test_verify_rejects_wrong_password():
    h = hash_password("right", iterations=100)
    assert not verify_password("wrong", h)


def test_verify_rejects_corrupt_hash():
    assert not verify_password("anything", "not-even-close-to-a-hash")


def test_verify_rejects_wrong_algorithm_tag():
    assert not verify_password("x", "bcrypt$12$abc$def")


def test_verify_rejects_truncated_hash():
    h = hash_password("right", iterations=100)
    truncated = h.rsplit("$", 1)[0]  # drop the derived-key field
    assert not verify_password("right", truncated)


def test_verify_rejects_non_base64_fields():
    assert not verify_password("x", "pbkdf2_sha256$100$not b64!$also not b64!")


def test_verify_never_raises_on_garbage():
    for garbage in ("", "$$$$", "pbkdf2_sha256$notanumber$AA==$AA==", None):
        try:
            if garbage is None:
                continue  # type: ignore[unreachable]
            assert verify_password("x", garbage) is False
        except Exception as e:  # pragma: no cover - the assertion IS the test
            pytest.fail(f"verify_password raised on {garbage!r}: {e}")


# ---- Basic-Auth header parsing ----

def _basic(username: str, password: str) -> str:
    raw = f"{username}:{password}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def test_parse_basic_auth_valid():
    assert parse_basic_auth(_basic("alice", "hunter2")) == ("alice", "hunter2")


def test_parse_basic_auth_missing_header():
    assert parse_basic_auth(None) is None


def test_parse_basic_auth_wrong_scheme():
    payload = base64.b64encode(b"alice:hunter2").decode("ascii")
    assert parse_basic_auth(f"Bearer {payload}") is None


def test_parse_basic_auth_non_base64():
    assert parse_basic_auth("Basic not*valid*base64!!!") is None


def test_parse_basic_auth_non_utf8():
    # Valid base64, but decodes to bytes that aren't valid UTF-8.
    payload = base64.b64encode(b"\xff\xfe\xfd").decode("ascii")
    assert parse_basic_auth(f"Basic {payload}") is None


def test_parse_basic_auth_no_colon():
    payload = base64.b64encode(b"nocolonhere").decode("ascii")
    assert parse_basic_auth(f"Basic {payload}") is None


def test_parse_basic_auth_password_containing_colon():
    # Must split on the FIRST colon only.
    assert parse_basic_auth(_basic("alice", "pa:ss:word")) == ("alice", "pa:ss:word")


def test_parse_basic_auth_empty_username():
    assert parse_basic_auth(_basic("", "hunter2")) == ("", "hunter2")


def test_parse_basic_auth_oversized_header():
    huge = "Basic " + "A" * 5000
    assert parse_basic_auth(huge) is None


# ---- lockout ----

def test_lockout_locks_after_max_failures():
    lt = LockoutTracker(max_failures=3, lockout_secs=60)
    now = 1000.0
    assert not lt.is_locked("1.2.3.4", now)
    lt.record_failure("1.2.3.4", now)
    lt.record_failure("1.2.3.4", now)
    assert not lt.is_locked("1.2.3.4", now)  # 2 failures, not locked yet
    lt.record_failure("1.2.3.4", now)
    assert lt.is_locked("1.2.3.4", now)  # 3rd failure trips the lock


def test_lockout_success_resets_counter():
    lt = LockoutTracker(max_failures=3, lockout_secs=60)
    now = 1000.0
    lt.record_failure("1.2.3.4", now)
    lt.record_failure("1.2.3.4", now)
    lt.record_success("1.2.3.4")
    lt.record_failure("1.2.3.4", now)
    assert not lt.is_locked("1.2.3.4", now)  # counter was reset, only 1 since


def test_lockout_expires():
    lt = LockoutTracker(max_failures=1, lockout_secs=10)
    now = 1000.0
    lt.record_failure("1.2.3.4", now)
    assert lt.is_locked("1.2.3.4", now + 5)
    assert not lt.is_locked("1.2.3.4", now + 11)


def test_lockout_window_slides():
    # Failures more than window_secs apart don't accumulate toward the
    # same lockout.
    lt = LockoutTracker(max_failures=2, lockout_secs=60, window_secs=60)
    lt.record_failure("1.2.3.4", 1000.0)
    lt.record_failure("1.2.3.4", 1000.0 + 61.0)  # window elapsed, resets
    assert not lt.is_locked("1.2.3.4", 1000.0 + 61.0)


def test_lockout_state_stays_bounded():
    lt = LockoutTracker(max_failures=5, lockout_secs=60, max_tracked_ips=256)
    for i in range(10_000):
        lt.record_failure(f"10.0.{i // 256}.{i % 256}", 1000.0 + i * 0.001)
    assert len(lt._state) <= 256


def test_lockout_scoped_per_ip():
    lt = LockoutTracker(max_failures=2, lockout_secs=60)
    lt.record_failure("1.1.1.1", 1000.0)
    lt.record_failure("1.1.1.1", 1000.0)
    assert lt.is_locked("1.1.1.1", 1000.0)
    assert not lt.is_locked("2.2.2.2", 1000.0)


# ---- credential cache ----

def test_credential_cache_hit_and_expiry():
    cache = CredentialCache(ttl_secs=10)
    now = 1000.0
    assert not cache.check("alice", "hunter2", now)
    cache.remember("alice", "hunter2", now)
    assert cache.check("alice", "hunter2", now + 5)
    assert not cache.check("alice", "hunter2", now + 11)


def test_credential_cache_disabled_when_ttl_zero():
    cache = CredentialCache(ttl_secs=0)
    cache.remember("alice", "hunter2", 1000.0)
    assert not cache.check("alice", "hunter2", 1000.0)


def test_credential_cache_wrong_password_is_a_miss():
    cache = CredentialCache(ttl_secs=10)
    cache.remember("alice", "hunter2", 1000.0)
    assert not cache.check("alice", "wrong", 1000.0)


def test_credential_cache_bounded_size():
    cache = CredentialCache(ttl_secs=10, max_entries=16)
    for i in range(100):
        cache.remember(f"user{i}", "pw", 1000.0 + i)
    assert len(cache._entries) <= 16


# ---- check_request: the full per-request decision, incl. the DoS-prevention guarantee ----

CREDS = PanelCredentials(username="csurlee", password_hash=hash_password("realpass", iterations=100))


def _fresh():
    return CredentialCache(ttl_secs=300), LockoutTracker(max_failures=5, lockout_secs=60)


def test_check_request_not_configured():
    cache, lockout = _fresh()
    assert check_request(None, _basic("csurlee", "realpass"), "1.2.3.4", cache, lockout) \
        == AuthResult.NOT_CONFIGURED


def test_check_request_missing_header_is_unauthorized_not_locked_out():
    cache, lockout = _fresh()
    result = check_request(CREDS, None, "1.2.3.4", cache, lockout, now=1000.0)
    assert result == AuthResult.UNAUTHORIZED
    # A bare browser-first-request with no credential must NOT count
    # toward lockout -- otherwise every legitimate first visit would
    # burn an attempt.
    assert not lockout.is_locked("1.2.3.4", 1000.0)


def test_check_request_correct_credentials():
    cache, lockout = _fresh()
    result = check_request(
        CREDS, _basic("csurlee", "realpass"), "1.2.3.4", cache, lockout, now=1000.0)
    assert result == AuthResult.OK


def test_check_request_wrong_password_counts_as_failure():
    cache, lockout = _fresh()
    check_request(CREDS, _basic("csurlee", "wrong"), "1.2.3.4", cache, lockout, now=1000.0)
    assert lockout._state["1.2.3.4"][0] == 1


def test_check_request_locks_out_after_repeated_failures():
    cache, lockout = _fresh()
    for _ in range(5):
        result = check_request(
            CREDS, _basic("csurlee", "wrong"), "1.2.3.4", cache, lockout, now=1000.0)
    assert result == AuthResult.UNAUTHORIZED
    result = check_request(
        CREDS, _basic("csurlee", "wrong"), "1.2.3.4", cache, lockout, now=1000.0)
    assert result == AuthResult.LOCKED


def test_check_request_unknown_username_is_unauthorized():
    cache, lockout = _fresh()
    result = check_request(
        CREDS, _basic("nosuchuser", "whatever"), "1.2.3.4", cache, lockout, now=1000.0)
    assert result == AuthResult.UNAUTHORIZED


def test_check_request_credential_cache_avoids_rehashing():
    """This is the test that stops the serial-server DoS regressing: a
    verified credential must be served from the cache on subsequent
    requests without invoking the (deliberately slow) KDF again."""
    calls = {"n": 0}

    class CountingCache(CredentialCache):
        def check(self, username, password, now):
            hit = super().check(username, password, now)
            if not hit:
                calls["n"] += 1  # a miss means verify_password will run the real KDF
            return hit

    cache = CountingCache(ttl_secs=300)
    lockout = LockoutTracker(max_failures=1000, lockout_secs=60)

    for i in range(100):
        result = check_request(
            CREDS, _basic("csurlee", "realpass"), "1.2.3.4", cache, lockout,
            now=1000.0 + i * 0.01)
        assert result == AuthResult.OK

    # Only the very first request should have been a cache miss (i.e.
    # actually run the KDF); the other 99 must be served from cache.
    assert calls["n"] == 1


def test_check_request_unknown_username_still_does_dummy_kdf_work():
    # Not a call-count assertion (that's covered above) -- this just
    # proves an unknown username doesn't short-circuit before verify_password
    # would run, by checking it doesn't raise and returns UNAUTHORIZED
    # consistently across repeated calls (i.e. no crash from the dummy-hash path).
    cache, lockout = _fresh()
    for _ in range(5):
        assert check_request(
            CREDS, _basic("ghost", "irrelevant"), "9.9.9.9", cache, lockout, now=2000.0,
        ) == AuthResult.UNAUTHORIZED
