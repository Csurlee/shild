"""Pure unit tests for plugins/WebPanel/csrf.py -- no supybot import, no
plugin test harness needed.
"""
from plugins.WebPanel.csrf import OriginResult, TokenSigner, check_origin

# --- TokenSigner --------------------------------------------------------


def test_issue_then_verify_round_trips():
    signer = TokenSigner(bucket_secs=600)
    token = signer.issue("controls", now=1_000_000.0)
    assert signer.verify(token, "controls", now=1_000_000.0)


def test_verify_rejects_wrong_scope():
    signer = TokenSigner(bucket_secs=600)
    token = signer.issue("controls", now=1_000_000.0)
    assert not signer.verify(token, "controls-terms", now=1_000_000.0)


def test_verify_accepts_previous_bucket():
    signer = TokenSigner(bucket_secs=600)
    token = signer.issue("controls", now=1_000_000.0)  # bucket N
    later_same_bucket_boundary = 1_000_000.0 + 600.0 + 1.0  # now in bucket N+1
    assert signer.verify(token, "controls", now=later_same_bucket_boundary)


def test_verify_rejects_two_buckets_old():
    signer = TokenSigner(bucket_secs=600)
    token = signer.issue("controls", now=1_000_000.0)  # bucket N
    two_buckets_later = 1_000_000.0 + 1200.0 + 1.0  # now in bucket N+2
    assert not signer.verify(token, "controls", now=two_buckets_later)


def test_verify_rejects_tampered_mac():
    signer = TokenSigner(bucket_secs=600)
    token = signer.issue("controls", now=1_000_000.0)
    bucket_s, _, mac = token.partition(".")
    tampered = f"{bucket_s}.{'0' * len(mac)}"
    assert not signer.verify(tampered, "controls", now=1_000_000.0)


def test_verify_rejects_non_integer_bucket():
    signer = TokenSigner(bucket_secs=600)
    assert not signer.verify("notanumber.deadbeef", "controls")


def test_verify_rejects_missing_dot():
    signer = TokenSigner(bucket_secs=600)
    assert not signer.verify("nodotatall", "controls")


def test_verify_rejects_none_and_empty():
    signer = TokenSigner(bucket_secs=600)
    assert not signer.verify(None, "controls")
    assert not signer.verify("", "controls")


def test_verify_rejects_oversized_token():
    signer = TokenSigner(bucket_secs=600)
    assert not signer.verify("1." + "a" * 200, "controls")


def test_verify_rejects_future_bucket():
    signer = TokenSigner(bucket_secs=600)
    # A token minted for a bucket far in the future (as if forged, or
    # severe clock skew) must not be treated as valid just because the
    # HMAC would technically match if we ever computed it that way --
    # verify() must not recompute for an arbitrary claimed bucket.
    token = signer.issue("controls", now=1_000_000.0 + 10_000.0)
    assert not signer.verify(token, "controls", now=1_000_000.0)


def test_two_signers_with_different_keys_reject_each_other():
    a = TokenSigner(bucket_secs=600, key=b"a" * 32)
    b = TokenSigner(bucket_secs=600, key=b"b" * 32)
    token = a.issue("controls", now=1_000_000.0)
    assert not b.verify(token, "controls", now=1_000_000.0)


def test_same_key_same_scope_matches_across_instances():
    key = b"k" * 32
    a = TokenSigner(bucket_secs=600, key=key)
    b = TokenSigner(bucket_secs=600, key=key)
    token = a.issue("controls", now=1_000_000.0)
    assert b.verify(token, "controls", now=1_000_000.0)


# --- check_origin ---------------------------------------------------------

ALLOWED = ["10.0.0.1:8080", "127.0.0.1:8080"]


def test_origin_exact_match_ok():
    assert check_origin("http://10.0.0.1:8080", None, ALLOWED) == OriginResult.OK


def test_origin_port_mismatch_rejected():
    assert check_origin("http://10.0.0.1:9999", None, ALLOWED) == OriginResult.MISMATCH


def test_origin_scheme_mismatch_rejected():
    assert check_origin("https://10.0.0.1:8080", None, ALLOWED) == OriginResult.MISMATCH


def test_origin_null_rejected():
    assert check_origin("null", None, ALLOWED) == OriginResult.MISMATCH


def test_origin_case_insensitive():
    assert check_origin("HTTP://10.0.0.1:8080", None, ALLOWED) == OriginResult.OK


def test_both_absent_is_missing():
    assert check_origin(None, None, ALLOWED) == OriginResult.MISSING


def test_referer_fallback_with_path_ok():
    assert check_origin(None, "http://10.0.0.1:8080/panel/controls", ALLOWED) == OriginResult.OK


def test_referer_wrong_host_rejected():
    assert check_origin(None, "http://evil.example/panel/controls", ALLOWED) == OriginResult.MISMATCH


def test_referer_malformed_rejected():
    assert check_origin(None, "not-a-url", ALLOWED) == OriginResult.MISMATCH


def test_origin_present_wins_over_referer_even_when_referer_would_match():
    # Origin, once present at all, is authoritative -- a mismatched
    # Origin is never rescued by a matching Referer.
    result = check_origin(
        "http://evil.example", "http://10.0.0.1:8080/panel/controls", ALLOWED)
    assert result == OriginResult.MISMATCH
