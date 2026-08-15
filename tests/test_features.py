from shildml import features


def test_feature_count_and_range():
    v = features.extract("SomeNick123", "~ident", "1.2.3.4")
    assert len(v) == features.N_FEATURES == len(features.FEATURE_NAMES)
    assert all(0.0 <= x <= 1.0 for x in v), v


def test_empty_inputs_dont_crash():
    v = features.extract("", "", "")
    assert len(v) == features.N_FEATURES
    assert all(0.0 <= x <= 1.0 for x in v)


def test_raw_ipv4_detected():
    v = features.extract("bot123456", "~x", "45.33.32.156")
    idx = features.FEATURE_NAMES.index("host_is_raw_ip")
    assert v[idx] == 1.0
    idx6 = features.FEATURE_NAMES.index("host_is_ipv6")
    assert v[idx6] == 0.0


def test_ipv6_detected():
    v = features.extract("bot", "~x", "2001:db8::1")
    idx_ip = features.FEATURE_NAMES.index("host_is_raw_ip")
    idx_v6 = features.FEATURE_NAMES.index("host_is_ipv6")
    assert v[idx_ip] == 1.0
    assert v[idx_v6] == 1.0


def test_hostname_not_flagged_as_raw_ip():
    v = features.extract("normaluser", "~real", "user/somenick")
    idx = features.FEATURE_NAMES.index("host_is_raw_ip")
    assert v[idx] == 0.0


def test_datacenter_keyword_detected():
    v = features.extract("x", "~x", "ec2-1-2-3-4.compute.amazonaws.com")
    idx = features.FEATURE_NAMES.index("host_is_datacenter")
    assert v[idx] == 1.0


def test_no_in_global_bad_feature_exists():
    # The whole point of v2: this leak-prone field must not be a feature.
    assert "in_global_bad" not in features.FEATURE_NAMES


def test_account_present_feature_toggles():
    v_no = features.extract("nick", "~i", "h", account_present=False)
    v_yes = features.extract("nick", "~i", "h", account_present=True)
    idx = features.FEATURE_NAMES.index("account_present")
    assert v_no[idx] == 0.0
    assert v_yes[idx] == 1.0


def test_schema_hash_stable():
    assert features.schema_hash() == features.schema_hash()


def test_schema_hash_changes_with_actions():
    import hashlib
    import json

    payload = {
        "feature_version": features.FEATURE_VERSION,
        "feature_names": features.FEATURE_NAMES,
        "actions": ["allow", "warn", "ban", "extra"],
        "datacenter_keywords": features.DATACENTER_KEYWORDS,
    }
    other_hash = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    assert other_hash != features.schema_hash()
