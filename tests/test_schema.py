import json

from shildml import schema


def test_upcast_v1_clean_row():
    row = schema.upcast_v1({
        "ts": 1, "nick": "x", "ident": "~x", "host": "1.2.3.4", "chan": "#c",
        "action": "warn", "reason": "r", "join_rate": 1, "in_global_bad": False,
        "cross_chan_count": 1,
    })
    assert row is not None
    assert row.action == "warn"
    assert row.label_quality == "ok"
    assert row.source == "eggdrop-v1"
    assert row.account_present is False


def test_upcast_v1_leaked_row_tagged():
    row = schema.upcast_v1({
        "nick": "x", "ident": "~x", "host": "1.2.3.4",
        "action": "ban", "in_global_bad": True,
    })
    assert row is not None
    assert row.action == "ban"
    assert row.label_quality == "leaked"


def test_upcast_v1_kick_folds_into_ban():
    row = schema.upcast_v1({"nick": "x", "ident": "~x", "host": "h", "action": "kick"})
    assert row is not None
    assert row.action == "ban"


def test_upcast_v1_rejects_unknown_action():
    row = schema.upcast_v1({"nick": "x", "ident": "~x", "host": "h", "action": "op"})
    assert row is None


def test_upcast_v1_missing_field_returns_none():
    row = schema.upcast_v1({"nick": "x", "action": "warn"})  # no ident/host
    assert row is None


def test_upcast_v2_basic():
    record = {
        "schema_version": 2, "source": "limnoria-shadow", "nick": "x", "ident": "~x",
        "host": "1.2.3.4", "account": "regnick",
        "context": {"join_rate": 3, "cross_chan_count": 2},
        "fused": {"action": "ban", "confidence": 0.9, "source": "ollama", "reason": "r"},
        "would_have_acted": True,
        "label_quality": "ok",
    }
    row = schema.upcast_v2(record)
    assert row is not None
    assert row.action == "ban"
    assert row.account_present is True
    assert row.join_rate == 3
    assert row.source == "limnoria-shadow-v2"


def _escalation_record(**evidence_kwargs):
    return {
        "nick": "x", "ident": "~x", "host": "1.2.3.4",
        "context": {"join_rate": 0, "cross_chan_count": 0},
        "fused": {"action": "ban", "confidence": 0.6, "source": "classifier+evidence",
                  "reason": "r"},
        "gate": {"applied": True, "rule": "evidence_corroborated_escalation"},
        "evidence": {"resolved_ip": "1.2.3.4", **evidence_kwargs},
        "would_have_acted": True,
        "label_quality": "ok",
    }


def test_upcast_v2_corrects_geo_proxy_only_historical_escalation_ban_to_warn():
    """2026-08-10: the core fix. A row written before the hard/soft
    evidence split recorded fused.action="ban" for a geo_proxy-only
    escalation -- upcast_v2 must correct this at load time, not leave the
    stale label in a future training run."""
    record = _escalation_record(geo_proxy=True)
    row = schema.upcast_v2(record)
    assert row is not None
    assert row.action == "warn"
    assert row.label_quality == "ok"  # still a clean, deterministic label


def test_upcast_v2_leaves_hard_evidence_escalation_ban_alone():
    record = _escalation_record(geo_proxy=True, open_proxy_ports=[8080])
    row = schema.upcast_v2(record)
    assert row is not None
    assert row.action == "ban"


def test_upcast_v2_correction_only_applies_to_the_escalation_rule():
    """A ban with no gate rule at all (e.g. a fully-confident classifier
    ban with no evidence gathered) must not be touched by this
    correction -- it was never subject to the hard/soft split."""
    record = {
        "nick": "x", "ident": "~x", "host": "1.2.3.4", "context": {},
        "fused": {"action": "ban", "confidence": 0.95, "source": "classifier", "reason": "r"},
        "would_have_acted": True,
        "label_quality": "ok",
    }
    row = schema.upcast_v2(record)
    assert row is not None
    assert row.action == "ban"


def test_upcast_v2_correction_does_not_touch_warn_action():
    """Only `ban` is ever corrected -- `warn` is already the milder tier,
    same convention as fusion.py's own cap logic."""
    record = _escalation_record(geo_proxy=True)
    record["fused"]["action"] = "warn"
    record["gate"]["rule"] = "evidence_corroborated_escalation"
    row = schema.upcast_v2(record)
    assert row is not None
    assert row.action == "warn"


def test_upcast_v2_degraded_decision_is_unusable():
    record = {
        "nick": "x", "ident": "~x", "host": "h", "context": {},
        "fused": {"action": "allow", "confidence": 0.0, "source": "degraded", "reason": "failed"},
        "would_have_acted": False,
        "label_quality": "unusable",
    }
    row = schema.upcast_v2(record)
    assert row is not None
    assert row.label_quality == "unusable"


def test_load_training_rows_excludes_leaked_by_default(tmp_path):
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"nick":"a","ident":"~a","host":"1.1.1.1","action":"ban","in_global_bad":true}\n'
        '{"nick":"b","ident":"~b","host":"2.2.2.2","action":"warn","in_global_bad":false}\n'
    )
    rows = schema.load_training_rows(path)
    assert len(rows) == 1
    assert rows[0].nick == "b"

    rows_all = schema.load_training_rows(path, include_leaked=True)
    assert len(rows_all) == 2


def test_load_training_rows_excludes_ignored_always(tmp_path):
    """Added 2026-08-10 alongside Shild's ignore-list feature -- unlike
    "leaked", an "ignored" row must stay excluded even with
    include_leaked=True: it's not a fixable leak, it's a host a human
    deliberately told the classifier to never learn from."""
    path = tmp_path / "data.jsonl"
    path.write_text(
        json.dumps({
            "nick": "a", "ident": "~a", "host": "1.1.1.1", "context": {},
            "fused": {"action": "allow", "confidence": 1.0, "source": "ignore", "reason": "x"},
            "would_have_acted": False,
            "label_quality": "ignored",
        }) + "\n" +
        json.dumps({
            "nick": "b", "ident": "~b", "host": "2.2.2.2", "context": {},
            "fused": {"action": "allow", "confidence": 1.0, "source": "classifier", "reason": "x"},
            "would_have_acted": False,
            "label_quality": "ok",
        }) + "\n"
    )
    rows = schema.load_training_rows(path)
    assert len(rows) == 1
    assert rows[0].nick == "b"

    rows_with_leaked_flag = schema.load_training_rows(path, include_leaked=True)
    assert len(rows_with_leaked_flag) == 1


def test_load_training_rows_skips_malformed_lines(tmp_path, capsys):
    path = tmp_path / "data.jsonl"
    path.write_text(
        '{"nick":"a","ident":"~a","host":"1.1.1.1","action":"warn"}\n'
        "not json at all\n"
        '{"nick":"b","ident":"~b","host":"2.2.2.2","action":"allow"}\n'
    )
    rows = schema.load_training_rows(path)
    assert len(rows) == 2
