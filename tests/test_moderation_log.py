from plugins.Shild.collector import build_moderation_record
from shildml.fusion import ClassifierResult


def test_kick_record_shape():
    r = build_moderation_record(
        network="libera", channel="#windrop", event_type="kick",
        actor_nick="RealOp", actor_ident="~op", actor_host="op.example.com",
        target_nick="spammer", target_ident="~spam", target_host="203.0.113.9",
        reason="stop spamming",
    )
    assert r["source"] == "limnoria-observed-moderation"
    assert r["event_type"] == "kick"
    assert r["actor"] == {"nick": "RealOp", "ident": "~op", "host": "op.example.com"}
    assert r["target"] == {"nick": "spammer", "ident": "~spam", "host": "203.0.113.9"}
    assert r["reason"] == "stop spamming"
    assert r["ban_mask"] is None
    assert r["classifier_at_time"] is None


def test_kick_record_includes_classifier_reading_when_given():
    clf = ClassifierResult(action="ban", confidence=0.91, probs=[0.02, 0.07, 0.91])
    r = build_moderation_record(
        network="libera", channel="#windrop", event_type="kick",
        actor_nick="RealOp", actor_ident="~op", actor_host="op.example.com",
        target_nick="spammer", target_ident="~spam", target_host="203.0.113.9",
        reason="bot", classifier=clf,
    )
    assert r["classifier_at_time"] == {"action": "ban", "confidence": 0.91, "probs": [0.02, 0.07, 0.91]}


def test_ban_record_shape_has_no_reason_but_has_mask():
    r = build_moderation_record(
        network="undernet", channel="#relay", event_type="ban",
        actor_nick="RealOp", actor_ident="~op", actor_host="op.example.com",
        target_nick=None, target_ident=None, target_host="203.0.113.9",
        ban_mask="*!*@203.0.113.9",
    )
    assert r["event_type"] == "ban"
    assert r["reason"] == ""
    assert r["ban_mask"] == "*!*@203.0.113.9"
    assert r["target"] == {"nick": None, "ident": None, "host": "203.0.113.9"}
