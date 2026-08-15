from shildml import evidence as evidence_mod
from shildml.fusion import (
    ClassifierResult,
    OllamaResult,
    Thresholds,
    decide,
    decide_raw,
    ignored_bypass,
    trusted_bypass,
)


def test_confident_classifier_skips_ollama():
    d = decide(ClassifierResult("ban", 0.9), None)
    assert d.action == "ban"
    assert d.source == "classifier"
    assert not d.degraded


def test_unconfident_classifier_defers_to_ollama():
    d = decide(
        ClassifierResult("warn", 0.3),
        OllamaResult(ok=True, action="ban", confidence=0.9, reason="bot pattern"),
    )
    assert d.action == "ban"
    assert d.source == "ollama"


def test_no_classifier_no_ollama_is_safe_default():
    d = decide(None, None)
    assert d.action == "allow"
    assert d.degraded
    assert d.label_quality == "unusable"


def test_ollama_failure_is_fail_open_not_ban():
    """The direct regression test for the old system's worst bug: a
    failed/malformed LLM response must never be treated as grounds to ban.
    """
    d = decide(ClassifierResult("warn", 0.1), OllamaResult(ok=False, degraded_reason="timeout"))
    assert d.action == "allow"
    assert d.degraded
    assert d.degraded_reason == "timeout"
    assert d.label_quality == "unusable"


def test_ollama_invalid_action_is_fail_open():
    d = decide(None, OllamaResult(ok=True, action="voice", confidence=0.95))
    assert d.action == "allow"
    assert d.degraded
    assert d.degraded_reason == "invalid_action"


def test_ollama_low_confidence_is_allow_but_not_degraded():
    d = decide(None, OllamaResult(ok=True, action="ban", confidence=0.4))
    assert d.action == "allow"
    assert not d.degraded
    assert d.label_quality == "ok"


def test_ollama_none_confidence_is_fail_open():
    d = decide(None, OllamaResult(ok=True, action="ban", confidence=None))
    assert d.action == "allow"


def test_custom_thresholds_respected():
    t = Thresholds(classifier_act=0.5, ollama_act=0.9)
    d = decide(ClassifierResult("ban", 0.6), None, thresholds=t)
    assert d.action == "ban"
    assert d.source == "classifier"


def test_classifier_invalid_action_falls_through_to_ollama():
    d = decide(
        ClassifierResult("voice", 0.99),  # classifier structurally can't emit this
        OllamaResult(ok=True, action="warn", confidence=0.9),
    )
    assert d.action == "warn"
    assert d.source == "ollama"


def test_trusted_bypass_is_clean_allow_not_degraded():
    ev = evidence_mod.HostEvidence(
        cloak="user/alice", trust_tier=evidence_mod.TRUST_REGISTERED, account_present=True,
    )
    d = trusted_bypass(ev)
    assert d.action == "allow"
    assert d.source == "trust"
    assert not d.degraded
    assert d.label_quality == "ok"
    assert "user/alice" in d.reason


def test_ignored_bypass_is_allow_but_label_quality_ignored():
    """Distinct from trusted_bypass -- an admin override is NOT the same
    training-label trustworthiness as a services-verified trusted cloak,
    so label_quality must be "ignored", not "ok" (see
    shildml.schema.load_training_rows, which excludes it accordingly)."""
    d = ignored_bypass("203.0.113.9")
    assert d.action == "allow"
    assert d.source == "ignore"
    assert not d.degraded
    assert d.label_quality == "ignored"
    assert "203.0.113.9" in d.reason


def test_ollama_disabled_unconfident_classifier_is_clean_allow():
    """2026-08-06: Ollama turned off by config -- an unconfident classifier
    read must resolve cleanly (usable training data), not get relabeled
    degraded/unusable the way an unexpected Ollama failure does.
    """
    d = decide_raw(ClassifierResult("warn", 0.3), None, ollama_disabled=True)
    assert d.action == "allow"
    assert d.source == "classifier"
    assert not d.degraded
    assert d.label_quality == "ok"


def test_ollama_disabled_no_classifier_still_allows():
    d = decide_raw(None, None, ollama_disabled=True)
    assert d.action == "allow"
    assert d.confidence == 0.0
    assert not d.degraded


def test_ollama_not_disabled_unconfident_classifier_still_degrades():
    """Regression guard: ollama_disabled defaults to False, so an
    unexpected "Ollama wasn't consulted" (e.g. a worker exception) must
    still be flagged degraded/unusable exactly as before this change.
    """
    d = decide_raw(ClassifierResult("warn", 0.3), None)
    assert d.action == "allow"
    assert d.degraded
    assert d.degraded_reason == "no_ollama_consulted"
    assert d.label_quality == "unusable"


def test_ollama_disabled_confident_classifier_still_acts():
    """A confident classifier's own read should act regardless of
    ollama_disabled -- that branch is checked first in decide_raw and
    never even looks at the ollama_disabled flag."""
    d = decide_raw(ClassifierResult("ban", 0.9), None, ollama_disabled=True)
    assert d.action == "ban"
    assert d.source == "classifier"
    assert not d.degraded
