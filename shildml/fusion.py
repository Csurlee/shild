"""Pure decision-fusion logic — no I/O, no IRC, no HTTP. This is the
single source of truth for combining the classifier's fast-path
prediction with the Ollama LLM's fallback analysis, shared verbatim by
the live plugin (plugins/Shild/plugin.py, built in M4) and the offline
replay tool (replay.py, built in M3). Sharing one function is what makes
"replay reproduces >=99% of the live plugin's decisions" a meaningful
test rather than two implementations that happen to agree today.

The load-bearing rule is FAIL-OPEN: a malformed/timed-out/unreachable
Ollama response must NEVER be treated as grounds to act. The old Tcl
pipeline's async_scan_decision treated a parse failure (confidence
defaulting to 0.0) as "fallback ban", which silently manufactured a
chunk of the 'ban' training labels from LLM *failures*, not decisions.
That is not replicated here, on purpose — see 05_ai.tcl / 01_protection.tcl
notes from the SHILD Tcl codebase for the bug this fixes.

Phase 1.5 adds a second fail-open layer on top: the evidence gate (see
shildml/evidence.py). Where the rule above stops Ollama's own failures
from manufacturing a ban, the gate stops Ollama/the classifier's
*successful but uncorroborated* guesses from doing the same thing — a
model's confidence is not evidence, and the whole point of this layer is
to require actual evidence before a `ban` survives.

2026-08-09: the gate gained a narrow, symmetric escalation path
(`_apply_escalation`) alongside its original downgrade-only one
(`_apply_gate`) — see that function's docstring for the real incident
that motivated it (idefix banning a hosting+proxy+open-port host on
Undernet #windrop that Shild's own classifier read at only 0.60
confidence, well under `thresholds.classifier_act`, and so never acted
on at all). The rule stays asymmetric in the way that matters: evidence
alone, or a classifier's own confidence alone, is still never enough —
only the *combination* of a classifier already leaning ban/warn AND
independently-corroborating evidence (DNSBL, bogon, geo_proxy, an
AbuseIPDB/IPQS score over threshold, an open proxy port) can escalate.
Neither signal is trusted to manufacture a decision alone; this is two
weak/moderate signals confirming each other, not one signal overriding
the other.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import evidence as evidence_mod

VALID_ACTIONS = ("allow", "warn", "ban")
_DOWNGRADE = {"ban": "warn", "warn": "allow", "allow": "allow"}
_TO_ALLOW = {"ban": "allow", "warn": "allow", "allow": "allow"}


@dataclass
class ClassifierResult:
    action: str
    confidence: float
    probs: list[float] = field(default_factory=list)


@dataclass
class OllamaResult:
    """`ok=False` covers every failure mode: unreachable, timeout, non-200,
    unparseable JSON, or an action outside VALID_ACTIONS. When ok=False,
    `action`/`confidence` are meaningless and callers must not read them
    — decide() never does.
    """
    ok: bool
    action: Optional[str] = None
    confidence: Optional[float] = None
    reason: str = ""
    degraded_reason: str = ""


@dataclass
class FusedDecision:
    action: str
    confidence: float
    source: str  # "classifier" | "ollama" | "trust" | "classifier+evidence" | "degraded"
    reason: str
    degraded: bool = False
    degraded_reason: str = ""
    # "unusable" marks decisions that must never be used as a training
    # label if this event later gets written to a collector (schema.py) —
    # degraded/failure paths are never ground truth.
    label_quality: str = "ok"
    # Set by the evidence gate/escalation (see _apply_gate and
    # _apply_escalation below). gate_rule is one of "" |
    # "ban_not_corroborated" | "contradicted" | "evidence_corroborated_escalation" |
    # "evidence_corroborated_escalation_soft_capped" | "soft_evidence_only"
    # (the last two added 2026-08-10 -- see the hard/soft evidence split) |
    # "evidence_corroborated_escalation_secondary_ban" |
    # "evidence_corroborated_escalation_extreme_evidence" (added 2026-08-14
    # -- see _apply_escalation's docstring for the secondary-rank-floor vs.
    # extreme-evidence-override distinction).
    gate_applied: bool = False
    gate_rule: str = ""


@dataclass
class Thresholds:
    classifier_act: float = 0.85  # classifier confidence needed to skip Ollama entirely
    ollama_act: float = 0.75      # Ollama confidence needed to actually act on its answer
    # Lower bar used ONLY when independently-corroborating evidence agrees
    # with the classifier's own top action (see _apply_escalation). Chosen
    # from the shadow corpus (2026-08-09 analysis): 362 historical rows had
    # a classifier ban/warn read with evidence.corroborates_bad() True,
    # spanning confidence 0.40-0.73; 0.55 catches ~70% of that cluster
    # (the higher-confidence majority) while leaving the weakest tail
    # (0.40-0.50, the least reliable slice) still requiring the full
    # classifier_act bar or Ollama.
    #
    # Lowered 0.55 -> 0.50 on 2026-08-10 after a real near-miss:
    # !shildcheck 192.0.2.1 read classifier ban at 0.538 -- 1.2 points
    # under 0.55 -- while Scamalytics independently rated the same IP
    # 100/100 "very high" fraud risk (hard evidence), and the escalation
    # never fired. A fresh corpus scan (data/shadow_decisions.jsonl) of
    # classifier ban/warn rows with corroborating evidence found a
    # substantial 50-55% confidence bucket (224 rows, comparable in size
    # to several buckets already above the old bar) sitting just outside
    # it. 0.50 is the exact boundary the ORIGINAL 2026-08-09 analysis
    # already drew between "reliable enough to consider" and "the
    # weakest, least reliable tail" (0.40-0.50) -- so this recovers the
    # 50-55% cluster (including the case above) without reaching into
    # that already-flagged unreliable tail.
    classifier_act_with_evidence: float = 0.50

    # 2026-08-14: floor on the classifier's OWN ban-probability (from
    # ClassifierResult.probs) for the secondary-rank escalation sub-rule in
    # _apply_escalation -- only applies when the classifier's top pick was
    # "warn" but ban was its second choice (ranked above allow). Chosen
    # from a real corpus slice: Spike77777/fietanre/tanami_ (2026-08-14)
    # all had ban as their classifier's 2nd choice at 34-39%, a real
    # contender, not noise -- 0.30 catches that cluster. See
    # evidence.py's EvidenceThresholds.scamalytics_extreme etc. for the
    # OTHER new sub-rule (extreme evidence, no rank requirement at all).
    classifier_ban_secondary_floor: float = 0.30


def decide(
    classifier: Optional[ClassifierResult],
    ollama: Optional[OllamaResult],
    thresholds: Thresholds = Thresholds(),
    evidence: "Optional[evidence_mod.HostEvidence]" = None,
    evidence_thresholds: "Optional[evidence_mod.EvidenceThresholds]" = None,
    ollama_disabled: bool = False,
) -> FusedDecision:
    """classifier=None means no model is loaded (or it wasn't consulted).
    ollama=None means Ollama wasn't consulted at all — this happens
    legitimately when the classifier was confident enough that the
    caller never needed to call out to the LLM, or (see `ollama_disabled`)
    when Ollama is turned off entirely.

    `evidence`, when given, is applied as a final gate over the raw fused
    decision (see _apply_gate) — this is additive and backward compatible:
    evidence=None (the default) reproduces the exact pre-Phase-1.5 behavior,
    which is what lets replay.py reproduce decisions recorded before this
    parameter existed.

    `ollama_disabled`: pass True when Ollama has been turned off by config
    (2026-08-06 — see plugin.py's `ollama.enabled`), not merely "failed to
    respond this time". See decide_raw()'s docstring for why this needs to
    be distinct from an unconsulted-due-to-failure `allow`.
    """
    raw = decide_raw(classifier, ollama, thresholds, ollama_disabled=ollama_disabled)
    eth = evidence_thresholds or evidence_mod.EvidenceThresholds()

    if evidence is not None and raw.action == "allow" and not raw.degraded:
        escalated = _apply_escalation(classifier, evidence, thresholds, eth)
        if escalated is not None:
            return escalated

    if evidence is None or raw.degraded or raw.action == "allow":
        return raw
    return _apply_gate(raw, evidence, eth)


def trusted_bypass(evidence: "evidence_mod.HostEvidence") -> FusedDecision:
    """Tier-0 evidence (a trusted cloak or a services account) is
    conclusive entirely on its own — skip the classifier/Ollama round-trip
    and resolve directly to allow. Distinct from _apply_gate: that fires
    AFTER a classifier/Ollama consultation to downgrade a ban/warn that
    turned out uncorroborated; this fires BEFORE any consultation happens
    at all, because trust already answers the question. Not `degraded` —
    this is a deliberate, clean decision, safe to use as a training label.

    Added 2026-08-06: analysis of the shadow corpus showed the classifier
    has never once reached its 0.85 confident-enough-to-check-Tier-0
    threshold, so the pre-existing Tier-0 short-circuit (only reachable
    from a confident classifier's ban/warn) never fired in practice —
    every trusted, cloaked, NickServ-registered user was still going
    through the full Ollama call, where a small model doesn't reliably
    follow its own system-prompt instruction to always allow them.
    """
    return FusedDecision(
        action="allow",
        confidence=1.0,
        source="trust",
        reason=f"trusted Tier 0 evidence, classifier/Ollama skipped: {evidence.summary()}",
    )


def ignored_bypass(host: str) -> FusedDecision:
    """An explicit admin-maintained ignore-list entry (plugin.py's
    `ignoreList`, managed via `shildignore`/`shildunignore`) is
    conclusive on its own -- skip classifier/evidence/Ollama entirely,
    exactly like trusted_bypass() above, but for admin DISCRETION (the
    operator's own second bot, a known friend) rather than an objective
    services-verified fact.

    Unlike trusted_bypass(), this is NOT `label_quality="ok"` -- an
    admin override says nothing about whether the host's actual
    behavior looks clean to the classifier, only that a human decided
    not to act on it regardless. Using it as a genuine "allow" training
    example would teach the classifier the wrong lesson (that whatever
    this host's real feature values are, is what "allow" looks like).
    `label_quality="ignored"` keeps it out of shildml.schema's training
    rows the same way "unusable" already is -- see load_training_rows.
    """
    return FusedDecision(
        action="allow",
        confidence=1.0,
        source="ignore",
        reason=f"host on Shild's ignore list, classifier/evidence/Ollama skipped: {host}",
        label_quality="ignored",
    )


def _apply_escalation(
    classifier: Optional[ClassifierResult],
    ev: "evidence_mod.HostEvidence",
    thresholds: "Thresholds",
    eth: "evidence_mod.EvidenceThresholds",
) -> Optional[FusedDecision]:
    """The one place evidence is allowed to make a decision MORE severe.

    Real incident that motivated this (2026-08-09): idefix (a real op)
    banned 91.239.206.69 on Undernet #windrop -- hosting IP, geo_proxy,
    an open proxy port on 8080, ASN corroborated. Shild's own classifier
    read the same join as ban at 0.60 confidence, well under
    `thresholds.classifier_act` (0.85), and with Ollama disabled the
    unconfident read resolved straight to a clean `allow` -- the
    corroborating evidence was gathered, recorded, and never used.

    Fires only when BOTH hold, so neither signal is trusted alone:
      - the classifier's own top action is already ban/warn (never
        invoked to justify an action the classifier didn't itself pick)
        at or above the lower `classifier_act_with_evidence` bar
      - `ev.corroborates_bad()` is True: at least one hard, independent
        signal (DNSBL, bogon, geo_proxy, an AbuseIPDB/IPQS score over
        threshold, an open proxy port) -- never merely the absence of
        contradicting evidence, which is a different (weaker) thing.

    Returns None (no escalation) rather than a FusedDecision when either
    condition fails, so the caller falls through to the normal `allow`.

    2026-08-10: a `ban` action is capped to `warn` when the only thing
    that corroborated is `geo_proxy` -- `ev.hard_corroborates_bad()` is
    False even though `ev.corroborates_bad()` is True. See evidence.py's
    module docstring for why: geo_proxy alone is infrastructure
    classification (hosting/VPN/proxy), not evidence of abuse, and a
    corpus review found 68% of escalations rested on it alone, including
    a real ban of a legitimate ProtonVPN connection. A classifier `warn`
    pick is never affected by the cap -- it's already the milder tier.
    `eth.require_hard_evidence_for_ban` (default True) is a safety valve
    in case this ever needs disabling -- set via
    `plugins.Shild.evidence.requireHardEvidenceForBan` and takes effect
    on `@reload Shild` (see evidence.py's EvidenceThresholds field).

    2026-08-14: two further, narrower sub-rules can promote a `warn`
    (never a `ban` that was already capped above -- see the `action ==
    "warn"` guard below) up to `ban`, using the classifier's full
    `probs` distribution rather than just its top pick. Real motivating
    case: batis610 (Scamalytics 82/100, hosting IP, no other signal)
    resolved to `warn` because the classifier ranked warn (55%) above
    ban (12-14%) -- correctly, since evidence alone was never supposed
    to out-rank the classifier. But a corpus check the same day found
    three OTHER hosts (Spike77777, fietanre, tanami_) where ban was the
    classifier's clear second choice (34-39%, well above noise) backed
    by hard evidence (an open proxy port, a real DroneBL hit, a bogon
    source) -- genuine near-misses this original rule couldn't reach at
    all, since it only ever reads the top-ranked action. Both sub-rules
    are gated by `eth.enable_secondary_ban_escalation` (default True,
    independent of `require_hard_evidence_for_ban` above):

      - **Secondary-rank floor**: ban is the classifier's own 2nd choice
        (ranked above allow) AND clears `thresholds.classifier_ban_
        secondary_floor` (0.30) AND hard (not soft) evidence corroborates.
        Catches Spike77777/fietanre/tanami_-style cases.
      - **Extreme-evidence override**: `ev.extreme_corroborates_bad()` --
        a materially higher evidence bar than the ordinary hard set
        (either one very high score or 2+ independent hard signals
        agreeing) -- fires regardless of the classifier's ban ranking.
        Catches batis610-style cases, where evidence alone is strong
        enough that it doesn't need the classifier's ranking to agree.

    Kept as two separate rules rather than one, on purpose: the first
    still respects "the classifier at least considered this," the second
    is a genuine, narrower exception to that principle, gated by a
    correspondingly higher evidence bar. Neither can produce anything
    other than `ban` (never a NEW `warn` or higher-than-`ban` action) and
    neither fires unless the base escalation above already qualified as a
    `warn`.
    """
    if classifier is None or classifier.action not in ("ban", "warn"):
        return None
    if classifier.confidence < thresholds.classifier_act_with_evidence:
        return None
    if not ev.corroborates_bad(eth):
        return None

    action = classifier.action
    rule = "evidence_corroborated_escalation"
    reason = (f"classifier {classifier.action} ({classifier.confidence:.0%}) "
              f"corroborated by evidence: {ev.summary()}")
    if action == "ban" and eth.require_hard_evidence_for_ban and not ev.hard_corroborates_bad(eth):
        action = "warn"
        rule = "evidence_corroborated_escalation_soft_capped"
        reason = (f"classifier ban ({classifier.confidence:.0%}) capped to warn -- only "
                  f"soft evidence (geo_proxy) corroborates, no hard signal: {ev.summary()}")

    if action == "warn" and eth.enable_secondary_ban_escalation and len(classifier.probs) >= 3:
        allow_p, warn_p, ban_p = classifier.probs[0], classifier.probs[1], classifier.probs[2]

        if (
            ban_p > allow_p
            and ban_p >= thresholds.classifier_ban_secondary_floor
            and ev.hard_corroborates_bad(eth)
        ):
            action = "ban"
            rule = "evidence_corroborated_escalation_secondary_ban"
            reason = (f"classifier warn ({warn_p:.0%}) with ban as 2nd choice "
                      f"({ban_p:.0%}, ahead of allow {allow_p:.0%}), promoted to ban by "
                      f"hard corroborating evidence: {ev.summary()}")
        elif ev.extreme_corroborates_bad(eth):
            action = "ban"
            rule = "evidence_corroborated_escalation_extreme_evidence"
            reason = (f"classifier warn ({warn_p:.0%}, ban ranked below allow) promoted to "
                      f"ban by extreme corroborating evidence: {ev.summary()}")

    return FusedDecision(
        action=action,
        confidence=classifier.confidence,
        source="classifier+evidence",
        reason=reason,
        gate_applied=True,
        gate_rule=rule,
    )


def _apply_gate(
    raw: FusedDecision,
    ev: "evidence_mod.HostEvidence",
    eth: "evidence_mod.EvidenceThresholds",
) -> FusedDecision:
    """Downgrade-only gate. Never called for an already-`allow` or
    already-degraded decision (see decide()) — nothing left to downgrade.

    2026-08-10: the "corroborates" branch used to be a pass-through
    (raw.action kept as-is). It now applies the same hard/soft cap as
    _apply_escalation -- a raw `ban` corroborated only by geo_proxy
    (soft) downgrades to `warn`, same reasoning as there. Currently
    unreachable in production (the classifier has never crossed
    thresholds.classifier_act in the live corpus, so `raw` never arrives
    here as a non-degraded ban from this path) but must stay correct for
    when that changes (e.g. Ollama re-enabled, or the threshold lowered).
    """
    verdict = ev.verdict(eth)
    if verdict == "contradicts":
        target, rule = "allow", "contradicted"
    elif verdict == "unknown" and raw.action == "ban":
        target, rule = "warn", "ban_not_corroborated"
    elif (
        verdict == "corroborates" and raw.action == "ban"
        and eth.require_hard_evidence_for_ban and not ev.hard_corroborates_bad(eth)
    ):
        target, rule = "warn", "soft_evidence_only"
    else:
        return raw

    if target == raw.action:
        return raw
    return FusedDecision(
        action=target,
        confidence=raw.confidence,
        source=f"{raw.source}+evidence",
        reason=f"{raw.reason} — gate[{rule}]: {ev.summary()}",
        gate_applied=True,
        gate_rule=rule,
    )


def decide_raw(
    classifier: Optional[ClassifierResult],
    ollama: Optional[OllamaResult],
    thresholds: Thresholds = Thresholds(),
    ollama_disabled: bool = False,
) -> FusedDecision:
    """The original (pre-evidence) fusion logic, exposed publicly so
    callers (plugin.py, collector.py) can record both the raw and the
    evidence-gated decision on every event -- that dual record is what
    scripts/gate_report.py measures to show the gate's actual effect.

    `ollama_disabled` (added 2026-08-06): distinguishes "Ollama is turned
    off by config, so of course it wasn't consulted" from "Ollama should
    have been consulted but wasn't" (the latter is a real gap -- worker
    exception, unexpected code path -- and stays `degraded`/`unusable`).
    Corpus analysis showed removing Ollama from the live path is
    reasonable (it never once produced an acting decision across 4,479
    rows, and was the dominant cause of unusable data) -- but a classifier
    read that wasn't confident enough to act on its own is still a real,
    clean, non-degraded outcome when there was never going to be a second
    opinion to begin with.
    """
    if (
        classifier is not None
        and classifier.action in VALID_ACTIONS
        and classifier.confidence >= thresholds.classifier_act
    ):
        return FusedDecision(
            action=classifier.action,
            confidence=classifier.confidence,
            source="classifier",
            reason=f"classifier confident ({classifier.confidence:.0%})",
        )

    if ollama is None and ollama_disabled:
        return FusedDecision(
            action="allow",
            confidence=classifier.confidence if classifier is not None else 0.0,
            source="classifier",
            reason="classifier not confident enough to act; Ollama disabled by config",
        )

    if ollama is None:
        # Classifier wasn't confident (or absent) and nothing else was
        # consulted. The safe default is allow — never manufacture a
        # decision just because nothing conclusive happened.
        return FusedDecision(
            action="allow", confidence=0.0, source="degraded",
            reason="classifier not confident and Ollama not consulted",
            degraded=True, degraded_reason="no_ollama_consulted",
            label_quality="unusable",
        )

    if not ollama.ok:
        return FusedDecision(
            action="allow", confidence=0.0, source="degraded",
            reason="Ollama call failed",
            degraded=True,
            degraded_reason=ollama.degraded_reason or "ollama_failed",
            label_quality="unusable",
        )

    if ollama.action not in VALID_ACTIONS:
        return FusedDecision(
            action="allow", confidence=0.0, source="degraded",
            reason=f"Ollama returned an action outside the vocabulary: {ollama.action!r}",
            degraded=True, degraded_reason="invalid_action",
            label_quality="unusable",
        )

    if ollama.confidence is None or ollama.confidence < thresholds.ollama_act:
        return FusedDecision(
            action="allow",
            confidence=ollama.confidence or 0.0,
            source="ollama",
            reason=f"Ollama not confident enough ({ollama.confidence})",
        )

    return FusedDecision(
        action=ollama.action,
        confidence=ollama.confidence,
        source="ollama",
        reason=ollama.reason or "Ollama decision",
    )
