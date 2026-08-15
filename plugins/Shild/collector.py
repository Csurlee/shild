"""Shadow-mode decision collector — writes the v2 JSONL schema consumed
by shildml.schema.upcast_v2. Never appends to the Eggdrop v1 file (see
shildml/schema.py's module docstring for why the two stay separate).

Phase 1.5 adds `fused_raw` (the pre-evidence-gate decision, from
fusion.decide_raw), `gate` (whether/how the gate changed it), and
`evidence` (the full HostEvidence, see shildml/evidence.py) to every
record. `fused` remains the gated decision -- the one used for
would_have_acted, relaying, and training labels -- so consumers written
before this phase (upcast_v2, replay.py) need no changes: they still read
`fused` and simply never see the three new keys. `fused_raw`/`gate`
existing side by side with `fused` is exactly what
scripts/gate_report.py compares to measure the gate's real-world effect,
now that scripts/compare_eggdrop.py's Eggdrop-comparison approach is dead
(both Eggdrop bots are permanently retired).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Optional

from shildml import evidence as evidence_mod
from shildml import fusion, schema

from .context import ContextSnapshot

OBSERVED_MODERATION_SCHEMA_VERSION = 1
ENFORCEMENT_SCHEMA_VERSION = 1


def build_record(
    *, network: str, channel: str, event_type: str,
    nick: str, ident: str, host: str, account: Optional[str],
    ctx: ContextSnapshot,
    classifier: Optional[fusion.ClassifierResult],
    ollama: Optional[fusion.OllamaResult],
    fused: fusion.FusedDecision,
    fused_raw: Optional[fusion.FusedDecision] = None,
    evidence: "Optional[evidence_mod.HostEvidence]" = None,
    ollama_latency_ms: Optional[float] = None,
) -> dict:
    return {
        "schema_version": schema.SCHEMA_VERSION_V2,
        "source": "limnoria-shadow",
        "ts": time.time(),
        "network": network,
        "channel": channel,
        "event_type": event_type,
        "nick": nick,
        "ident": ident,
        "host": host,
        "account": account,
        "context": {
            "join_rate": ctx.join_rate,
            "cross_chan_count": ctx.cross_chan_count,
            "account_present": ctx.account_present,
        },
        "classifier": (
            {"action": classifier.action, "confidence": classifier.confidence,
             "probs": classifier.probs}
            if classifier is not None else None
        ),
        "ollama": (
            {"action": ollama.action, "confidence": ollama.confidence,
             "reason": ollama.reason, "raw_ok": ollama.ok,
             "degraded_reason": ollama.degraded_reason, "latency_ms": ollama_latency_ms}
            if ollama is not None else None
        ),
        "fused": {
            "action": fused.action, "confidence": fused.confidence,
            "source": fused.source, "reason": fused.reason,
        },
        "fused_raw": (
            {"action": fused_raw.action, "confidence": fused_raw.confidence,
             "source": fused_raw.source}
            if fused_raw is not None else None
        ),
        "gate": {"applied": fused.gate_applied, "rule": fused.gate_rule},
        "evidence": evidence.to_dict() if evidence is not None else None,
        "would_have_acted": fused.action != "allow" and not fused.degraded,
        "label_quality": fused.label_quality,
    }


def build_moderation_record(
    *, network: str, channel: str, event_type: str,
    actor_nick: str, actor_ident: str, actor_host: str,
    target_nick: Optional[str], target_ident: Optional[str], target_host: Optional[str],
    reason: str = "", ban_mask: Optional[str] = None,
    classifier: Optional[fusion.ClassifierResult] = None,
) -> dict:
    """A kick/ban **observed from someone else** -- never from Shild itself
    (see plugin.py's doKick/doMode, the only callers of this; both bail if
    the actor is us). This is read-only observation: real ops' real
    decisions on real hosts, which is free ground truth no amount of
    Ollama/classifier introspection can manufacture on its own. Distinct
    from `build_enforcement_record` below, which is the opposite case --
    an action Shild itself took.

    `classifier` is a synchronous, no-network read of what Shild's own
    classifier would have said about the target *at the moment they were
    kicked* (when we know enough about them to ask) -- purely for later
    analysis, never fed back into training automatically and never gating
    anything. `event_type` is "kick" or "ban"; `reason` is the kick reason
    text (empty for bans, which carry no reason field over IRC); `ban_mask`
    is the raw hostmask from a MODE +b/+q (None for kicks).
    """
    return {
        "schema_version": OBSERVED_MODERATION_SCHEMA_VERSION,
        "source": "limnoria-observed-moderation",
        "ts": time.time(),
        "network": network,
        "channel": channel,
        "event_type": event_type,
        "actor": {"nick": actor_nick, "ident": actor_ident, "host": actor_host},
        "target": {"nick": target_nick, "ident": target_ident, "host": target_host},
        "reason": reason,
        "ban_mask": ban_mask,
        "classifier_at_time": (
            {"action": classifier.action, "confidence": classifier.confidence,
             "probs": classifier.probs}
            if classifier is not None else None
        ),
    }


def build_enforcement_record(
    *, id: int, network: str, channel: str, nick: str, ident: str, host: str,
    ban_mask: str, reason: str, duration_secs: int, unban_at: float,
    fused: fusion.FusedDecision,
) -> dict:
    """A real enforcement action Shild itself took -- distinct from both
    `shadow_decisions.jsonl` (decisions, whether or not acted on) and
    `observed_moderation.jsonl` (actions OTHERS took). This is the third
    and final leg of that distinction: an action WE took. `fused` is the
    exact decision that triggered it, kept alongside for audit -- so a
    later review can always answer "why did Shild ban this host" without
    cross-referencing timestamps against the shadow log by hand. `id` is
    the same permanent, ever-incrementing number (plugins/Shild/ban_ids.py)
    shown in the real kick message's own "[ID: N]" (2026-08-11) -- looking
    a past ban back up means finding its `id` here, no separate lookup
    command needed.
    """
    return {
        "schema_version": ENFORCEMENT_SCHEMA_VERSION,
        "source": "limnoria-shild-enforcement",
        "id": id,
        "ts": time.time(),
        "network": network,
        "channel": channel,
        "target": {"nick": nick, "ident": ident, "host": host},
        "ban_mask": ban_mask,
        "reason": reason,
        "duration_secs": duration_secs,
        "unban_at": unban_at,
        "fused_decision": {
            "action": fused.action, "confidence": fused.confidence,
            "source": fused.source, "reason": fused.reason,
        },
    }


class Collector:
    """Append-only writer for shadow_decisions.jsonl (or, via further
    instances, data/observed_moderation.jsonl / data/enforcement_actions.jsonl
    -- see plugin.py). Registered
    with world.flushers is NOT needed here (unlike Seen's periodic-save
    pattern) since every write is already a complete, immediately-synced
    record — there's no in-memory accumulation to flush.
    """

    def __init__(self, path: str):
        self.path = Path(path)

    def write(self, record: dict) -> None:
        schema.write_jsonl_line(self.path, record)
