"""Training/decision record schemas and JSONL I/O.

Two record families exist, deliberately never merged at write time:

- v1: the Tcl/Eggdrop collector's format (~/eggdrop/logs/classifier_training.jsonl),
  10 keys: ts, nick, ident, host, chan, action, reason, join_rate,
  in_global_bad, cross_chan_count. Still being written today by the
  (untouched, per user decision) Eggdrop bots.
- v2: the Limnoria shadow-mode collector's format (plugins/Shild/collector.py,
  built in M4) — richer, carries classifier + Ollama provenance separately
  from the fused decision, and is leak-free by construction because its
  context snapshot is taken before any evaluation happens.

`upcast_v1` converts a v1 dict into a `TrainingRow` — the common shape the
trainer actually consumes — tagging rows whose label may be tainted by the
in_global_bad leak (see features.py docstring) as label_quality="leaked"
rather than silently trusting or silently discarding them. Merge happens
here, at training time, never by writing into the other file.

2026-08-10: `upcast_v2` also corrects one specific historical label
class, at load time, for the same reason -- never mutate the raw JSONL,
only what a training run actually consumes. Rows written via the
evidence-corroborated-escalation path (fusion.py's `_apply_escalation`)
before the hard/soft evidence split landed recorded `fused.action="ban"`
whenever ANY evidence corroborated, including geo_proxy alone -- ip-api's
proxy/VPN/hosting flag, which is infrastructure classification, not
abuse evidence (a real ProtonVPN connection was banned on this signal
alone; see evidence.py's module docstring). A corpus check found 23 of
33 such historical `ban` rows are geo_proxy-only and would resolve to
`warn` under current policy. Since every input the current policy needs
(the recorded `evidence` block) is already in the row, this is a
deterministic recomputation -- not a guess, not a human override, not a
new decision -- so it belongs in the loader, applied automatically to
every future training run, not a one-off relabeling script.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from . import evidence as _evidence

SCHEMA_VERSION_V2 = 2


def read_jsonl(path: str | Path) -> Iterator[dict]:
    """Yield one dict per non-empty line. Malformed lines are skipped with
    a note on stderr rather than raising — training corpora accumulate
    over months and one bad line shouldn't kill the whole run.
    """
    import sys

    p = Path(path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as e:
                print(f"{path}:{lineno}: skipping malformed line: {e}", file=sys.stderr)


def write_jsonl_line(path: str | Path, record: dict) -> None:
    """Append one record as a single JSONL line. Callers are responsible
    for flushing/fsync semantics (see plugins/Shild/collector.py).
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True))
        fh.write("\n")


@dataclass
class TrainingRow:
    """The common shape shildml.train actually consumes, regardless of
    which collector produced it.
    """

    nick: str
    ident: str
    host: str
    join_rate: float
    account_present: bool
    cross_chan_count: int
    action: str  # one of features.ACTIONS ("allow" | "warn" | "ban")
    source: str  # "eggdrop-v1" | "limnoria-shadow-v2"
    label_quality: str  # "ok" | "leaked" | "unusable"
    host_group: str = field(init=False)

    def __post_init__(self):
        # Used for host-grouped train/val splitting so near-duplicate
        # events from the same host never land on both sides of the split.
        self.host_group = self.host


# v1 action values that don't map onto the 3-class taxonomy at all (e.g.
# a stray "voice"/"op" row from data collected before this was tightened)
# are dropped rather than coerced, to avoid manufacturing a label.
_V1_VALID_ACTIONS = {"allow", "warn", "kick", "ban"}


def upcast_v1(record: dict) -> Optional[TrainingRow]:
    """Convert one Eggdrop v1 record into a TrainingRow, or None if it
    can't be interpreted (missing required field, or an action outside
    the known v1 vocabulary).

    `kick` is folded into `ban` for the 3-class taxonomy (kick is handled
    as rule-based warn-count escalation, not an ML class — see
    features.ACTIONS) rather than dropped, since a kick was still a real
    "this needed enforcement" signal.
    """
    action = record.get("action")
    if action not in _V1_VALID_ACTIONS:
        return None
    if action == "kick":
        action = "ban"

    try:
        nick = str(record["nick"])
        ident = str(record["ident"])
        host = str(record["host"])
    except KeyError:
        return None

    in_global_bad = bool(record.get("in_global_bad", False))
    return TrainingRow(
        nick=nick,
        ident=ident,
        host=host,
        join_rate=float(record.get("join_rate", 0) or 0),
        account_present=False,  # Eggdrop/Tcl never saw IRCv3 account tags
        cross_chan_count=int(record.get("cross_chan_count", 0) or 0),
        action=action,
        source="eggdrop-v1",
        # See features.py module docstring: in_global_bad was set for a
        # host *before* the training row for that same decision was
        # written, so any row where it was true may have taken a
        # short-circuit "already known bad" code path rather than a
        # genuine independent decision. Rows where it's false are clean.
        label_quality="leaked" if in_global_bad else "ok",
    )


def _corrected_v2_action(record: dict, action: str) -> str:
    """Applies the 2026-08-10 hard/soft evidence correction (see module
    docstring) to a single row's label, if it applies. Only the
    escalation path (`evidence_corroborated_escalation`) could ever have
    produced a geo_proxy-only `ban` historically -- the downgrade gate's
    "corroborates" branch was a plain pass-through before this fix (no
    `gate_rule` recorded for it at all), and it's structurally
    unreachable anyway before this date (the classifier has never once
    crossed `thresholds.classifier_act` live, so `_apply_gate` was never
    invoked on a real non-degraded ban) -- so this is the only historical
    rule string that needs the check.
    """
    if action != "ban":
        return action
    gate = record.get("gate") or {}
    if gate.get("rule") != "evidence_corroborated_escalation":
        return action
    ev = _evidence.HostEvidence.from_dict(record.get("evidence") or {})
    if ev.hard_corroborates_bad():
        return action
    return "warn"


def upcast_v2(record: dict) -> Optional[TrainingRow]:
    """Convert one Limnoria v2 shadow record (written by
    plugins/Shild/collector.py, built in M4) into a TrainingRow."""
    fused = record.get("fused") or {}
    action = fused.get("action")
    if action not in ("allow", "warn", "ban"):
        return None
    action = _corrected_v2_action(record, action)
    ctx = record.get("context") or {}
    try:
        nick = str(record["nick"])
        ident = str(record["ident"])
        host = str(record["host"])
    except KeyError:
        return None

    quality = record.get("label_quality", "ok")
    if record.get("would_have_acted") is False and action != "allow":
        # Fused decision said act, but the record says it wouldn't have —
        # inconsistent record, don't trust the label.
        quality = "unusable"

    return TrainingRow(
        nick=nick,
        ident=ident,
        host=host,
        join_rate=float(ctx.get("join_rate", 0) or 0),
        account_present=bool(record.get("account") or ctx.get("account_present", False)),
        cross_chan_count=int(ctx.get("cross_chan_count", 0) or 0),
        action=action,
        source="limnoria-shadow-v2",
        label_quality=quality,
    )


def load_training_rows(
    *paths: str | Path, include_leaked: bool = False
) -> list[TrainingRow]:
    """Load and upcast every row from the given JSONL files (mixing v1 and
    v2 freely — each record is auto-detected by shape). Rows with
    label_quality in {"leaked"} are excluded unless include_leaked=True;
    "unusable" and "ignored" rows are always excluded regardless of that
    flag: "unusable" comes from degraded/failed decisions (see fusion.py),
    "ignored" (added 2026-08-10) comes from an admin ignore-list override
    (fusion.ignored_bypass) — neither carries a trustworthy label, and an
    ignored host's real behavior may look nothing like a genuine "allow".
    """
    rows: list[TrainingRow] = []
    for path in paths:
        for raw in read_jsonl(path):
            row = upcast_v2(raw) if "fused" in raw else upcast_v1(raw)
            if row is None:
                continue
            if row.label_quality in ("unusable", "ignored"):
                continue
            if row.label_quality == "leaked" and not include_leaked:
                continue
            rows.append(row)
    return rows
