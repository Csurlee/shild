"""Feature extraction for the SHILD classifier — v2.

v2 changes from the original Tcl-era classifier (~/shild-ai/features.py):
  - Dropped `in_global_bad`: in the old pipeline it was set to True for a
    host *before* the training label for that same ban decision was
    written, so it was a near-perfect proxy for the label (confirmed
    empirically: in_global_bad=True co-occurred with ban/kick 105/113
    times and allow 0 times). A feature set by the action you're trying
    to predict isn't a feature, it's a leaked label.
  - Added `account_present`: whether the sender has a services account
    (IRCv3 `account` tag) — a strong non-bot signal Eggdrop never saw.
  - Every feature is named (FEATURE_NAMES) and the whole schema is
    versioned+hashed (schema_hash()) so a trained model can refuse to
    load against a features.py it wasn't trained against, instead of
    silently producing garbage (see artifact.py).

Phase 1.5 adds shildml/evidence.py (DNSBL, IP reputation, cloak trust).
That evidence gates the fused decision that BECOMES the training label
(see fusion.decide / fusion._apply_gate), so it must never be added here
as a feature — doing so would be the exact same leak as the retired
in_global_bad, just with new field names. Evidence belongs in the Ollama
prompt and in the JSONL record for analysis, never in extract().
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from collections import Counter

FEATURE_VERSION = 2

ACTIONS = ["allow", "warn", "ban"]
ACTION_IDX = {a: i for i, a in enumerate(ACTIONS)}

CONSONANTS = set("bcdfghjklmnpqrstvwxyz")

DATACENTER_KEYWORDS = [
    "amazonaws", "linode", "digitalocean", "vultr", "ovh", "hetzner",
    "choopa", "psychz", "leaseweb", "nocix", "quadranet", "multacom",
    "colocation", "colo", "hosting", "vps", "cloud", "server", "node",
    "proxy", "tor-exit", "torexit", "exit-node", "datacenter",
    "data-center",
]

FEATURE_NAMES = [
    # nick (0-7)
    "nick_len_norm", "nick_entropy_norm", "nick_digit_frac",
    "nick_alpha_frac", "nick_is_alnum", "nick_trailing_digits3",
    "nick_consonant_frac", "nick_was_lowercase",
    # ident (8-11)
    "ident_len_norm", "ident_is_digit", "ident_entropy_norm",
    "ident_unresolved",
    # host (12-18)
    "host_is_raw_ip", "host_is_ipv6", "host_dot_count_norm",
    "host_len_norm", "host_entropy_norm", "host_is_datacenter",
    "host_embedded_ip",
    # context (19-21)
    "join_rate_norm", "account_present", "cross_chan_count_norm",
]

N_FEATURES = len(FEATURE_NAMES)


def _entropy(s: str) -> float:
    """Shannon entropy in bits, 0.0 for empty string."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _nick_features(nick: str) -> list[float]:
    n = nick.lower()
    ln = len(n)
    alpha = sum(c.isalpha() for c in n)
    digits = sum(c.isdigit() for c in n)
    consonants = sum(c in CONSONANTS for c in n)
    return [
        min(ln / 20, 1.0),
        min(_entropy(n) / 4, 1.0),
        digits / ln if ln else 0.0,
        alpha / ln if ln else 0.0,
        1.0 if n.isalnum() else 0.0,
        1.0 if re.search(r"\d{3,}$", n) else 0.0,
        consonants / alpha if alpha else 0.0,
        1.0 if nick == n else 0.0,  # nick was already all-lowercase
    ]


def _ident_features(ident: str) -> list[float]:
    i = ident.lstrip("~")
    ln = len(i)
    return [
        min(ln / 20, 1.0),
        1.0 if i.isdigit() else 0.0,
        min(_entropy(i) / 4, 1.0),
        1.0 if ident.startswith("~") else 0.0,
    ]


def _host_features(host: str) -> list[float]:
    is_ip = False
    is_ipv6 = False
    try:
        addr = ipaddress.ip_address(host)
        is_ip = True
        is_ipv6 = addr.version == 6
    except ValueError:
        pass
    h = host.lower()
    return [
        1.0 if is_ip else 0.0,
        1.0 if is_ipv6 else 0.0,
        min(host.count(".") / 5, 1.0),
        min(len(host) / 60, 1.0),
        min(_entropy(h) / 4, 1.0),
        1.0 if any(k in h for k in DATACENTER_KEYWORDS) else 0.0,
        1.0 if re.search(r"\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}", host) else 0.0,
    ]


def extract(
    nick: str,
    ident: str,
    host: str,
    join_rate: float = 0.0,
    account_present: bool = False,
    cross_chan_count: int = 0,
) -> list[float]:
    """Extract the fixed-order, fixed-length (N_FEATURES) feature vector.

    All inputs should be plain strings/numbers already resolved by the
    caller (e.g. plugins/Shild/context.py) — this function does no I/O and
    no IRC-specific parsing, which is what keeps it unit-testable and
    replayable offline.
    """
    vec: list[float] = []
    vec += _nick_features(nick)
    vec += _ident_features(ident)
    vec += _host_features(host)
    vec += [
        min(join_rate / 10, 1.0),
        1.0 if account_present else 0.0,
        min(cross_chan_count / 5, 1.0),
    ]
    assert len(vec) == N_FEATURES, f"expected {N_FEATURES} features, got {len(vec)}"
    return vec


def schema_hash() -> str:
    """Hash of everything that must match between a trained artifact and
    the running feature extractor. Bump FEATURE_VERSION on any change to
    the feature functions or extract()'s behavior, so old artifacts fail
    loudly (see artifact.py) instead of silently producing garbage.
    """
    payload = {
        "feature_version": FEATURE_VERSION,
        "feature_names": FEATURE_NAMES,
        "actions": ACTIONS,
        "datacenter_keywords": DATACENTER_KEYWORDS,
    }
    blob = json.dumps(payload, sort_keys=True).encode()
    return hashlib.sha256(blob).hexdigest()
