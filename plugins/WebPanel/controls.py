"""Pure allowlist tables + registry-safety helpers for WebPanel's write
routes (2026-08-24). No supybot import -- unit-testable with plain
pytest against fake node objects, no IRC harness needed. See http.py for
how these compose into the actual routes, and CLAUDE.md's WebPanel
section for the full design writeup.

**Why this file exists, not a generic "set any registry key" form**: the
whole write surface IS this allowlist -- `GLOBAL_SWITCHES` (3 entries)
and `CHANNEL_TOGGLES` (13 entries) are the complete, exhaustive, hardcoded
set of registry paths any WebPanel POST route is ever allowed to touch.
There is no code path anywhere in this plugin that accepts an arbitrary
registry key string from a request and writes it -- see the original
"Deliberately read-only" design note this change closes out (still
readable in git history / CLAUDE.md) for exactly which keys
(`protection.killSwitch`, `ollama.url` (SSRF), `Shild.enabled`) a naive
version of this feature would have dangerously exposed.

**Why the per-channel read/write helpers exist at all, instead of just
calling `registry.Value.getSpecific()`/`Config.channel`'s own dual-write
directly**: both of those CREATE a registry node as a side effect of
being called (`Value._makeChild`, confirmed in supybot/registry.py --
its own comment there literally warns this can "leak megabytes of memory
a week" if called with high-cardinality input). That's an accepted cost
when it only ever happens on Limnoria's single main IRC thread. It is
NOT safe from a second thread: `registry.close()` (run from the main
thread on flush/shutdown) does `self._added.sort()` then iterates
`self._added`/`self._children` -- concurrent `list.append()`/dict-insert
from a node-creating read or write on the HTTP thread races that,
worst-case silently dropping the config write-back at the exact moment
(shutdown) an admin's change most needs to survive. `peek_channel_value`
NEVER creates a node (walks `._children` directly); `write_channel_value`
REFUSES to write unless both target nodes already exist
(`channel_nodes_ready`); `warm_channel_nodes` is the only function here
that creates a node, and it's called ONLY from a periodic main-thread
event in plugin.py, never from the HTTP thread.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class GlobalSwitch:
    key: str
    plugin: str
    path: tuple[str, ...]
    label: str
    # Whether `True` for this switch means "armed/enforcing" (like
    # UndernetX's xFallbackEnabled) as opposed to "safe/inert" (like both
    # killSwitches, where True means enforcement is DISABLED). Rendered
    # as two structurally separate sections in render.controls_overview
    # -- see this module's own tests for the pin that all three switches'
    # values are exactly what's expected, so the UI can never conflate
    # the two polarities under one generic "toggle" label.
    true_means_armed: bool
    true_state_label: str
    false_state_label: str
    to_true_action_label: str
    to_false_action_label: str
    # The boolean VALUE that, if this switch is being set TO it, is the
    # enforcement-increasing direction and therefore requires the
    # "yes, I understand" confirmation checkbox. The opposite direction
    # (making things safer) never requires it.
    dangerous_value: bool


GLOBAL_SWITCHES: tuple[GlobalSwitch, ...] = (
    GlobalSwitch(
        key="shild_kill_switch",
        plugin="Shild",
        path=("protection", "killSwitch"),
        label="Shild enforcement kill switch",
        true_means_armed=False,
        true_state_label="Safe (kill switch engaged)",
        false_state_label="ARMED (kill switch disengaged)",
        to_true_action_label="Engage kill switch (make safe)",
        to_false_action_label="Disengage kill switch (arm enforcement)",
        dangerous_value=False,
    ),
    GlobalSwitch(
        key="spamguard_kill_switch",
        plugin="SpamGuard",
        path=("protection", "killSwitch"),
        label="SpamGuard enforcement kill switch",
        true_means_armed=False,
        true_state_label="Safe (kill switch engaged)",
        false_state_label="ARMED (kill switch disengaged)",
        to_true_action_label="Engage kill switch (make safe)",
        to_false_action_label="Disengage kill switch (arm enforcement)",
        dangerous_value=False,
    ),
    GlobalSwitch(
        key="undernetx_x_fallback",
        plugin="UndernetX",
        path=("enforcement", "xFallbackEnabled"),
        label="UndernetX X-routed enforcement fallback",
        true_means_armed=True,
        true_state_label="ARMED (X-fallback enabled)",
        false_state_label="Inert (X-fallback disabled)",
        to_true_action_label="Enable X-fallback (arm)",
        to_false_action_label="Disable X-fallback (make inert)",
        dangerous_value=True,
    ),
)

_GLOBAL_SWITCHES_BY_KEY = {s.key: s for s in GLOBAL_SWITCHES}


def global_switch_by_key(key: str) -> Optional[GlobalSwitch]:
    return _GLOBAL_SWITCHES_BY_KEY.get(key)


@dataclass(frozen=True)
class ChannelToggle:
    key: str
    plugin: str
    path: tuple[str, ...]
    label: str
    help: str


# All 13 opSettable=False per-channel values across Shild/SpamGuard/
# UndernetX -- the same set plugins/Shild/plugin.py's `shildconfig`
# command reports (including `quitPartEnabled`, which shildconfig itself
# was found to be missing during this same change and fixed alongside
# it -- see CLAUDE.md).
CHANNEL_TOGGLES: tuple[ChannelToggle, ...] = (
    ChannelToggle("shild_enabled", "Shild", ("enabled",),
                  "Shild: analyze joins", "Runs the classifier+evidence pipeline on every join."),
    ChannelToggle("shild_message_analysis", "Shild", ("messageAnalysis",),
                  "Shild: analyze messages", "Also analyzes channel messages, not just joins."),
    ChannelToggle("spamguard_enabled", "SpamGuard", ("enabled",),
                  "SpamGuard: enabled", "Master switch for every SpamGuard check in this channel."),
    ChannelToggle("spamguard_flood", "SpamGuard", ("floodEnabled",),
                  "SpamGuard: flood heuristic", "Same nick posting many messages quickly."),
    ChannelToggle("spamguard_hilight", "SpamGuard", ("hilightEnabled",),
                  "SpamGuard: hilight heuristic", "One message naming many real channel members."),
    ChannelToggle("spamguard_caps", "SpamGuard", ("capsEnabled",),
                  "SpamGuard: caps heuristic", "Message mostly in uppercase letters."),
    ChannelToggle("spamguard_mojibake", "SpamGuard", ("mojibakeEnabled",),
                  "SpamGuard: mojibake heuristic", "Garbled-encoding detection."),
    ChannelToggle("spamguard_raid", "SpamGuard", ("raidEnabled",),
                  "SpamGuard: raid heuristic", "Many distinct nicks joining in a short window."),
    ChannelToggle("spamguard_group_flood", "SpamGuard", ("groupFloodEnabled",),
                  "SpamGuard: group-flood heuristic",
                  "Many distinct nicks each posting once in a short window."),
    ChannelToggle("spamguard_repeat_chars", "SpamGuard", ("repeatCharsEnabled",),
                  "SpamGuard: repeat-chars heuristic", "A single character repeated many times."),
    ChannelToggle("spamguard_quit_part", "SpamGuard", ("quitPartEnabled",),
                  "SpamGuard: QUIT/PART observation",
                  "Checks leave-reason text against content terms (observe only, never enforces)."),
    ChannelToggle("spamguard_clone_scan", "SpamGuard", ("cloneScanEnabled",),
                  "SpamGuard: clone scan", "Periodic sweep for many nicks sharing one host."),
    ChannelToggle("undernetx_prefer_x", "UndernetX", ("enforcement", "preferXCommands"),
                  "UndernetX: prefer X commands",
                  "Route enforcement through Undernet's X service instead of native MODE/KICK."),
)

_CHANNEL_TOGGLES_BY_KEY = {t.key: t for t in CHANNEL_TOGGLES}


def channel_toggle_by_key(key: str) -> Optional[ChannelToggle]:
    return _CHANNEL_TOGGLES_BY_KEY.get(key)


def parse_bool(raw: Optional[str]) -> Optional[bool]:
    """Accepts only a fixed, unambiguous set of spellings -- returns
    None (meaning: reject this request) for anything else, INCLUDING
    "toggle", which `registry.Boolean.set()` itself would otherwise
    silently accept as "flip whatever the current value is" (a real
    footgun found while designing this: a form re-POSTed or replayed
    would then do something different each time rather than being
    idempotent). Deliberately does not call `.set()` on a registry node
    at all -- callers pass the resulting real Python bool to
    `.setValue()` instead."""
    if raw is None:
        return None
    v = raw.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return None


def peek_channel_value(node, network: str, channel: str) -> bool:
    """Non-creating read of a channel-specific (optionally network-
    qualified) registry Value -- replicates registry.Value.getSpecific()'s
    exact precedence (registry.py's own network+channel branch) WITHOUT
    ever calling `.get()`/`.getSpecific()`, both of which create a
    permanent child node as a side effect of merely being called. See
    this module's own docstring for why that's unsafe from the HTTP
    thread.

    Correct by construction even for a node that was never created: an
    unset child's effective value is kept continuously in sync with its
    parent by registry.py's own `_setValue` inheritance-propagation
    logic, so a would-be child that doesn't exist yet holds exactly the
    same value its nearest existing ancestor already reports.
    """
    children = node._children
    network_value = children.get(":" + network)
    network_channel_value = (
        network_value._children.get(channel) if network_value is not None else None
    )
    channel_value = children.get(channel)

    if network_value is not None and (
        network_value._wasSet
        or (network_channel_value is not None and network_channel_value._wasSet)
    ):
        target = network_channel_value if network_channel_value is not None else network_value
        return bool(target())
    if channel_value is not None and channel_value._wasSet:
        return bool(channel_value())
    if network_channel_value is not None:
        return bool(network_channel_value())
    if network_value is not None:
        return bool(network_value())
    return bool(node())


def channel_nodes_ready(node, network: str, channel: str) -> bool:
    """True only if BOTH the bare-channel node and the network-qualified
    channel node already exist -- the precondition write_channel_value
    requires before it will write anything at all."""
    children = node._children
    if channel not in children:
        return False
    network_value = children.get(":" + network)
    if network_value is None:
        return False
    return channel in network_value._children


def warm_channel_nodes(node, network: str, channel: str) -> None:
    """MAIN-THREAD ONLY. Forces creation of both nodes `write_channel_
    value` will need, via the normal (node-creating) `.get()` path --
    safe here specifically because this is only ever called from
    plugins/WebPanel/plugin.py's periodic main-thread warm event, never
    from the HTTP thread."""
    node.get(channel)
    node.get(":" + network).get(channel)


def write_channel_value(node, network: str, channel: str, value: bool) -> bool:
    """Writes BOTH the bare-channel node and the network-qualified node,
    mirroring the bundled Config plugin's own `channel` command (so a
    web-originated write behaves identically to `@config channel ...`,
    including the same precedence any future read of this value will
    see). Returns False (nothing written) if `channel_nodes_ready` is
    false -- this is what makes it structurally impossible for the HTTP
    thread to ever create a registry node itself; the admin retries after
    the next warm pass (at most `controlsWarmIntervalSecs` later)."""
    if not channel_nodes_ready(node, network, channel):
        return False
    node._children[channel].setValue(value)
    node._children[":" + network]._children[channel].setValue(value)
    return True


# Fixed message-code table for the post-redirect flash banner -- NEVER
# reflects raw request-controlled text back into the page (an attacker-
# crafted link like `?ok=Kill+switch+disarmed+successfully` is a real
# social-engineering primitive even with perfect HTML-escaping). `arg`
# is an optional, separately-escaped, length-capped detail (e.g. which
# channel) substituted into the template with plain str.format.
FLASH: dict[str, tuple[str, str]] = {
    "killswitch_set": ("ok", "Kill switch updated."),
    "channel_toggle_set": ("ok", "Channel setting for {arg} updated."),
    "ignore_added": ("ok", "{arg} added to the ignore list."),
    "ignore_removed": ("ok", "{arg} removed from the ignore list."),
    "term_added": ("ok", "Term added ({arg})."),
    "term_add_duplicate": ("ok", "Term already present ({arg})."),
    "term_removed": ("ok", "Term removed ({arg})."),
    "term_not_found": ("err", "No term found with that id."),
    "csrf_expired": ("err", "This form expired -- reload the page and try again."),
    "origin_rejected": ("err", "Request rejected (Origin/Referer check failed)."),
    "write_disabled": ("err", "Writing from the panel is currently disabled."),
    "plugin_not_loaded": ("err", "{arg} isn't loaded -- nothing to change."),
    "invalid_input": ("err", "That value wasn't understood ({arg})."),
    "channel_not_ready": ("err",
                           "This channel's settings aren't warmed up yet -- try again in a moment."),
    "ignore_needs_host": ("err",
                           "Enter a host/IP, not a nick -- use shildignore on IRC for nick lookup."),
    "ignore_not_found": ("err", "{arg} isn't on the ignore list."),
    "confirmation_required": ("err", "Check the confirmation box to make this change."),
}

_MAX_FLASH_ARG_LEN = 80


def flash_for(code: Optional[str], arg: Optional[str] = None) -> Optional[tuple[str, str]]:
    """Returns (level, message) for a known flash `code`, or None for an
    unrecognized one (the caller shows nothing rather than guess)."""
    if code is None:
        return None
    entry = FLASH.get(code)
    if entry is None:
        return None
    level, template = entry
    safe_arg = (arg or "")[:_MAX_FLASH_ARG_LEN]
    return level, template.format(arg=safe_arg)
