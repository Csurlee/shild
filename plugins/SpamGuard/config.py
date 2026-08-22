"""Config registry for SpamGuard.

Word/phrase/pattern lists and the join-window/exemption values are plain
registerGlobalValue -- global values have no per-channel override for an
op to set in the first place (opSettable only applies to
registerChannelValue, e.g. "enabled" below), so a channel op can never
loosen what counts as spam or shrink the join window regardless. Real,
global admin decisions only -- see plugins/Shild/config.py's own module
docstring for the same reasoning applied to its own global values.
"""
from __future__ import annotations

from supybot import conf, registry

try:
    from supybot.i18n import PluginInternationalization
    _ = PluginInternationalization("SpamGuard")
except ImportError:
    _ = lambda x: x  # noqa: E731


def configure(advanced):
    conf.registerPlugin("SpamGuard", True)


SpamGuard = conf.registerPlugin("SpamGuard")

conf.registerChannelValue(
    SpamGuard, "enabled",
    registry.Boolean(False, _(
        """Whether SpamGuard watches this channel's messages at all.
        Opt-in per channel, like Shild's own "enabled" -- never active on
        a channel just because the plugin is loaded.""")),
    opSettable=False,
)

# ---------------------------------------------------------------------
# LEGACY, migration-only (2026-08-10): these six flat lists used to be
# the live source of truth for every matched category. As of the
# id-keyed TermStore (terms.py), they are read exactly ONCE -- at
# __init__, only when the term store is still completely empty (see
# plugin.py's _migrate_legacy_registry_terms) -- to seed the store from
# whatever was already configured, then never consulted again. Left
# registered (rather than deleted outright) so that migration path keeps
# working and so scripts/bootstrap_runtime.py's SPAMGUARD_WORDS seeding
# still has somewhere to write for a brand-new deployment. Do NOT add a
# new word/pattern/etc here expecting it to take effect live -- use
# `spamguard <category> add <term>` (or `spamguard pattern add <regex>`),
# which write straight into the persisted, id-keyed term store
# (termsPath below) instead.
# ---------------------------------------------------------------------
conf.registerGlobalValue(
    SpamGuard, "words",
    registry.SpaceSeparatedListOfStrings([], _(
        """LEGACY, migration-only -- see the module comment above. Use
        `spamguard word add <term>` instead of setting this directly.""")),
)
conf.registerGlobalValue(
    SpamGuard, "phrases",
    registry.CommaSeparatedListOfStrings([], _(
        """LEGACY, migration-only -- see the module comment above. Use
        `spamguard word add "a phrase"` instead of setting this directly.""")),
)
conf.registerGlobalValue(
    SpamGuard, "patterns",
    registry.CommaSeparatedListOfStrings([], _(
        """LEGACY, migration-only -- see the module comment above. Use
        `spamguard pattern add <regex>` instead of setting this directly.""")),
)
conf.registerGlobalValue(
    SpamGuard, "identWords",
    registry.SpaceSeparatedListOfStrings([], _(
        """LEGACY, migration-only -- see the module comment above. Use
        `spamguard ident add <term>` instead of setting this directly.""")),
)
conf.registerGlobalValue(
    SpamGuard, "realnameWords",
    registry.SpaceSeparatedListOfStrings([], _(
        """LEGACY, migration-only -- see the module comment above. Use
        `spamguard realname add <term>` instead of setting this directly.""")),
)
conf.registerGlobalValue(
    SpamGuard, "realnamePhrases",
    registry.CommaSeparatedListOfStrings([], _(
        """LEGACY, migration-only -- see the module comment above. Use
        `spamguard realname add "a phrase"` instead of setting this
        directly. IMPORTANT (kept from the pre-migration docstring,
        still true): a joining user's realname field is ONLY available
        when the server negotiated the IRCv3 "extended-join" capability
        (Limnoria requests it automatically, but not every ircd supports
        it -- confirmed 2026-08-10 this needs live verification per
        network, see CLAUDE.md). If extended-join isn't active, realname
        matching silently never fires for that network -- not an error,
        just no data to check.""")),
)

conf.registerGlobalValue(
    SpamGuard, "termsPath",
    registry.String("data/spamguard_terms.json", _(
        """Path to the persisted, id-keyed term store (every configured
        word/phrase/pattern/ident/realname entry, each with a permanent
        numeric id -- see terms.py) -- this, not the legacy lists above,
        is the actual live source of truth for matching as of
        2026-08-10. Resolved relative to the bot's own working directory
        (runtime/), matching every other JSON/JSONL path in this
        deployment -- do NOT prefix with "runtime/" (see Shild's
        budgetPath/secretsPath docstrings for the double-"runtime/" bug
        this exact mistake caused there). Unlike the old registry lists,
        this file is NOT wiped by a scripts/bootstrap_runtime.py regen
        (it isn't part of the Limnoria registry at all), so terms added
        live via `spamguard <category> add` survive a regen with no
        script edit needed.""")),
)

conf.registerGlobalValue(
    SpamGuard, "hostBansPath",
    registry.String("data/spamguard_host_bans.json", _(
        """Path to the persisted host/IP ban history (hostbans.py) --
        auto-populated every time a real, HOST-based enforcement fires
        (never an ident- or nick-field match, which already target
        something narrower and more durable than a host). Resolved
        relative to the bot's own working directory (runtime/), same
        convention as termsPath -- do NOT prefix with "runtime/" (see
        Shild's budgetPath/secretsPath docstrings for the double-
        "runtime/" bug this exact mistake caused elsewhere). Recording
        into this file always happens regardless of
        hostBanAutoRebanEnabled below -- only the real auto-reban ACTION
        is gated by that switch.""")),
)
conf.registerGlobalValue(
    SpamGuard, "hostBanAutoRebanEnabled",
    registry.Boolean(False, _(
        """Master arm switch (2026-08-22) for automatically re-banning a
        host that's already in the persisted host-ban history
        (hostBansPath) the moment it rejoins under ANY nick/ident/
        realname, using the exact original kick message -- rather than
        needing a fresh term match every time. Default False, off until
        deliberately armed: recording into the store is always on and
        harmless (watch it fill in via `spamguardhostbans` first), but
        real auto-reban is a new, automatic enforcement path and gets
        the same staged-rollout treatment as everything else in this
        plugin that changes real enforcement behavior. Only ever fires
        for a rejoining identity whose ident is ALSO unverified (leading
        `~`) -- see enforcement.py's ban_mask() docstring; a rejoin with
        a real ident server is left alone entirely, by design.""")),
)
conf.registerGlobalValue(
    SpamGuard, "hostBanRetentionDays",
    registry.PositiveInteger(30, _(
        """How many days of inactivity before a persisted host-ban
        record stops being eligible to trigger an auto-reban. Refreshed
        on every hit (a fresh match OR a reban both count), so a repeat
        offender stays flagged indefinitely -- this only ages out a host
        that hasn't been seen in a long time, protecting against a
        dynamic/residential IP later being reassigned by its ISP to a
        completely unrelated, innocent person. An expired record is
        still visible in `spamguardhostbans` output (kept until the next
        prune sweep, see hostBanPruneIntervalSecs) but will not fire.""")),
)
conf.registerGlobalValue(
    SpamGuard, "hostBanPruneIntervalSecs",
    registry.PositiveInteger(3600, _(
        """How often (seconds) a background sweep actually deletes
        host-ban records past hostBanRetentionDays from the persisted
        file, so it doesn't grow unbounded with ancient, already-inert
        entries. Purely storage hygiene -- get()'s own expiry check
        already refuses to act on an expired record between sweeps.""")),
)

conf.registerGlobalValue(
    SpamGuard, "joinWindowSecs",
    registry.PositiveInteger(60, _(
        """Only messages sent within this many seconds of a tracked join
        are eligible to trigger a real kick+ban -- this is what limits
        SpamGuard to the "bot joins, immediately pastes a template"
        pattern it was built for, rather than punishing an established
        regular who happens to type a matched word. A match outside the
        window is still logged/relayed, just never acted on.""")),
)

conf.registerGlobalValue(
    SpamGuard, "exemptRegistered",
    registry.Boolean(True, _(
        """Whether a message from any ircdb-registered user (recognized
        via their hostmask, regardless of capability) is exempt from
        enforcement -- on top of the always-exempt cases (channel
        halfop+, or holding this channel's own "op" ircdb capability).
        A real spam bot is essentially never a registered user of this
        bot, so this mainly protects a legitimate regular who happens to
        type a matched word before their join-window exemption would
        otherwise apply on its own.""")),
)

conf.registerGlobalValue(
    SpamGuard, "logPath",
    registry.String("data/spamguard_actions.jsonl", _(
        """Path to the JSONL log of every match SpamGuard sees -- acted on
        or not, with a reason tag either way (killswitch/not-opped/
        outside-window/exempt/enforced). Resolved relative to the bot's
        own working directory (runtime/), matching every other JSONL log
        path in this deployment -- do NOT prefix with "runtime/" (see
        Shild's budgetPath/secretsPath docstrings for the double-
        "runtime/" bug this exact mistake caused there).""")),
)

# Network-specific, same reasoning as Shild's relayChannel: a match found
# on one network must never be announced to a channel on a different
# network by accident.
conf.registerNetworkValue(
    SpamGuard, "relayChannel",
    registry.String("", _(
        """Channel to relay SpamGuard match notices to. Empty disables
        relaying (the JSONL log is still written either way).""")),
)

# ---------------------------------------------------------------------
# Protection: real enforcement (kick+ban), gated by actually holding op
# in the channel (see enforcement.py::is_opped) AND this kill switch.
# Deliberately SEPARATE from Shild's protection.killSwitch -- see
# CLAUDE.md's SpamGuard section for why: this is a simple, deterministic
# content match with a much lower false-positive surface than Shild's
# ML/evidence pipeline, and the user wanted the ability to arm one
# independently of the other.
# ---------------------------------------------------------------------

conf.registerGroup(SpamGuard, "protection")
conf.registerGlobalValue(
    SpamGuard.protection, "killSwitch",
    registry.Boolean(True, _(
        """Global override: when True (the default), SpamGuard NEVER
        takes a real enforcement action anywhere, regardless of op
        status. Must be deliberately set False before any real kick/ban
        can happen. Matching/logging/relay above is entirely unaffected
        either way. Independent of Shild's own protection.killSwitch --
        flipping one does not arm the other.""")),
)
conf.registerGlobalValue(
    SpamGuard.protection, "banDurationSecs",
    registry.PositiveInteger(3600, _(
        """How long (seconds) a real ban set by SpamGuard lasts before
        being automatically lifted. Matches Shild's own default.""")),
)
conf.registerGlobalValue(
    SpamGuard.protection, "kickReason",
    registry.String("You are not welcome here!", _(
        """Default reason text shown in the kick message, same role as
        Armour/idefix's own per-entry "(reason: ...)" text. May contain
        a literal {term} placeholder, which is substituted with the
        matched term's text (e.g. "Blacklisted: {term}"); a value with no
        {term} placeholder is used as-is. An unrelated stray '{' (a typo,
        not a real placeholder) falls back to the raw value rather than
        erroring. The full kick reason plugin.py actually sends is built
        as 'SpamGuard: "<term>" - <nick>!<ident>@<host> - reason: <this
        value, with {term} substituted> - [id: <term id>]' -- not just
        this string alone -- so the matched term, the exact connecting
        hostmask, and the permanent term id are always visible in the
        channel, not only in the JSONL log/relay line. The hostmask shown
        here is NOT necessarily the ban mask actually set (an ident-field
        match bans *!<ident>@*, not this specific host) -- check /mode +b
        live for the real active mask. There is no separate ban-message
        value: IRC's MODE +b carries no text reason field at all, only
        the kick does.""")),
)

# ---------------------------------------------------------------------
# Message heuristics (2026-08-14): flood, mass nick-highlight, excessive
# caps, and mojibake/garbled-encoding -- non-term, threshold-based
# detectors adapted from ideas in Libera Chat's own `ozone` network-abuse
# bot (see plugin.py's _check_heuristics and heuristics.py/mojibake.py's
# own module docstrings). Unlike the term-based matchers above (implicitly
# off until a word/phrase/pattern is actually added), each of these is
# ALWAYS "live" the moment code exists to run it, so each gets its own
# per-channel enable (default off) as the equivalent safety property --
# same staged-rollout discipline as the original word-list rollout
# (CLAUDE.md's SpamGuard section): watch [spamguard] relay lines with the
# kill switch on before ever flipping enforcement live. The threshold
# VALUES themselves are global (not channel-settable), matching
# joinWindowSecs/exemptRegistered above -- real admin decisions only, a
# channel op can't loosen what counts as flood/caps/mojibake any more
# than they can edit the word list. None of the four require the join
# window (require_join_window=False, same treatment as ident/nick/
# realname) -- these are general per-message conduct signals, not the
# "bot joins and immediately pastes a template" pattern content matching
# targets specifically.
# ---------------------------------------------------------------------

conf.registerChannelValue(
    SpamGuard, "floodEnabled",
    registry.Boolean(False, _(
        """Whether the flood heuristic (floodMessageLimit messages from
        the same nick within floodWindowSecs) is checked in this
        channel. Opt-in, like `enabled` above -- see the module comment
        above this block for why each heuristic needs its own toggle.""")),
    opSettable=False,
)
conf.registerGlobalValue(
    SpamGuard, "floodMessageLimit",
    registry.PositiveInteger(5, _(
        """Number of messages from the same nick within floodWindowSecs
        that counts as flooding.""")),
)
conf.registerGlobalValue(
    SpamGuard, "floodWindowSecs",
    registry.PositiveFloat(8.0, _(
        """Rolling window (seconds) floodMessageLimit is counted over.""")),
)

conf.registerChannelValue(
    SpamGuard, "hilightEnabled",
    registry.Boolean(False, _(
        """Whether the mass-highlight heuristic (a single message naming
        hilightNickLimit or more distinct real channel members by nick)
        is checked in this channel -- classic raid-bot behavior (ping as
        many real users as possible in one message). Opt-in, same
        reasoning as floodEnabled above.""")),
    opSettable=False,
)
conf.registerGlobalValue(
    SpamGuard, "hilightNickLimit",
    registry.PositiveInteger(4, _(
        """Number of distinct real channel members named by nick in one
        message that counts as a mass-highlight.""")),
)
conf.registerGlobalValue(
    SpamGuard, "hilightMinNickLen",
    registry.PositiveInteger(3, _(
        """Nicks shorter than this are never counted toward
        hilightNickLimit -- a 1-2 character nick is common enough as an
        ordinary word/word-fragment substring that counting it would
        trigger on completely unrelated chatter.""")),
)

conf.registerChannelValue(
    SpamGuard, "capsEnabled",
    registry.Boolean(False, _(
        """Whether the excessive-caps heuristic (capsPercent or more of
        a message's letters in uppercase, once it's at least
        capsMinLength characters) is checked in this channel. Opt-in,
        same reasoning as floodEnabled above.""")),
    opSettable=False,
)
conf.registerGlobalValue(
    SpamGuard, "capsPercent",
    registry.Probability(0.70, _(
        """Fraction (0.0-1.0) of a message's LETTERS (not its total
        length -- punctuation/digits/links never count either way) that
        must be uppercase to trigger.""")),
)
conf.registerGlobalValue(
    SpamGuard, "capsMinLength",
    registry.PositiveInteger(10, _(
        """Messages shorter than this (characters) are never checked for
        excessive caps -- a short message like "OK" or "NO" is
        legitimately all-caps far more often than it's abuse.""")),
)

conf.registerChannelValue(
    SpamGuard, "mojibakeEnabled",
    registry.Boolean(False, _(
        """Whether the mojibake (garbled character-encoding) heuristic
        is checked in this channel -- see mojibake.py's module docstring
        for what it actually detects (vendored from Libera Chat's ozone
        bot, itself vendored from python-ftfy under the MIT license).
        Opt-in, same reasoning as floodEnabled above.""")),
    opSettable=False,
)
conf.registerGlobalValue(
    SpamGuard, "mojibakeScore",
    registry.PositiveInteger(2, _(
        """mojibake.mojibake_score() value at or above which a message
        triggers -- a score counts unlikely character-sequence
        juxtapositions, so even 1-2 can be a real signal in an otherwise
        clean message; not a percentage.""")),
)

# ---------------------------------------------------------------------
# Raid heuristic (2026-08-16): distinct-nick join-burst detection, adapted
# from the "grouped flood" idea in progval's AttackProtector plugin
# (github.com/progval/Supybot-plugins/tree/master/AttackProtector) --
# reimplemented independently, not vendored (that plugin is 2010-era
# Python 2-flavored code). Checked in doJoin, not doPrivmsg -- see
# _check_join_heuristics in plugin.py. Enforces against only the ONE
# joiner who tips the count over raidJoinLimit, not the whole burst --
# same "act on the current event" convention as flood/hilight/caps/
# mojibake above, and deliberately conservative: a real netsplit-
# reconnect burst of legitimate returning regulars looks identical at
# the network level to a coordinated raid (confirmed via a real corpus
# check during Shild's own join_rate feature design, 2026-08-14 -- see
# CLAUDE.md), so raidJoinLimit defaults meaningfully higher than a
# single-nick flood threshold and this still funnels through the SAME
# exemption/killSwitch/op gate chain as every other heuristic --
# nothing here bypasses that safety net.
# ---------------------------------------------------------------------

conf.registerChannelValue(
    SpamGuard, "raidEnabled",
    registry.Boolean(False, _(
        """Whether the raid heuristic (raidJoinLimit distinct nicks
        joining this channel within raidWindowSecs) is checked. Opt-in,
        same reasoning as floodEnabled above -- and worth extra caution
        before enabling: a legitimate netsplit-reconnect burst of real
        regulars can look similar to a coordinated raid at the network
        level.""")),
    opSettable=False,
)
conf.registerGlobalValue(
    SpamGuard, "raidJoinLimit",
    registry.PositiveInteger(8, _(
        """Number of DISTINCT nicks joining this channel within
        raidWindowSecs that counts as a raid. Deliberately higher than
        floodMessageLimit -- a grouped/coordinated signal should need
        more corroboration than a single nick's own behavior before
        anyone gets kicked over it.""")),
)
conf.registerGlobalValue(
    SpamGuard, "raidWindowSecs",
    registry.PositiveFloat(15.0, _(
        """Rolling window (seconds) raidJoinLimit is counted over.""")),
)
