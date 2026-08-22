###
# Copyright (c) 2017, Ken Spencer
# Copyright (c) 2020, oddluck <oddluck@riseup.net>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   * Redistributions of source code must retain the above copyright notice,
#     this list of conditions, and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions, and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#   * Neither the name of the author of this software nor the name of
#     contributors to this software may be used to endorse or promote products
#     derived from this software without specific prior written consent.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
###

import supybot.conf as conf
import supybot.registry as registry
import supybot.ircutils as ircutils
from supybot.i18n import PluginInternationalization, internationalizeDocstring

_ = PluginInternationalization("UndernetX")


def configure(advanced):
    # This will be called by supybot to configure this module.  advanced is
    # a bool that specifies whether the user identified himself as an advanced
    # user or not.  You should effect your configuration by manipulating the
    # registry as appropriate.
    from supybot.questions import expect, anything, something, yn

    conf.registerPlugin("UndernetX", True)


UndernetX = conf.registerPlugin("UndernetX")
# This is where your configuration variables (if any) should go.  For example:
# conf.registerGlobalValue(UndernetX, 'someConfigVariableName',
#     registry.Boolean(False, _("""Help for someConfigVariableName.""")))
conf.registerGlobalValue(
    UndernetX,
    "modeXonID",
    registry.Boolean(True, _("""Whether or not to mode +x on ID""")),
)
conf.registerGroup(UndernetX, "auth")
# /msg X@channels.undernet.org login username password
conf.registerGlobalValue(
    UndernetX.auth, "username", registry.String("", _("""Username for X"""))
)
conf.registerGlobalValue(
    UndernetX.auth,
    "password",
    # private=True added 2026-08-14 -- was a plain String, visible in
    # cleartext to any @config reader (runtime/shildpy.conf is mode
    # 0664, world-readable -- see plugins/WebPanel/secrets.py's own
    # docstring, which names this exact value as an example of why).
    # Set this via the new "xsetpass" command, not @config directly --
    # see plugin.py's docstring on that command for why (it also prints
    # the runtime/secrets.json lines to paste in, so the value survives
    # a scripts/bootstrap_runtime.py regen).
    registry.String("", _("""Password for X"""), private=True),
)
conf.registerGlobalValue(
    UndernetX.auth,
    "xservice",
    registry.String("X@channels.undernet.org", _("""XService hostmask""")),
)
conf.registerGlobalValue(
    UndernetX.auth,
    "xserviceHostmask",
    registry.String("X!cservice@undernet.org", _(
        """The FULL hostmask (nick!ident@host) X authenticates from --
        deliberately more specific than "auth.xservice" (which is just
        where login/commands are SENT). doNotice only trusts a NOTICE as
        genuinely from X if its prefix matches this, which is what lets
        the bot detect and log a nick impersonating X (same nick,
        different real hostmask) rather than trusting anyone named
        "X".""")),
)
conf.registerGlobalValue(
    UndernetX.auth,
    "noJoinsUntilAuthed",
    registry.Boolean(True, _("""Don't join until we're authed.""")),
)

# -- shild-py additions below (2026-08-14) -- everything above this line
# is the original vendored oddluck/limnoria-plugins UndernetX config,
# left otherwise untouched; see plugin.py for the matching split.

conf.registerGroup(UndernetX, "commands")
conf.registerGlobalValue(
    UndernetX.commands,
    "replyTimeoutSecs",
    registry.PositiveInteger(10, _(
        """How long (seconds) an xban/xkick/xop/etc. command waits for a
        NOTICE reply from X before giving up and reporting "no reply".
        X gives no request id in its replies, so this is a best-effort
        FIFO correlation (see xcommands.PendingXRequestQueue's
        docstring) -- a long timeout just means a longer wait to notice
        X never actually responded (e.g. insufficient access).""")),
)
conf.registerGlobalValue(
    UndernetX.commands,
    "defaultBanDuration",
    registry.String("0d", _(
        """Default duration passed to "xban" when the command's own
        [duration] argument is omitted. "0d" is permanent; X accepts
        "5m" through "365d".""")),
)
conf.registerGlobalValue(
    UndernetX.commands,
    "defaultBanAccess",
    registry.NonNegativeInteger(75, _(
        """Default "banlevel" argument passed to "xban"/enforce_ban_via_x
        when omitted. CONFIRMED LIVE 2026-08-17 via "/msg X help ban"
        (the module's own earlier "access level exempt from the ban"
        guess was WRONG -- kept here as a historical note so a future
        edit doesn't reintroduce it): this is a BAN SEVERITY level, 1 to
        the bot's own X access level (100 in this deployment) --
        1-74 only prevents the target from getting ops; 75-500 removes
        them from the channel entirely (X auto-kicks anyone currently
        present who matches a 75+ ban). A level below 75 would silently
        never remove a spammer/abuser at all. 0 (the old default) is
        flatly REJECTED by X ("Invalid banlevel range. Valid range is
        1-100") -- confirmed live the same day as a real incident: every
        X-routed ban was failing outright, so only the separate explicit
        KICK ever actually removed anyone. 75 is X's own stated default
        when the level argument is omitted entirely (per its help text),
        and is the lowest level that actually accomplishes real removal
        -- deliberately not maxed at 100, which would only matter if this
        bot's own account needed to out-rank another automated banner's
        level, not a concern here.""")),
)

conf.registerGroup(UndernetX, "enforcement")
conf.registerChannelValue(
    UndernetX.enforcement,
    "preferXCommands",
    registry.Boolean(False, _(
        """Whether THIS channel opts in to the X-routed enforcement
        FALLBACK: when Shild/SpamGuard want to kick+ban here but the bot
        doesn't hold real IRC op, should it try routing the action
        through X (e.g. "/msg X ban #chan host") instead of doing
        nothing. Not op-settable -- same reasoning as every other
        enforcement-adjacent switch in this deployment (Shild.enabled,
        SpamGuard.enabled): a channel op should not unilaterally change
        how the bot moderates.

        As of 2026-08-16 this has a real consumer: Shild's and
        SpamGuard's enforcement paths call
        UndernetX.x_enforcement_available(irc, channel), which requires
        this AND enforcement.xFallbackEnabled AND a live-verified,
        cached probe result confirming X actually manages this channel
        and the bot has enough access there -- opting in here alone does
        NOT arm anything by itself; see enforcement.xFallbackEnabled's
        own docstring and docs/UNDERNETX.md's "X-routed enforcement
        fallback" section for the required rollout/verification steps
        before setting this True anywhere live. When it IS true, the bot
        also periodically probes this channel's X access in the
        background (on join, on a fresh X login, and lazily as needed)
        so a verdict is ready before it's ever needed -- an opted-out
        channel generates zero X traffic for this feature.""")),
    opSettable=False,
)
conf.registerGlobalValue(
    UndernetX.enforcement,
    "xFallbackEnabled",
    registry.Boolean(False, _(
        """Master arm switch for the entire X-routed enforcement
        fallback feature (2026-08-16). Defaults False -- the feature
        ships fully wired but completely inert until this is flipped,
        deliberately separate from the per-channel
        enforcement.preferXCommands opt-in: the risk this switch guards
        against is CODE-shaped (the X ACCESS-reply classifier in
        xprobe.py is NOT verified against a live "channel not
        registered with X" or a live successful access-level reply --
        only scraped from general X documentation, plus one confirmed
        string, "No Match!"), not per-channel, so one global flip
        should be enough to back the whole thing out under a live
        incident rather than needing to walk every opted-in channel one
        by one -- same shape as protection.killSwitch elsewhere in this
        deployment. Do NOT enable before completing the live
        verification procedure in docs/UNDERNETX.md's "X-routed
        enforcement fallback" section. Even when True, a channel with
        no real X presence still resolves to "unusable" and behaves
        exactly like today (log-only, no action) -- this switch only
        permits the FEATURE to run, it never bypasses the per-channel
        availability check itself.""")),
)
conf.registerGlobalValue(
    UndernetX.enforcement,
    "minAccessLevel",
    registry.NonNegativeInteger(100, _(
        """Minimum X access level the capability probe must see for the
        bot's own username in a channel before that channel counts as
        usable for X-routed enforcement. 100 is X's documented
        op-granting access level, which comfortably implies ban/kick
        authority -- but this is UNVERIFIED against a live ACCESS reply
        for this deployment's actual account, same caveat as
        commands.defaultBanAccess. Confirm the real number your account
        shows (via "xaccess <#channel> =<botnick>" or the "xprobe"
        command) before relying on the default.""")),
)
conf.registerGlobalValue(
    UndernetX.enforcement,
    "probeTtlSecs",
    registry.PositiveInteger(3600, _(
        """How long (seconds) a capability-probe verdict is trusted
        before being treated as stale (and therefore unusable again,
        triggering a fresh probe on the next lazy check). Default 1h --
        long enough that a channel doesn't get re-probed constantly,
        short enough that a revoked X access level self-corrects within
        an hour even if nothing explicitly invalidates the cache
        sooner.""")),
)
conf.registerGlobalValue(
    UndernetX.enforcement,
    "probeMinIntervalSecs",
    registry.PositiveInteger(60, _(
        """Floor (seconds) between capability probes for the SAME
        channel, regardless of how many times it's asked about in that
        window -- prevents a burst of joins/enforcement misses on an
        unknown/stale channel from firing more than one ACCESS query at
        X per interval.""")),
)

# vim:set shiftwidth=4 tabstop=4 expandtab textwidth=79:
