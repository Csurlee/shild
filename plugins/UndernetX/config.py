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
    registry.NonNegativeInteger(0, _(
        """Default access-level argument passed to "xban" when omitted
        -- the minimum access level EXEMPT from the ban (0 exempts no
        one). Under-documented by X itself as of this writing -- see
        xcommands.py's module docstring -- verify against a live
        "/msg X help ban" before relying on a non-default value for
        anything but a supervised, manual ban.""")),
)

conf.registerGroup(UndernetX, "enforcement")
conf.registerChannelValue(
    UndernetX.enforcement,
    "preferXCommands",
    registry.Boolean(False, _(
        """Whether THIS channel's moderation should prefer routing
        through X (e.g. "/msg X ban #chan host" instead of a raw
        MODE +b) when the bot holds sufficient X access, rather than
        Limnoria's own IRC-native MODE/KICK. Not op-settable -- same
        reasoning as every other enforcement-adjacent switch in this
        deployment (Shild.enabled, SpamGuard.enabled): a channel op
        should not unilaterally change how the bot moderates.

        As of 2026-08-14 this value is inspectable and settable but has
        NO consumer yet -- Shild's and SpamGuard's own enforcement.py
        modules don't read it. It exists now (readable via
        UndernetX.prefers_x_commands(irc, channel)) so a follow-up that
        wires it into their real kick/ban paths doesn't need to
        redesign this seam, only call it.""")),
    opSettable=False,
)

# vim:set shiftwidth=4 tabstop=4 expandtab textwidth=79:
