"""WebPanel: a LAN-only, authenticated web dashboard for shild-py --
ZNC-style overview/stats/logs/live-preview/commands pages over data
Shild/ChannelStats/ChannelLogger already produce, plus (2026-08-24) a
small, explicitly allowlisted write surface. See plugin.py's module
docstring for the full read/write boundary.
"""

import supybot
from supybot import world

__version__ = "1.13"
__author__ = supybot.authors.unknown
__contributors__ = {}
__url__ = "https://github.com/Csurlee/shild"

from . import auth
from . import secrets
from . import logs
from . import render
from . import stats
from . import csrf
from . import controls
from . import audit
from . import config
from . import http
from . import plugin
from importlib import reload

# @reload WebPanel only re-executes this package's own module tree, not
# anything imported the normal top-level way (see CLAUDE.md's
# "@reload Shild does NOT reimport shildml" gotcha). The subtler version
# of the same bug: http.py does `from . import logs, render` at ITS OWN
# top level, but Python's reload() of http.py does NOT transitively
# reload modules http.py merely imports -- it just re-binds the name to
# whatever's already in sys.modules. So logs.py/render.py/stats.py must
# each be reload()ed explicitly HERE too, in dependency order (before
# http, which imports them), or a reload would keep serving stale code
# for them while looking like it worked. csrf.py/controls.py/audit.py
# (2026-08-24) are the same "new submodule reload-list gotcha" applied
# to the new write-support modules -- added here in the SAME change that
# introduced them, not after the fact.
reload(auth)
reload(secrets)
reload(logs)
reload(render)
reload(stats)
reload(csrf)
reload(controls)
reload(audit)
reload(config)
reload(http)
reload(plugin)

if world.testing:
    from . import test

Class = plugin.Class
configure = config.configure
