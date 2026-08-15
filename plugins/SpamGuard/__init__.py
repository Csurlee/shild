"""
SpamGuard: deterministic content-match kick+ban for spam bots that join
a channel and immediately paste a known template message. See plugin.py's
module docstring for the motivating example and design.
"""

import supybot
from supybot import world

__version__ = "1.2"
__author__ = supybot.authors.unknown
__contributors__ = {}
__url__ = "https://github.com/Csurlee/shild"

# Import every submodule and reload() it so `@reload SpamGuard` picks up
# edits without a full bot restart -- same discipline as every other
# plugin in this repo (a new submodule added later must be added here
# too, or it goes stale on reload).
from . import matcher
from . import enforcement
from . import config
from . import plugin
from importlib import reload

reload(matcher)
reload(enforcement)
reload(config)
reload(plugin)

if world.testing:
    from . import test

Class = plugin.Class
configure = config.configure
