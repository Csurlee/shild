"""
GitHubWatch: polls configured GitHub repos and announces new pushes,
opened issues, and opened/merged pull requests to a channel.
"""

import supybot
from supybot import world

__version__ = "1.9"
__author__ = supybot.authors.unknown
__contributors__ = {}
__url__ = "https://github.com/Csurlee/shild"

from . import github
from . import state
from . import secrets
from . import worker
from . import config
from . import plugin
from importlib import reload

reload(github)
reload(state)
reload(secrets)
reload(worker)
reload(config)
reload(plugin)

if world.testing:
    from . import test

Class = plugin.Class
configure = config.configure
