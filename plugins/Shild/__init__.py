"""
Shild: AI + ML classifier IRC channel guardian -- Phase 1 (shadow mode:
observes and logs decisions, never acts; no moderation commands yet).
"""

import supybot
from supybot import world

__version__ = "1.8"
__author__ = supybot.authors.unknown
__contributors__ = {}
__url__ = "https://github.com/Csurlee/shild"

# Import every submodule and reload() it so `@reload Shild` picks up
# edits without a full bot restart -- if a new submodule is added later,
# it must be added here too or it'll go stale on reload (this bit us
# almost by omission during development, worth remembering).
from . import context
from . import prompts
from . import ollama
from . import classifier
from . import worker
from . import budget
from . import reputation
from . import proxyscan
from . import enforcement
from . import collector
from . import config
from . import plugin
from importlib import reload

reload(context)
reload(prompts)
reload(ollama)
reload(classifier)
reload(worker)
reload(budget)
reload(reputation)
reload(proxyscan)
reload(enforcement)
reload(collector)
reload(config)
reload(plugin)

if world.testing:
    from . import test

Class = plugin.Class
configure = config.configure
