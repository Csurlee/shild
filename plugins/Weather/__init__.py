"""
Weather: current conditions, forecast, and air quality via
OpenWeatherMap, OpenStreetMap Nominatim, and OpenAQ. Saves a per-user
default location on explicit "setweather" only.
"""

import supybot
from supybot import world

__version__ = "1.8"
__author__ = supybot.authors.unknown
__contributors__ = {}
__url__ = "https://github.com/Csurlee/shild"

from . import units
from . import symbols
from . import cache
from . import store
from . import secrets
from . import geocode
from . import owm
from . import airquality
from . import forecast
from . import render
from . import client
from . import config
from . import plugin
from importlib import reload

reload(units)
reload(symbols)
reload(cache)
reload(store)
reload(secrets)
reload(geocode)
reload(owm)
reload(airquality)
reload(forecast)
reload(render)
reload(client)
reload(config)
reload(plugin)

if world.testing:
    from . import test

Class = plugin.Class
configure = config.configure
