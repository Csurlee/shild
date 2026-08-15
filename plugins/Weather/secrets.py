"""Optional OpenWeatherMap/OpenAQ key loading -- same pattern and same
rationale as plugins/GitHubWatch/secrets.py: never in the Limnoria
registry (an admin's `@config` dump must not be able to leak it), env
var takes precedence over the gitignored secrets file. Fails open
(returns None per-key, never raises) on a missing/unreadable/corrupt
file -- same convention as every other secrets loader in this repo
except plugins/WebPanel/secrets.py, which fails closed for a documented,
different reason (that plugin serves data with no auth otherwise).
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


def load_weather_secrets(path: str) -> dict:
    data: dict = {}
    p = Path(path)
    if p.exists():
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            data = {}
    return {
        "openweathermap_key": os.environ.get("SHILD_OPENWEATHERMAP_KEY")
        or data.get("openweathermap_key") or None,
        "openaq_key": os.environ.get("SHILD_OPENAQ_KEY") or data.get("openaq_key") or None,
    }
