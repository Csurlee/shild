"""Optional GitHub token loading -- same pattern and same rationale as
plugins/Shild/reputation.py's load_secrets: never in the Limnoria
registry (an admin's `@config` dump must not be able to leak it), env
var takes precedence over the gitignored secrets file.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


def load_github_token(path: str) -> Optional[str]:
    data: dict = {}
    p = Path(path)
    if p.exists():
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            data = {}
    return os.environ.get("SHILD_GITHUB_TOKEN") or data.get("github_token") or None
