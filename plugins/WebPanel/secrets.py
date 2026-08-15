"""WebPanel credential loading -- same file/pattern as
plugins/Shild/reputation.py's load_secrets and
plugins/GitHubWatch/secrets.py's load_github_token: credentials come from
a gitignored local JSON file, never the Limnoria registry (an admin's
`@config` dump must not be able to leak them -- runtime/shildpy.conf is
mode 0664, world-readable, and already holds this project's Libera
NickServ and Undernet X passwords in cleartext, which is the concrete
demonstration of why). Environment variables take precedence over the
file.

**Deliberately fail-CLOSED, unlike every other secrets loader in this
repo.** Shild's reputation keys and GitHubWatch's token just disable a
feature when missing -- open is the safe default there, since a missing
key just means "skip this optional lookup". Here, missing/unparseable
credentials would mean serving channel logs and shadow-decision data
(real users' nicks, hostmasks, resolved IPs, ASN/geo/reputation scores)
to anyone who can reach the panel with no login at all -- so
load_panel_credentials() returning None must be treated by callers as
"refuse every request" (see auth.AuthResult.NOT_CONFIGURED / http.py),
never as "there's no auth configured, let it through".
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

from .auth import PanelCredentials


def load_panel_credentials(path: str) -> Optional[PanelCredentials]:
    data: dict = {}
    p = Path(path)
    if p.exists():
        try:
            data = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            data = {}
    username = os.environ.get("SHILD_WEBPANEL_USER") or data.get("web_panel_user") or ""
    password_hash = (
        os.environ.get("SHILD_WEBPANEL_PASSWORD_HASH")
        or data.get("web_panel_password_hash")
        or ""
    )
    if not username or not password_hash:
        return None
    return PanelCredentials(username=username, password_hash=password_hash)


class CredentialWatcher:
    """Wraps load_panel_credentials with mtime-based caching, so rotating
    the panel password (edit runtime/secrets.json, or change the env var
    before a restart) takes effect on the next request rather than
    needing a full plugin reload -- but the file isn't re-read on every
    single request either, which would mean a stat() syscall on every
    page load. A missing file is checked every call (getmtime raises
    OSError, cheap) so credentials appear as soon as the file does.
    """

    def __init__(self, path: str):
        self._path = path
        self._mtime: Optional[float] = None
        self._credentials: Optional[PanelCredentials] = None
        self._checked = False

    def get(self) -> Optional[PanelCredentials]:
        try:
            mtime: Optional[float] = os.path.getmtime(self._path)
        except OSError:
            mtime = None
        if not self._checked or mtime != self._mtime:
            self._credentials = load_panel_credentials(self._path)
            self._mtime = mtime
            self._checked = True
        return self._credentials
