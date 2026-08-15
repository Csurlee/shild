"""Pure authentication logic for WebPanel: password hashing/verification,
HTTP Basic-Auth header parsing, brute-force lockout, and a short-lived
verified-credential cache so a slow KDF doesn't become a self-inflicted
denial of service on Limnoria's serial (non-threading) HTTP server.

No supybot import anywhere in this file -- unit-testable with plain
pytest, no IRC harness needed. See http.py for how these pieces compose
into the actual per-request check, and this project's WebPanel design
notes (CLAUDE.md) for the threat model this defends -- and does not
defend -- against. In short: this stops LAN password-guessing and DNS
rebinding (the latter in http.py, via the Host-header allowlist); it does
NOT provide transport encryption -- there is no TLS anywhere in
Limnoria's httpserver, so the password and every page cross the network
in cleartext regardless of what this module does.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import os
import time
from dataclasses import dataclass
from typing import Optional

PBKDF2_ALGORITHM = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000
_DK_LEN = 32
_MAX_AUTH_HEADER_LEN = 4096


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """Returns 'pbkdf2_sha256$<iterations>$<salt_b64>$<dk_b64>'. Store
    this, never the plaintext -- see secrets.py's module docstring for
    the honest accounting of what that does and doesn't buy on a
    cleartext-only HTTP server (short version: it protects against a
    leaked secrets.json handing over a reused password, nothing more)."""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=_DK_LEN)
    return "$".join([
        PBKDF2_ALGORITHM,
        str(iterations),
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    ])


def verify_password(password: str, stored_hash: str) -> bool:
    """Never raises -- a corrupt or unrecognized hash string just fails
    verification, the same fail-closed posture as a wrong password."""
    try:
        algorithm, iterations_s, salt_b64, dk_b64 = stored_hash.split("$")
        if algorithm != PBKDF2_ALGORITHM:
            return False
        iterations = int(iterations_s)
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(dk_b64, validate=True)
    except (ValueError, binascii.Error):
        return False
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=len(expected))
    return hmac.compare_digest(actual, expected)


# A fixed dummy hash, computed once at import time, verified against for
# an unrecognized username -- so response timing can't reveal which
# usernames are valid vs. not. The "password" behind it is random and
# used for nothing else.
_DUMMY_HASH = hash_password(
    base64.b64encode(os.urandom(24)).decode("ascii"), iterations=DEFAULT_ITERATIONS)


@dataclass(frozen=True)
class PanelCredentials:
    username: str
    password_hash: str


def _split_basic_header(header: Optional[str]) -> Optional[str]:
    """Returns the base64 payload if `header` is a well-formed
    'Basic <payload>' Authorization value, else None. Deliberately kept
    separate from decoding the payload (see _decode_basic_payload) --
    check_request needs to distinguish "no Basic attempt at all" (a
    browser's normal first request, not an attack) from "a malformed
    Basic attempt" (which does count toward lockout)."""
    if not header or len(header) > _MAX_AUTH_HEADER_LEN:
        return None
    scheme, _, payload = header.partition(" ")
    if scheme.lower() != "basic" or not payload:
        return None
    return payload


def _decode_basic_payload(payload: str) -> Optional[tuple[str, str]]:
    try:
        raw = base64.b64decode(payload, validate=True)
        decoded = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    username, _, password = decoded.partition(":")
    return username, password


def parse_basic_auth(header: Optional[str]) -> Optional[tuple[str, str]]:
    """Public helper: header -> (username, password) or None for anything
    malformed (absent, oversized, wrong scheme, bad base64, non-UTF-8, no
    colon). Splits on the FIRST colon only, since a password may itself
    contain one. Used directly by tests; check_request below uses the two
    halves separately for lockout-accounting reasons."""
    payload = _split_basic_header(header)
    if payload is None:
        return None
    return _decode_basic_payload(payload)


class CredentialCache:
    """Short-lived memory-only cache of already-verified credentials.
    Limnoria's HTTP server handles requests serially (see http.py's
    module docstring), and Basic Auth re-sends credentials on every
    single request/page-load/live-preview-refresh -- re-running a
    ~200ms PBKDF2 hash that often would let anyone on the LAN wedge the
    panel for everyone else. Keyed by an HMAC of (username, password)
    under a random per-process key, so the cache itself never holds a
    password or anything reversible to one, and it evaporates on
    process restart/reload.
    """

    def __init__(self, ttl_secs: float, max_entries: int = 16):
        self._ttl = ttl_secs
        self._max_entries = max_entries
        self._key = os.urandom(32)
        self._entries: dict[bytes, float] = {}  # digest -> expiry

    def _digest(self, username: str, password: str) -> bytes:
        msg = username.encode("utf-8") + b"\0" + password.encode("utf-8")
        return hmac.new(self._key, msg, "sha256").digest()

    def check(self, username: str, password: str, now: float) -> bool:
        if self._ttl <= 0:
            return False
        expiry = self._entries.get(self._digest(username, password))
        return expiry is not None and expiry > now

    def remember(self, username: str, password: str, now: float) -> None:
        if self._ttl <= 0:
            return
        if len(self._entries) >= self._max_entries:
            # Bounded by construction: drop the entry expiring soonest
            # rather than let this grow with e.g. a scripted client that
            # varies its password on every request.
            oldest = min(self._entries, key=self._entries.get)
            del self._entries[oldest]
        self._entries[self._digest(username, password)] = now + self._ttl


class LockoutTracker:
    """Per-client-IP brute-force lockout. Deliberately never sleep()s to
    slow an attacker down: httpserver.py's server is a plain (not
    threading) HTTPServer, so blocking the request-handling thread
    blocks every other client too -- a lockout window that returns
    immediately is the only safe throttle available here.
    """

    def __init__(self, max_failures: int, lockout_secs: float,
                 max_tracked_ips: int = 256, window_secs: float = 60.0):
        self._max_failures = max_failures
        self._lockout_secs = lockout_secs
        self._max_tracked_ips = max_tracked_ips
        self._window_secs = window_secs
        # ip -> (fail_count, window_start, locked_until)
        self._state: dict[str, tuple[int, float, float]] = {}

    def is_locked(self, ip: str, now: float) -> bool:
        entry = self._state.get(ip)
        if entry is None:
            return False
        _, _, locked_until = entry
        return now < locked_until

    def record_failure(self, ip: str, now: float) -> None:
        count, window_start, _locked_until = self._state.get(ip, (0, now, 0.0))
        if now - window_start > self._window_secs:
            count, window_start = 0, now
        count += 1
        locked_until = now + self._lockout_secs if count >= self._max_failures else 0.0
        if ip not in self._state and len(self._state) >= self._max_tracked_ips:
            # Bounded dict: evict whichever IP's window started longest
            # ago. A determined distributed attacker can still cycle
            # through more IPs than we track, but that's true of any
            # bounded in-memory tracker and not worth unbounded memory.
            oldest = min(self._state, key=lambda k: self._state[k][1])
            del self._state[oldest]
        self._state[ip] = (count, window_start, locked_until)

    def record_success(self, ip: str) -> None:
        self._state.pop(ip, None)


class AuthResult:
    OK = "ok"
    NOT_CONFIGURED = "not_configured"  # -> 503, panel refuses everything
    LOCKED = "locked"                  # -> 429
    UNAUTHORIZED = "unauthorized"      # -> 401


def check_request(
    credentials: Optional[PanelCredentials],
    auth_header: Optional[str],
    client_ip: str,
    cache: CredentialCache,
    lockout: LockoutTracker,
    now: Optional[float] = None,
) -> str:
    """The full per-request auth decision (one of the AuthResult.* values
    above). Order matters and is deliberate:

    1. No credentials configured at all -> fail CLOSED (NOT_CONFIGURED),
       never fall back to "no auth". See secrets.py's module docstring
       for why this inverts every other secrets loader's fail-open
       polarity in this repo.
    2. No Basic-Auth attempt present at all -> UNAUTHORIZED without
       touching lockout state. This is a browser's completely normal
       first request before it has a credential to send; penalizing it
       would lock out every legitimate first visit.
    3. A Basic-Auth attempt IS present -> check lockout before doing any
       decode/verify work, so a locked-out IP can't burn CPU on this
       path at all.
    4. Malformed payload (bad base64/UTF-8/no colon) -> counts as a
       failure; this is a real attempt, just a broken one.
    5. Verify. Always runs a real KDF call -- against the true hash for
       a recognized username, against a fixed dummy hash otherwise --
       so response timing can't distinguish "wrong password" from
       "unknown username".
    """
    if now is None:
        now = time.time()
    if credentials is None:
        return AuthResult.NOT_CONFIGURED

    payload = _split_basic_header(auth_header)
    if payload is None:
        return AuthResult.UNAUTHORIZED

    if lockout.is_locked(client_ip, now):
        return AuthResult.LOCKED

    parsed = _decode_basic_payload(payload)
    if parsed is None:
        lockout.record_failure(client_ip, now)
        return AuthResult.UNAUTHORIZED

    username, password = parsed

    if cache.check(username, password, now):
        lockout.record_success(client_ip)
        return AuthResult.OK

    is_known_user = hmac.compare_digest(
        username.encode("utf-8"), credentials.username.encode("utf-8"))
    target_hash = credentials.password_hash if is_known_user else _DUMMY_HASH
    verified = verify_password(password, target_hash)

    if verified and is_known_user:
        cache.remember(username, password, now)
        lockout.record_success(client_ip)
        return AuthResult.OK

    lockout.record_failure(client_ip, now)
    return AuthResult.UNAUTHORIZED


def run_hash_cli() -> None:  # pragma: no cover - interactive CLI, not unit-tested
    """Prompts for a username and password via getpass (never echoed to
    the terminal, never appears in shell history) and prints ONLY the
    resulting hash line, in the exact
    `web_panel_user`/`web_panel_password_hash` shape
    runtime/secrets.json expects (see secrets.py's module docstring for
    why the plaintext must never be written anywhere, including here --
    this function never writes to disk itself, on purpose; you paste the
    two lines into secrets.json yourself).

    Run this as `python plugins/WebPanel/auth.py`, NOT
    `python -m plugins.WebPanel.auth`. The `-m` form imports this file
    through the plugins.WebPanel PACKAGE, which runs
    plugins/WebPanel/__init__.py and, transitively,
    supybot.i18n.PluginInternationalization, which tries to resolve the
    plugin's directory via `sys.modules['__main__'].__file__` -- unset
    when Python runs a module that way, causing an AttributeError.
    Confirmed live 2026-08-06; same class of issue already documented
    for plugins/Shild/proxyscan.py's standalone smoke test. Running this
    file directly (not as part of the package) sidesteps it entirely --
    this module has no relative imports of its own, so nothing about
    plugins.WebPanel ever gets imported.
    """
    import getpass
    import json as _json

    username = input("WebPanel username: ").strip()
    if not username:
        raise SystemExit("Username must not be empty.")
    password = getpass.getpass("WebPanel password (not echoed): ")
    if not password:
        raise SystemExit("Password must not be empty.")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise SystemExit("Passwords did not match.")

    password_hash = hash_password(password)
    print("\nAdd these two lines to runtime/secrets.json (merge with the "
          "existing keys -- don't overwrite abuseipdb_key etc.):\n")
    print(_json.dumps({"web_panel_user": username}, indent=2)[1:-1].strip() + ",")
    print(_json.dumps({"web_panel_password_hash": password_hash}, indent=2)[1:-1].strip())


if __name__ == "__main__":  # pragma: no cover
    run_hash_cli()
