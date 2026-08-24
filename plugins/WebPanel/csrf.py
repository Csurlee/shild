"""Pure CSRF defenses for WebPanel's write routes (2026-08-24). No supybot
import -- unit-testable with plain pytest, no IRC harness needed.

**Two independent layers, and their real ordering of importance** (see
plugins/WebPanel/http.py's doPost for how these compose into one gate):

1. **Origin/Referer verification is the PRIMARY defense.** The actual
   attack this defends against: an admin's browser has cached Basic-Auth
   credentials for this panel; they visit an unrelated page that
   auto-submits a hidden form POSTing to a panel write route. The
   browser attaches the cached credentials automatically -- the
   allowedHosts Host-header check (http.py's DNS-rebinding defense)
   contributes NOTHING here, since the attacker's form targets the
   panel's own real, correct Host. `check_origin()` rejects that: modern
   browsers (Chrome 51+, Firefox 70+, Safari 12.1+) send `Origin` on
   every state-changing cross-origin request, and this repo's own panel
   never links anywhere external, so a same-origin `Referer` fallback
   for browsers that omit `Origin` costs nothing. Forging a same-origin
   `Origin` would need XSS on the panel itself, which the existing
   `default-src 'none'` CSP (no script-src at all) already rules out.

2. **The signed token is SECONDARY, defense-in-depth, not the load-
   bearing layer.** `TokenSigner` is a session-free, storage-free HMAC
   token (mirrors auth.py's `CredentialCache` -- a random per-process
   `os.urandom(32)` key, no server-side per-token state) embedded as a
   hidden field in every rendered write form and checked on submit. It
   converts "we depend on every current and future browser correctly
   sending Origin on a form POST" into "either of two independent things
   must hold" -- genuinely useful, but be honest about what it does NOT
   buy: there is no TLS anywhere in Limnoria's httpserver (see auth.py's
   own module docstring), so a LAN eavesdropper reads this token straight
   out of a GET response exactly as easily as they'd read the Basic-Auth
   credentials themselves. Neither CSRF layer defends against that
   adversary -- only against a hostile THIRD-PARTY PAGE the admin's
   browser happens to visit while credentials are cached.

Because there's no session, the token isn't tied to "this specific admin's
login" -- it only proves "this form was rendered by THIS PROCESS recently
enough to still be in the current or previous time bucket", combined with
same-origin-policy already preventing a hostile page from reading the
token out of a GET response it can't see the body of. That's sufficient
for what this buys: proof the write request originated from a page this
server itself served, not a forged cross-site POST.
"""
from __future__ import annotations

import hmac
import os
import time
from typing import Iterable, Optional
from urllib.parse import urlsplit


class TokenSigner:
    """Stateless: verifying a token needs nothing but the per-process key
    and the current time -- no dict of issued tokens to leak, expire, or
    grow unbounded. A `@reload WebPanel` (which rebuilds the owning
    WebPanelCallback and therefore this signer, per http.py's __init__)
    invalidates every currently-open form; that's an accepted, documented
    tradeoff, not an oversight -- the alternative (a persisted key) would
    make the token meaningfully more valuable to steal for no real gain
    given point 2 above already concedes it isn't the load-bearing layer.
    """

    def __init__(self, bucket_secs: float = 1800.0, key: Optional[bytes] = None):
        self._bucket_secs = bucket_secs
        self._key = key if key is not None else os.urandom(32)

    def _mac(self, bucket: int, scope: str) -> str:
        msg = f"{bucket}\0{scope}".encode("utf-8")
        return hmac.new(self._key, msg, "sha256").hexdigest()

    def issue(self, scope: str, *, now: Optional[float] = None) -> str:
        """`scope` binds a token to one page/action family (e.g.
        "controls", "controls-channel:libera:#windrop") so a token
        rendered for one form can't be replayed against an unrelated one
        -- cheap to check, no reason not to."""
        if now is None:
            now = time.time()
        bucket = int(now // self._bucket_secs)
        return f"{bucket}.{self._mac(bucket, scope)}"

    def verify(self, token: Optional[str], scope: str, *, now: Optional[float] = None) -> bool:
        """Never raises. Accepts the current time bucket OR the
        immediately preceding one (so a token rendered right at a bucket
        boundary doesn't expire mid-form-fill), rejecting anything else
        outright -- including a bucket number from the FUTURE, which
        would only ever occur from a forged token or serious clock skew,
        neither of which should be treated as valid."""
        if not token or len(token) > 128:
            return False
        bucket_s, _, mac = token.partition(".")
        if not mac or not bucket_s.lstrip("-").isdigit():
            return False
        try:
            bucket = int(bucket_s)
        except ValueError:
            return False
        if now is None:
            now = time.time()
        current = int(now // self._bucket_secs)
        if bucket not in (current, current - 1):
            return False
        return hmac.compare_digest(mac, self._mac(bucket, scope))


class OriginResult:
    OK = "ok"
    MISSING = "missing"      # neither Origin nor Referer present
    MISMATCH = "mismatch"    # present, but doesn't match an allowed host


def check_origin(
    origin: Optional[str],
    referer: Optional[str],
    allowed_hosts: Iterable[str],
    *,
    scheme: str = "http",
) -> str:
    """One of the OriginResult.* values. `allowed_hosts` is the SAME set
    already validated against the request's own Host header
    (plugins.WebPanel.allowedHosts) -- reusing it here means a POST is
    only ever accepted from an origin this server already considers
    itself reachable at, nothing broader.

    Order: `Origin` wins if present at all (even a malformed/`null` one
    -- that's still a definitive signal, not a reason to fall through to
    Referer). Only truly ABSENT Origin falls back to Referer. Both
    absent -> MISSING (rejected the same as a mismatch by the caller;
    kept as a distinct code purely so a 403 body/log line can say which
    happened).
    """
    allowed = {f"{scheme}://{h}".lower() for h in allowed_hosts}
    if origin is not None:
        return OriginResult.OK if origin.strip().lower() in allowed else OriginResult.MISMATCH
    if referer is not None:
        parts = urlsplit(referer)
        if not parts.scheme or not parts.netloc:
            return OriginResult.MISMATCH
        candidate = f"{parts.scheme}://{parts.netloc}".lower()
        return OriginResult.OK if candidate in allowed else OriginResult.MISMATCH
    return OriginResult.MISSING
