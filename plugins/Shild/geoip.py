"""Local, offline IP-to-country lookup backed by a downloaded MMDB file
(DB-IP City Lite, CC BY 4.0 -- see scripts/update_geoip_db.py's own
docstring for where it comes from and how to refresh it).

Why this exists: ip-api.com's single request already returns everything
Tier 1 geo needs (proxy/hosting flags, ASN, ISP, country -- see
reputation.py's IPAPI_FIELDS), so this does NOT remove that network call --
proxy/hosting/ASN/ISP have no free local equivalent. What it removes is
COUNTRY's dependency on that call specifically: country is now resolved
from a local, offline database first, so it's still populated even when
ip-api.com is slow, down, or budget-exhausted for the day. ip-api's own
countryCode remains the fallback if the local DB is missing or the lookup
misses (e.g. a fresh install that hasn't run the download script yet) --
see reputation.py's _apply_geo for how the two are combined.

Fails closed everywhere: a missing file, a corrupt file, an invalid IP, or
any lookup miss all just return None, same "we don't know, not a crash"
convention as every other optional evidence source in this codebase. The
mmdb Reader is safe for concurrent use (memory-mapped, read-only) and is
opened once and cached per path, not per lookup.
"""
from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Optional

log = logging.getLogger("supybot")

try:
    import maxminddb
except ImportError:  # pragma: no cover -- optional dependency, see pyproject.toml
    maxminddb = None

_readers: dict[str, object] = {}
_load_failed: set[str] = set()


def _get_reader(db_path: str):
    """Opens (and caches) an mmdb Reader for db_path. Returns None -- and
    remembers not to retry -- if the package isn't installed, the file
    doesn't exist yet, or it fails to parse. Retried again only if the
    module is reloaded (matches the rest of this codebase's "@reload
    Shild doesn't re-import shildml/third-party state" behavior).
    """
    if maxminddb is None or db_path in _load_failed:
        return None
    reader = _readers.get(db_path)
    if reader is not None:
        return reader
    if not Path(db_path).is_file():
        _load_failed.add(db_path)
        return None
    try:
        reader = maxminddb.open_database(db_path)
    except Exception:
        log.warning("GeoIP: failed to open local database at %s", db_path, exc_info=True)
        _load_failed.add(db_path)
        return None
    _readers[db_path] = reader
    return reader


def lookup_country(ip: str, db_path: str) -> Optional[str]:
    """Returns an ISO 3166-1 alpha-2 country code (e.g. "US"), or None if
    the local database isn't available or has no entry for this IP.
    Never raises.
    """
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    reader = _get_reader(db_path)
    if reader is None:
        return None
    try:
        result = reader.get(ip)
    except Exception:
        return None
    if not isinstance(result, dict):
        return None
    country = result.get("country") or {}
    code = country.get("iso_code")
    return code if isinstance(code, str) and code else None


def reset_cache() -> None:
    """Test-only: drop cached readers/failure memory so a test can point
    at a fresh path without a previous test's state leaking in -- same
    class of cross-test leak this codebase has hit repeatedly for
    registry values (see CLAUDE.md), just for this module's own
    process-level cache instead.
    """
    _readers.clear()
    _load_failed.clear()
