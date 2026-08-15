#!/usr/bin/env python3
"""Downloads/refreshes the local DB-IP City Lite MMDB file used by
plugins/Shild/geoip.py for offline, no-network, no-budget country lookups.

Source: db-ip.com's "City Lite" database, CC BY 4.0 (attribution required,
no share-alike, freely redistributable) -- fetched via jsDelivr's generic
npm-package CDN (the dbip-city-lite npm package publishes the raw .mmdb.gz,
jsDelivr serves it from any npm package with no auth/key/rate limit). This
URL was found via wp-statistics/geo's own README (github.com/wp-statistics/
geo), which documents the same jsDelivr path for a public IP-geolocation
service it runs -- we pull directly from jsDelivr, not from wp-statistics'
own infrastructure, so nothing here actually depends on that project
staying up.

GeoLite2-City (MaxMind, CC BY-SA 4.0) was considered instead and rejected
for this default: CC BY-SA's share-alike clause is a heavier obligation for
a project that already mixes MIT/BSD-3-Clause code, and DB-IP City Lite
covers the one field this project actually uses (country) just as well.

Attribution (required by the CC BY 4.0 license -- keep this if you ever
quote/redistribute the downloaded file itself, not just use it in-process):
    IP Geolocation by DB-IP (https://db-ip.com)

Usage:
    python scripts/update_geoip_db.py                  # download/refresh
    python scripts/update_geoip_db.py --check           # print status, exit 1 if stale/missing

Intended to run from a weekly cron job (DB-IP City Lite itself updates
monthly; weekly is deliberately more frequent than needed rather than less,
same "no harm in checking early" reasoning as this project's other
scheduled jobs) -- NOT added to crontab automatically by this script; see
CLAUDE.md for the line to add by hand, same as every other cron job in
this project.
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

DOWNLOAD_URL = "https://cdn.jsdelivr.net/npm/dbip-city-lite/dbip-city-lite.mmdb.gz"
DEFAULT_DEST = "runtime/geoip/dbip-city-lite.mmdb"
STALE_AFTER_SECS = 35 * 24 * 3600  # ~5 weeks -- one missed weekly cron tolerated


def _meta_path(dest: Path) -> Path:
    return dest.with_suffix(dest.suffix + ".meta.json")


def check(dest: str) -> int:
    dest_path = Path(dest)
    meta_path = _meta_path(dest_path)
    if not dest_path.is_file():
        print(f"MISSING: {dest_path} does not exist -- run without --check to download it.")
        return 1
    if not meta_path.is_file():
        print(f"UNKNOWN AGE: {dest_path} exists but has no .meta.json (manually placed?).")
        return 0
    meta = json.loads(meta_path.read_text())
    age = time.time() - meta.get("downloaded_at", 0)
    status = "STALE" if age > STALE_AFTER_SECS else "OK"
    print(f"{status}: {dest_path} downloaded {age / 86400:.1f} days ago "
          f"(source: {meta.get('source_url', '?')})")
    return 1 if status == "STALE" else 0


def update(dest: str) -> int:
    dest_path = Path(dest)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = dest_path.with_suffix(dest_path.suffix + ".tmp")

    print(f"Downloading {DOWNLOAD_URL} ...")
    try:
        with urllib.request.urlopen(DOWNLOAD_URL, timeout=30) as resp:
            compressed = resp.read()
    except Exception as exc:
        print(f"ERROR: download failed: {exc}", file=sys.stderr)
        return 1

    try:
        raw = gzip.decompress(compressed)
    except Exception as exc:
        print(f"ERROR: downloaded file isn't valid gzip: {exc}", file=sys.stderr)
        return 1

    tmp_path.write_bytes(raw)

    # Verify the downloaded file actually opens as a valid mmdb BEFORE
    # replacing whatever's currently live -- a bad download must never
    # clobber a working database (same "verify before overwrite" discipline
    # this project uses for every other live-data write, see
    # scripts/release_to_public.py's own gates).
    try:
        import maxminddb
        with maxminddb.open_database(str(tmp_path)) as reader:
            test = reader.get("1.1.1.1")
            if not isinstance(test, dict):
                raise ValueError("test lookup did not return a record")
    except Exception as exc:
        tmp_path.unlink(missing_ok=True)
        print(f"ERROR: downloaded file failed validation, not installed: {exc}", file=sys.stderr)
        return 1

    os.replace(tmp_path, dest_path)
    _meta_path(dest_path).write_text(json.dumps({
        "source_url": DOWNLOAD_URL,
        "downloaded_at": time.time(),
        "size_bytes": len(raw),
    }, indent=2))
    print(f"OK: wrote {dest_path} ({len(raw) / 1_000_000:.1f} MB)")
    print("Attribution (CC BY 4.0): IP Geolocation by DB-IP (https://db-ip.com)")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dest", default=DEFAULT_DEST,
                         help=f"where to write the .mmdb file (default: {DEFAULT_DEST})")
    parser.add_argument("--check", action="store_true",
                         help="report status only, don't download; exit 1 if missing/stale")
    args = parser.parse_args()

    if args.check:
        sys.exit(check(args.dest))
    sys.exit(update(args.dest))


if __name__ == "__main__":
    main()
