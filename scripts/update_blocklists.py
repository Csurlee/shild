#!/usr/bin/env python3
"""Downloads/refreshes the local IP blocklist files used by
plugins/Shild/blocklist.py for offline, no-network, no-budget hard-evidence
checks -- a real corroborating signal (open proxy / botnet C&C membership),
distinct from the descriptive-only geo work in update_geoip_db.py.

Source: github.com/firehol/blocklist-ipsets, an aggregator of many free,
independently-maintained IP threat lists distributed as plain-text ipset
files (raw.githubusercontent.com, no auth/key/rate limit). This project
deliberately pulls only a small, curated subset -- NOT FireHOL's giant
multi-million-IP composite aggregates like "firehol_proxies" (~3.1M IPs) --
both because this box has only ~3.4GB RAM and because a blind aggregate
mixes in far more false-positive-prone sources than these specific,
actively-maintained, single-purpose trackers:

  socks_proxy_30d  -- open SOCKS proxies, source: socks-proxy.net, ~4-5K IPs
  sslproxies_30d   -- open SSL/HTTPS proxies, source: sslproxies.org, ~2-3K IPs
  cybercrime       -- botnet C&C servers, source: cybercrime-tracker.net, ~400 IPs
  feodo_badips     -- Feodo banking-trojan C&C IPs, source: abuse.ch Feodo
                       Tracker -- "badips" variant specifically recommended
                       by abuse.ch for lower false positives over the raw
                       feodo list, tiny (tens of IPs)

Each is a genuinely different, independently-maintained source (not four
views of the same underlying list), matching this project's existing DNSBL
curation philosophy: specific, verifiable, low-false-positive sources over
one giant blind aggregate (see reputation.py's module docstring for the
same reasoning applied to DNSBL zones -- several assumed-good ones,
including Spamhaus's PBL, were tested live and dropped).

Usage:
    python scripts/update_blocklists.py                # download/refresh all
    python scripts/update_blocklists.py --check         # report status, exit 1 if any missing/stale

Intended to run from a cron job more frequent than update_geoip_db.py's --
these lists update far more often upstream (some every few minutes) and
are tiny, so refreshing hourly costs nothing. NOT added to crontab
automatically; see docs/SHILD.md for the line to add by hand, same as
every other scheduled job in this project. Unlike update_geoip_db.py,
plugins/Shild/blocklist.py picks up a refreshed file on its very next
lookup automatically (mtime-checked, no plugin reload or bot restart
needed) -- see that module's own docstring.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

BASE_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/{name}.ipset"

LISTS = ("socks_proxy_30d", "sslproxies_30d", "cybercrime", "feodo_badips")

DEFAULT_DEST_DIR = "runtime/blocklists"
# Sanity ceiling on parsed IP count -- catches an accidental fetch of a
# wrong/giant file (e.g. a URL typo landing on one of FireHOL's real
# multi-million-IP aggregates) before it gets installed and blows past
# this box's RAM budget. Every curated list above is expected to be
# under a few thousand entries; this is a generous 50x margin, not a
# tight tuning knob.
MAX_SANE_IPS = 200_000
STALE_AFTER_SECS = 7 * 24 * 3600  # these lists update far more often than weekly


def _dest_path(dest_dir: str, name: str) -> Path:
    return Path(dest_dir) / f"{name}.txt"


def _meta_path(dest_dir: str) -> Path:
    return Path(dest_dir) / ".meta.json"


def check(dest_dir: str) -> int:
    meta_path = _meta_path(dest_dir)
    if not meta_path.is_file():
        print(f"MISSING: no {meta_path} -- run without --check to download.")
        return 1
    meta = json.loads(meta_path.read_text())
    rc = 0
    for name in LISTS:
        p = _dest_path(dest_dir, name)
        if not p.is_file():
            print(f"MISSING: {p}")
            rc = 1
            continue
        entry = meta.get(name, {})
        age = time.time() - entry.get("downloaded_at", 0)
        status = "STALE" if age > STALE_AFTER_SECS else "OK"
        print(f"{status}: {p} ({entry.get('count', '?')} IPs, "
              f"downloaded {age / 3600:.1f}h ago)")
        if status == "STALE":
            rc = 1
    return rc


def _fetch(name: str) -> list[str]:
    url = BASE_URL.format(name=name)
    with urllib.request.urlopen(url, timeout=20) as resp:
        text = resp.read().decode("utf-8", errors="ignore")
    ips = [
        line.strip() for line in text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return ips


def update(dest_dir: str) -> int:
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    meta_path = _meta_path(dest_dir)
    meta = json.loads(meta_path.read_text()) if meta_path.is_file() else {}

    ok = True
    for name in LISTS:
        print(f"Downloading {name} ...")
        try:
            ips = _fetch(name)
        except Exception as exc:
            print(f"ERROR: {name} download failed: {exc}", file=sys.stderr)
            ok = False
            continue

        if not ips:
            print(f"ERROR: {name} downloaded empty, not installed", file=sys.stderr)
            ok = False
            continue
        if len(ips) > MAX_SANE_IPS:
            print(f"ERROR: {name} has {len(ips)} entries, over the "
                  f"{MAX_SANE_IPS} sanity ceiling -- not installed "
                  f"(wrong URL, or FireHOL renamed this into a giant "
                  f"aggregate?)", file=sys.stderr)
            ok = False
            continue

        dest_path = _dest_path(dest_dir, name)
        tmp_path = dest_path.with_suffix(".tmp")
        tmp_path.write_text("\n".join(ips) + "\n")
        tmp_path.replace(dest_path)
        meta[name] = {"downloaded_at": time.time(), "count": len(ips),
                       "source_url": BASE_URL.format(name=name)}
        print(f"OK: wrote {dest_path} ({len(ips)} IPs)")

    meta_path.write_text(json.dumps(meta, indent=2))
    return 0 if ok else 1


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                      formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dest", default=DEFAULT_DEST_DIR,
                         help=f"directory to write list files into (default: {DEFAULT_DEST_DIR})")
    parser.add_argument("--check", action="store_true",
                         help="report status only, don't download; exit 1 if missing/stale")
    args = parser.parse_args()

    if args.check:
        sys.exit(check(args.dest))
    sys.exit(update(args.dest))


if __name__ == "__main__":
    main()
