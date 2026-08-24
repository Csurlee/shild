#!/usr/bin/env python3
"""Sync plugins/GitHubWatch/ into the separate, public `Csurlee/limnoria-plugins`
repo (~/limnoria-plugins by default) as its own standalone plugin directory.

Why this exists: GitHubWatch has zero cross-plugin coupling with Shild/
SpamGuard/UndernetX/WebPanel (confirmed by grep -- only comments cite Shild
as a design-pattern reference, no import/getCallback), so it's genuinely
copy-paste-able into any other Limnoria bot. The user asked (2026-08-24) for
it to also live in their general-purpose `limnoria-plugins` repo, kept in
sync going forward whenever GitHubWatch changes here -- this script is that
sync step, run by hand (or by me) after a GitHubWatch change, same
"review before push" discipline as scripts/release_to_public.py, just far
smaller in scope: no secrets, no test-suite gate, only two cosmetic
identity strings need rewriting.

Deliberately NOT a Python-import-based copy (no `import plugins.GitHubWatch`)
-- this only ever touches files on disk, mirroring release_to_public.py's own
"plain file copy + sed-style substitution" approach.

Usage:
    python scripts/sync_githubwatch_to_limnoria_plugins.py [--dest ~/limnoria-plugins]

Never commits or pushes -- stops after copying + rewriting, and prints
`git status`/`git diff --stat` in the destination repo for a human (or me,
before running `git add`/`commit`/`push`) to review.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent.parent / "plugins" / "GitHubWatch"

# Files to copy verbatim from plugins/GitHubWatch/ -- everything except
# __pycache__ and compiled artifacts.
COPY_FILES = [
    "__init__.py",
    "config.py",
    "github.py",
    "plugin.py",
    "secrets.py",
    "state.py",
    "test.py",
    "worker.py",
]

# (old, new) substitutions applied to the copied files -- rewrites the two
# identity strings that name THIS repo (shild-py / Csurlee/shild) so the
# standalone copy correctly identifies itself as living in
# Csurlee/limnoria-plugins instead. Everything else (the SHILD_GITHUB_TOKEN
# env var name, the historical "found live against Csurlee/shild" comments
# documenting where a bug was actually discovered) is left alone on purpose:
# renaming the env var would be cosmetic churn for zero behavior change, and
# the historical comments are accurate provenance, not a live dependency.
SUBSTITUTIONS = [
    (
        'USER_AGENT = "shild-py-GitHubWatch (github.com/Csurlee/shild)"',
        'USER_AGENT = "GitHubWatch (github.com/Csurlee/limnoria-plugins)"',
    ),
    (
        '__url__ = "https://github.com/Csurlee/shild"',
        '__url__ = "https://github.com/Csurlee/limnoria-plugins"',
    ),
]


def sync(dest_repo: Path) -> None:
    dest = dest_repo / "GitHubWatch"
    dest.mkdir(parents=True, exist_ok=True)

    for name in COPY_FILES:
        src_file = SOURCE / name
        if not src_file.exists():
            print(f"skip (not found in source): {name}", file=sys.stderr)
            continue
        text = src_file.read_text()
        for old, new in SUBSTITUTIONS:
            text = text.replace(old, new)
        (dest / name).write_text(text)

    print(f"synced {len(COPY_FILES)} files -> {dest}")
    print()
    subprocess.run(["git", "status", "--short"], cwd=dest_repo)
    print()
    subprocess.run(["git", "diff", "--stat"], cwd=dest_repo)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--dest",
        default=str(Path.home() / "limnoria-plugins"),
        help="path to the local limnoria-plugins checkout (default: ~/limnoria-plugins)",
    )
    args = ap.parse_args()
    dest_repo = Path(args.dest).expanduser()
    if not (dest_repo / ".git").exists():
        print(f"error: {dest_repo} is not a git repo (clone it first)", file=sys.stderr)
        sys.exit(1)
    sync(dest_repo)


if __name__ == "__main__":
    main()
