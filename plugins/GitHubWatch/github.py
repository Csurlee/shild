"""GitHub API client + pure event filtering/formatting.

Polls the repo-level Events API (`GET /repos/{owner}/{repo}/events`)
rather than separately polling commits/issues/pulls -- one endpoint call
per repo per poll covers pushes, issues, AND pull requests together
(GitHub's events feed already merges them, tagged by `type`), which
keeps API usage low enough to run unauthenticated (60 req/hour) for a
single repo at a sane poll interval, and scales better than three
separate endpoints once more repos are added.

`relevant_events`/`format_event` are pure (no I/O, no supybot import) so
they're unit-testable with canned API response fixtures -- see test.py.
Only `fetch_events` touches the network.
"""
from __future__ import annotations

from typing import Optional

import aiohttp

API_BASE = "https://api.github.com"
USER_AGENT = "shild-py-GitHubWatch (github.com/Csurlee/shild)"

# Event types worth announcing, and which payload["action"] values count
# for the ones that fire on every state change (Issues/PullRequest events
# fire for opened/closed/reopened/labeled/assigned/etc -- most of that is
# noise for an IRC ping).
_ANNOUNCE_ISSUE_ACTIONS = {"opened"}
_ANNOUNCE_PR_ACTIONS = {"opened", "closed"}  # "closed" filtered to merged-only below


async def fetch_events(
    session: aiohttp.ClientSession,
    owner: str,
    repo: str,
    token: Optional[str] = None,
    timeout: float = 10.0,
) -> tuple[list[dict], Optional[str]]:
    """Returns (events, error). `events` is the raw list GitHub returns,
    newest-first, on success (possibly empty -- not an error). Never
    raises: any failure mode returns ([], reason) so a polling loop can
    log and move on to the next repo rather than dying.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"{API_BASE}/repos/{owner}/{repo}/events"
    try:
        async with session.get(
            url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout)
        ) as resp:
            if resp.status == 404:
                return [], "repo_not_found"
            if resp.status in (403, 429):
                return [], "rate_limited_or_forbidden"
            if resp.status != 200:
                return [], f"http_{resp.status}"
            data = await resp.json(content_type=None)
            if not isinstance(data, list):
                return [], "unexpected_response"
            return data, None
    except Exception as e:  # noqa: BLE001 -- fail-open boundary, must not raise
        return [], type(e).__name__


def relevant_events(events: list[dict], since_id: Optional[int] = None) -> list[dict]:
    """Filter a raw (newest-first) event list down to the ones worth
    announcing, stopping once `since_id` is reached (exclusive -- that
    one and everything older was already announced on a prior poll).
    Returned list is still newest-first; reverse it before announcing so
    channel output reads in chronological order.
    """
    out = []
    for event in events:
        try:
            event_id = int(event["id"])
        except (KeyError, ValueError, TypeError):
            continue
        if since_id is not None and event_id <= since_id:
            break
        etype = event.get("type")
        payload = event.get("payload", {})
        if etype == "PushEvent":
            out.append(event)
        elif etype == "IssuesEvent" and payload.get("action") in _ANNOUNCE_ISSUE_ACTIONS:
            out.append(event)
        elif etype == "PullRequestEvent" and payload.get("action") in _ANNOUNCE_PR_ACTIONS:
            if payload.get("action") == "closed" and not payload.get("pull_request", {}).get("merged"):
                continue  # closed without merging -- not interesting enough to ping a channel about
            out.append(event)
    return out


def max_event_id(events: list[dict]) -> Optional[int]:
    """Highest numeric id across a raw event list, or None if empty/all
    unparseable. Used to advance the polling cursor even for events that
    weren't `relevant_events` (a repo that's all comments/labels for a
    while shouldn't cause the same events to be re-fetched forever).
    """
    ids = []
    for event in events:
        try:
            ids.append(int(event["id"]))
        except (KeyError, ValueError, TypeError):
            continue
    return max(ids) if ids else None


def format_event(event: dict, max_commits_shown: int = 3) -> str:
    """One GitHub event dict -> one IRC message line. Pure/no I/O."""
    etype = event.get("type")
    actor = event.get("actor", {}).get("login") or "someone"
    repo = event.get("repo", {}).get("name") or "?"
    payload = event.get("payload", {})

    if etype == "PushEvent":
        return _format_push(actor, repo, payload, max_commits_shown)
    if etype == "IssuesEvent":
        return _format_issue(actor, repo, payload)
    if etype == "PullRequestEvent":
        return _format_pull_request(actor, repo, payload)
    return f"[{repo}] {actor}: {etype}"


def _format_push(actor: str, repo: str, payload: dict, max_commits_shown: int) -> str:
    ref = payload.get("ref", "")
    branch = ref.rsplit("/", 1)[-1] if ref else "?"

    before, head = payload.get("before", ""), payload.get("head", "")
    compare_url = ""
    if before and head and before != "0" * 40:
        compare_url = f" — https://github.com/{repo}/compare/{before[:7]}...{head[:7]}"

    # GitHub's Events API omits "commits"/"size" entirely for a private
    # repo accessed via a token (confirmed live 2026-08-02 against a real
    # push) -- NOT present-but-empty, actually absent, so don't invent a
    # commit count when there's nothing to count. The compare link is the
    # accurate source of truth either way.
    commits = payload.get("commits")
    size = payload.get("size")
    if commits is None or size is None:
        return f"[{repo}] {actor} pushed to {branch}{compare_url}"

    plural = "" if size == 1 else "s"
    shown = [c.get("message", "").splitlines()[0][:80] for c in commits[:max_commits_shown]]
    summary = "; ".join(m for m in shown if m)
    remaining = size - len(shown)
    if remaining > 0:
        summary += f" (+{remaining} more)" if summary else f"{remaining} commit{plural}"

    msg = f"[{repo}] {actor} pushed {size} commit{plural} to {branch}"
    if summary:
        msg += f": {summary}"
    return msg + compare_url


def _format_issue(actor: str, repo: str, payload: dict) -> str:
    issue = payload.get("issue", {})
    return (
        f"[{repo}] {actor} opened issue #{issue.get('number')}: "
        f"{issue.get('title', '')} — {issue.get('html_url', '')}"
    )


def _format_pull_request(actor: str, repo: str, payload: dict) -> str:
    pr = payload.get("pull_request", {})
    number = pr.get("number", payload.get("number"))
    title = pr.get("title", "")
    url = pr.get("html_url", "")
    if payload.get("action") == "closed" and pr.get("merged"):
        return f"[{repo}] {actor}'s PR #{number} merged: {title} — {url}"
    return f"[{repo}] {actor} opened PR #{number}: {title} — {url}"
