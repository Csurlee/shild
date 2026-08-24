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


def relevant_events(events: list[dict], since_ids: Optional[dict] = None) -> list[dict]:
    """Filter a raw (newest-first) event list down to the ones worth
    announcing. `since_ids` maps event TYPE -> the highest id of that
    type already seen/announced.

    2026-08-24 fix (found via live investigation, not a hypothesis):
    this used to take a single `since_id: int` and `break` the moment
    any event's id fell at or below it -- built on the assumption that
    GitHub's numeric event ids are one shared, roughly time-ordered
    sequence across every event type. That's false. Confirmed against
    Csurlee/shild's real event history: a PushEvent at 10:07:58 UTC
    had id 18700998032, while IssuesEvent/IssueCommentEvent entries from
    just two minutes earlier (10:05:xx UTC) sat around 13751500000 --
    nearly 5 BILLION lower, despite being chronologically almost
    simultaneous. Event ids are allocated from structurally different
    ranges per type. A single combined "max id ever seen" cursor gets
    permanently poisoned the first time a high-id-range type (PushEvent)
    is polled -- every future Issues/PullRequest event, whose ids stay
    in the much lower range, then silently fails the `<= since_id`
    check forever. This is exactly what happened live for this repo:
    pushes are frequent, so the shared cursor almost certainly blocked
    every issue/PR announcement since the feature shipped.

    Tracking the floor per type (not a single scalar, and no early
    `break` -- types are interleaved in the API's response, so a global
    break is never safe) fixes this. An event type with no entry in
    `since_ids` (never independently seeded yet) is treated as "first
    time seeing this type" and is never included here -- same
    "seed the cursor, don't replay history" behavior this always had at
    the whole-repo level, now applied per type too.

    Returned list is still newest-first; reverse it before announcing so
    channel output reads in chronological order.
    """
    since_ids = since_ids or {}
    out = []
    for event in events:
        try:
            event_id = int(event["id"])
        except (KeyError, ValueError, TypeError):
            continue
        etype = event.get("type")
        floor = since_ids.get(etype)
        if floor is None or event_id <= floor:
            continue
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


def max_event_ids_by_type(events: list[dict]) -> dict:
    """Highest numeric id per event TYPE across a raw event list --
    2026-08-24, replaces the old single-scalar `max_event_id` (see
    relevant_events' own docstring for exactly why a combined max
    across types is unsafe). Used to advance the per-type polling
    cursor even for events that weren't `relevant_events` (e.g. a
    comment shouldn't cause the same events to be re-fetched forever,
    though re-fetching the API's fixed recent-events page is cheap
    regardless)."""
    out: dict = {}
    for event in events:
        etype = event.get("type")
        if etype is None:
            continue
        try:
            event_id = int(event["id"])
        except (KeyError, ValueError, TypeError):
            continue
        if event_id > out.get(etype, -1):
            out[etype] = event_id
    return out


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


def _first_line(text: str) -> str:
    """Strips embedded \\r/\\n (and anything after the first line) from
    third-party text before it's formatted into an announcement -- same
    treatment push commit messages already get just above
    (`.splitlines()[0]`). GitHub's API doesn't reject an embedded
    newline in an issue/PR title the way its web UI does, so an
    untreated title could contain one. Confirmed this can't cause
    IRC-protocol injection (ircmsgs.privmsg's own argument validator
    rejects \\r/\\n/NUL at message-construction time) -- but plugin.py's
    broad except-Exception around event formatting means an unguarded
    title used to silently drop the WHOLE announcement instead of just
    the newline, letting anyone who can open an issue/PR on a watched
    public repo suppress its own notification. Found via code review,
    2026-08-24.
    """
    return text.splitlines()[0] if text else text


def _format_issue(actor: str, repo: str, payload: dict) -> str:
    issue = payload.get("issue", {})
    title = _first_line(issue.get("title", ""))
    return (
        f"[{repo}] {actor} opened issue #{issue.get('number')}: "
        f"{title} — {issue.get('html_url', '')}"
    )


def _format_pull_request(actor: str, repo: str, payload: dict) -> str:
    pr = payload.get("pull_request", {})
    number = pr.get("number", payload.get("number"))
    title = _first_line(pr.get("title", ""))
    url = pr.get("html_url", "")
    if payload.get("action") == "closed" and pr.get("merged"):
        return f"[{repo}] {actor}'s PR #{number} merged: {title} — {url}"
    return f"[{repo}] {actor} opened PR #{number}: {title} — {url}"
