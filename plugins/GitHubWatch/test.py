"""Offline tests for GitHubWatch's pure logic (github.py's filtering/
formatting, state.py's persisted cursor). Neither module imports
supybot, so these are plain unittest -- no live network, no IRC server,
same "hermetic" spirit as plugins/Shild/test.py's offline suite.
"""
import json
import tempfile
import unittest
from pathlib import Path

from . import github
from .state import SeenStateStore


def _push_event(event_id="100", ref="refs/heads/main", commits=None, before="a" * 40, head="b" * 40):
    return {
        "id": event_id,
        "type": "PushEvent",
        "actor": {"login": "alice"},
        "repo": {"name": "owner/repo"},
        "payload": {
            "ref": ref,
            "size": len(commits) if commits is not None else 1,
            "commits": commits if commits is not None else [{"message": "fix bug"}],
            "before": before,
            "head": head,
        },
    }


def _reduced_push_event(event_id="100", ref="refs/heads/main", before="a" * 40, head="b" * 40):
    """Matches the REAL payload shape GitHub returns for a private repo
    polled with a token (confirmed live 2026-08-02) -- no "commits"/"size"
    keys at all, not present-but-empty. See github.py's _format_push.
    """
    return {
        "id": event_id,
        "type": "PushEvent",
        "actor": {"login": "alice"},
        "repo": {"name": "owner/repo"},
        "payload": {"ref": ref, "before": before, "head": head, "push_id": 1},
    }


def _issue_event(event_id="101", action="opened", number=42, title="Something broke"):
    return {
        "id": event_id,
        "type": "IssuesEvent",
        "actor": {"login": "bob"},
        "repo": {"name": "owner/repo"},
        "payload": {
            "action": action,
            "issue": {"number": number, "title": title, "html_url": f"https://github.com/owner/repo/issues/{number}"},
        },
    }


def _pr_event(event_id="102", action="opened", number=7, title="Add feature", merged=False):
    return {
        "id": event_id,
        "type": "PullRequestEvent",
        "actor": {"login": "carol"},
        "repo": {"name": "owner/repo"},
        "payload": {
            "action": action,
            "number": number,
            "pull_request": {
                "number": number, "title": title, "merged": merged,
                "html_url": f"https://github.com/owner/repo/pull/{number}",
            },
        },
    }


class RelevantEventsTest(unittest.TestCase):
    # Every non-"first poll of an empty since_ids" case below needs a
    # since_ids floor per type it expects to see -- relevant_events()
    # treats a missing type entry as "never seeded, don't replay" (see
    # its own docstring). -1 is a floor every real GitHub id (always
    # positive) clears.
    _SEED_ALL = {"PushEvent": -1, "IssuesEvent": -1, "PullRequestEvent": -1}

    def test_push_issue_opened_pr_opened_are_relevant(self):
        events = [_push_event(), _issue_event(action="opened"), _pr_event(action="opened")]
        self.assertEqual(len(github.relevant_events(events, since_ids=self._SEED_ALL)), 3)

    def test_issue_closed_is_not_relevant(self):
        events = [_issue_event(action="closed")]
        self.assertEqual(github.relevant_events(events, since_ids=self._SEED_ALL), [])

    def test_pr_synchronize_is_not_relevant(self):
        events = [_pr_event(action="synchronize")]
        self.assertEqual(github.relevant_events(events, since_ids=self._SEED_ALL), [])

    def test_pr_closed_without_merge_is_not_relevant(self):
        events = [_pr_event(action="closed", merged=False)]
        self.assertEqual(github.relevant_events(events, since_ids=self._SEED_ALL), [])

    def test_pr_closed_with_merge_is_relevant(self):
        events = [_pr_event(action="closed", merged=True)]
        self.assertEqual(len(github.relevant_events(events, since_ids=self._SEED_ALL)), 1)

    def test_since_id_excludes_already_seen(self):
        events = [_push_event(event_id="103"), _push_event(event_id="102"), _push_event(event_id="101")]
        result = github.relevant_events(events, since_ids={"PushEvent": 101})
        self.assertEqual([e["id"] for e in result], ["103", "102"])

    def test_since_ids_none_includes_nothing(self):
        # 2026-08-24 fix: a type with no floor at all (since_ids=None, or
        # missing that type's key) is treated as "never independently
        # seeded" and never included -- this is the correct fail-safe
        # behavior (seed, don't replay), replacing the old, unsafe
        # "since_id=None means include everything" semantics.
        events = [_push_event(event_id="103"), _push_event(event_id="102")]
        result = github.relevant_events(events, since_ids=None)
        self.assertEqual(result, [])

    def test_malformed_id_is_skipped_not_crashed(self):
        events = [{"id": "not-a-number", "type": "PushEvent", "payload": {}}]
        self.assertEqual(github.relevant_events(events, since_ids=self._SEED_ALL), [])

    # ---- regression: cross-event-type id ranges are NOT comparable
    # (2026-08-24, found live against Csurlee/shild's real event
    # history -- see github.py's relevant_events docstring) ----

    def test_a_high_id_pushevent_cursor_never_suppresses_a_lower_id_issuesevent(self):
        # Real observed shape: a PushEvent's id can be billions higher
        # than an IssuesEvent's id from almost the same moment. A single
        # combined cursor at the push's id would make relevant_events
        # (old behavior) discard the issue event outright, even though
        # it was never actually seen before.
        push_cursor = 18700998032  # a real observed PushEvent id
        new_issue_id = 13751509200  # a real observed IssuesEvent id, LOWER
        events = [_issue_event(event_id=str(new_issue_id), action="opened")]
        since_ids = {"PushEvent": push_cursor, "IssuesEvent": 1}  # issue floor is genuinely low
        result = github.relevant_events(events, since_ids=since_ids)
        self.assertEqual(len(result), 1)

    def test_each_event_type_is_filtered_against_its_own_floor_only(self):
        events = [
            _push_event(event_id="18700998032"),
            _issue_event(event_id="13751509200", action="opened"),
        ]
        # Push's own floor already covers it (not new); issue's own floor
        # does not (it IS new) -- only the issue should come back.
        since_ids = {"PushEvent": 18700998032, "IssuesEvent": 1}
        result = github.relevant_events(events, since_ids=since_ids)
        self.assertEqual([e["type"] for e in result], ["IssuesEvent"])


class MaxEventIdsByTypeTest(unittest.TestCase):
    def test_finds_max_per_type_independently(self):
        events = [
            _push_event(event_id="50"), _push_event(event_id="200"), _push_event(event_id="10"),
            _issue_event(event_id="5", action="opened"),
        ]
        self.assertEqual(github.max_event_ids_by_type(events),
                          {"PushEvent": 200, "IssuesEvent": 5})

    def test_empty_list_is_empty_dict(self):
        self.assertEqual(github.max_event_ids_by_type([]), {})

    def test_all_malformed_is_empty_dict(self):
        self.assertEqual(github.max_event_ids_by_type([{"id": "x", "type": "PushEvent"}, {}]), {})

    def test_a_much_higher_id_type_does_not_affect_another_types_max(self):
        # The exact real-world shape this whole fix is about: these two
        # ids differ by ~5 billion despite being minutes apart.
        events = [
            _push_event(event_id="18700998032"),
            _issue_event(event_id="13751509200", action="opened"),
        ]
        result = github.max_event_ids_by_type(events)
        self.assertEqual(result["PushEvent"], 18700998032)
        self.assertEqual(result["IssuesEvent"], 13751509200)


class FormatEventTest(unittest.TestCase):
    def test_push_single_commit(self):
        line = github.format_event(_push_event(commits=[{"message": "fix bug\nlonger body"}]))
        self.assertIn("[owner/repo]", line)
        self.assertIn("alice pushed 1 commit to main", line)
        self.assertIn("fix bug", line)
        self.assertNotIn("longer body", line)  # only first line of commit message

    def test_push_multiple_commits_truncates(self):
        commits = [{"message": f"commit {i}"} for i in range(5)]
        line = github.format_event(_push_event(commits=commits), max_commits_shown=2)
        self.assertIn("pushed 5 commits", line)
        self.assertIn("commit 0", line)
        self.assertIn("commit 1", line)
        self.assertIn("+3 more", line)
        self.assertNotIn("commit 4", line)

    def test_push_includes_compare_url_when_not_new_branch(self):
        line = github.format_event(_push_event(before="a" * 40, head="b" * 40))
        self.assertIn("compare/aaaaaaa...bbbbbbb", line)

    def test_push_new_branch_has_no_compare_url(self):
        line = github.format_event(_push_event(before="0" * 40, head="b" * 40))
        self.assertNotIn("compare/", line)

    def test_push_reduced_private_repo_payload_does_not_claim_zero_commits(self):
        # Regression: GitHub omits commits/size entirely for a private repo
        # polled with a token -- confirmed live 2026-08-02 -- and the old
        # code read that as len([]) == 0 and announced "pushed 0 commits".
        line = github.format_event(_reduced_push_event())
        self.assertIn("[owner/repo] alice pushed to main", line)
        self.assertIn("compare/aaaaaaa...bbbbbbb", line)
        self.assertNotIn("0 commit", line)

    def test_issue_opened(self):
        line = github.format_event(_issue_event(number=42, title="Something broke"))
        self.assertIn("bob opened issue #42", line)
        self.assertIn("Something broke", line)
        self.assertIn("issues/42", line)

    def test_pr_opened(self):
        line = github.format_event(_pr_event(action="opened", number=7, title="Add feature"))
        self.assertIn("carol opened PR #7", line)
        self.assertIn("Add feature", line)

    def test_pr_merged(self):
        line = github.format_event(_pr_event(action="closed", number=7, merged=True))
        self.assertIn("carol's PR #7 merged", line)

    def test_issue_title_with_embedded_newline_is_sanitized(self):
        # Regression, 2026-08-24: push commit messages already stripped
        # to the first line; issue/PR titles didn't -- an untreated
        # embedded newline used to make the whole announcement silently
        # vanish (plugin.py's broad except-Exception around formatting)
        # instead of just the newline being stripped.
        line = github.format_event(
            _issue_event(number=42, title="Something broke\nfake extra content"))
        self.assertIn("bob opened issue #42", line)
        self.assertIn("Something broke", line)
        self.assertNotIn("fake extra content", line)
        self.assertNotIn("\n", line)

    def test_pr_title_with_embedded_newline_is_sanitized(self):
        line = github.format_event(
            _pr_event(action="opened", number=7, title="Add feature\nfake extra content"))
        self.assertIn("carol opened PR #7", line)
        self.assertIn("Add feature", line)
        self.assertNotIn("fake extra content", line)
        self.assertNotIn("\n", line)


class SeenStateStoreTest(unittest.TestCase):
    def test_unknown_repo_is_empty_dict(self):
        with tempfile.TemporaryDirectory() as d:
            store = SeenStateStore(str(Path(d) / "state.json"))
            self.assertEqual(store.last_seen("owner/repo"), {})

    def test_round_trip_across_instances(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "state.json")
            store1 = SeenStateStore(path)
            store1.mark_seen("owner/repo", "PushEvent", 42)
            store2 = SeenStateStore(path)
            self.assertEqual(store2.last_seen("owner/repo"), {"PushEvent": 42})

    def test_mark_seen_never_goes_backwards(self):
        with tempfile.TemporaryDirectory() as d:
            store = SeenStateStore(str(Path(d) / "state.json"))
            store.mark_seen("owner/repo", "PushEvent", 50)
            store.mark_seen("owner/repo", "PushEvent", 10)
            self.assertEqual(store.last_seen("owner/repo"), {"PushEvent": 50})

    def test_corrupt_file_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.json"
            path.write_text("{not valid json")
            store = SeenStateStore(str(path))
            self.assertEqual(store.last_seen("owner/repo"), {})

    # ---- per-type tracking (2026-08-24 fix) ----

    def test_different_event_types_track_independent_cursors(self):
        with tempfile.TemporaryDirectory() as d:
            store = SeenStateStore(str(Path(d) / "state.json"))
            store.mark_seen("owner/repo", "PushEvent", 18700998032)
            store.mark_seen("owner/repo", "IssuesEvent", 13751509200)
            seen = store.last_seen("owner/repo")
            self.assertEqual(seen["PushEvent"], 18700998032)
            self.assertEqual(seen["IssuesEvent"], 13751509200)

    def test_old_flat_int_format_is_discarded_not_migrated(self):
        # Regression, 2026-08-24: the pre-fix format was {repo: int} --
        # a single combined cursor, which was the bug itself. Loading it
        # must NOT try to treat that int as a seed for any one type
        # (that would just carry the poisoning forward); it must be
        # discarded, falling back to "never seen this repo", same as a
        # corrupt file.
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.json"
            path.write_text(json.dumps({"owner/repo": 18700998032}))
            store = SeenStateStore(str(path))
            self.assertEqual(store.last_seen("owner/repo"), {})


if __name__ == "__main__":
    unittest.main()
