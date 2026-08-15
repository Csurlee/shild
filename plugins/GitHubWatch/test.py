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
    def test_push_issue_opened_pr_opened_are_relevant(self):
        events = [_push_event(), _issue_event(action="opened"), _pr_event(action="opened")]
        self.assertEqual(len(github.relevant_events(events)), 3)

    def test_issue_closed_is_not_relevant(self):
        events = [_issue_event(action="closed")]
        self.assertEqual(github.relevant_events(events), [])

    def test_pr_synchronize_is_not_relevant(self):
        events = [_pr_event(action="synchronize")]
        self.assertEqual(github.relevant_events(events), [])

    def test_pr_closed_without_merge_is_not_relevant(self):
        events = [_pr_event(action="closed", merged=False)]
        self.assertEqual(github.relevant_events(events), [])

    def test_pr_closed_with_merge_is_relevant(self):
        events = [_pr_event(action="closed", merged=True)]
        self.assertEqual(len(github.relevant_events(events)), 1)

    def test_since_id_excludes_already_seen(self):
        events = [_push_event(event_id="103"), _push_event(event_id="102"), _push_event(event_id="101")]
        result = github.relevant_events(events, since_id=101)
        self.assertEqual([e["id"] for e in result], ["103", "102"])

    def test_since_id_none_includes_everything(self):
        events = [_push_event(event_id="103"), _push_event(event_id="102")]
        result = github.relevant_events(events, since_id=None)
        self.assertEqual(len(result), 2)

    def test_malformed_id_is_skipped_not_crashed(self):
        events = [{"id": "not-a-number", "type": "PushEvent", "payload": {}}]
        self.assertEqual(github.relevant_events(events), [])


class MaxEventIdTest(unittest.TestCase):
    def test_finds_max_across_mixed_order(self):
        events = [_push_event(event_id="50"), _push_event(event_id="200"), _push_event(event_id="10")]
        self.assertEqual(github.max_event_id(events), 200)

    def test_empty_list_is_none(self):
        self.assertIsNone(github.max_event_id([]))

    def test_all_malformed_is_none(self):
        self.assertIsNone(github.max_event_id([{"id": "x"}, {}]))


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


class SeenStateStoreTest(unittest.TestCase):
    def test_unknown_repo_is_none(self):
        with tempfile.TemporaryDirectory() as d:
            store = SeenStateStore(str(Path(d) / "state.json"))
            self.assertIsNone(store.last_seen("owner/repo"))

    def test_round_trip_across_instances(self):
        with tempfile.TemporaryDirectory() as d:
            path = str(Path(d) / "state.json")
            store1 = SeenStateStore(path)
            store1.mark_seen("owner/repo", 42)
            store2 = SeenStateStore(path)
            self.assertEqual(store2.last_seen("owner/repo"), 42)

    def test_mark_seen_never_goes_backwards(self):
        with tempfile.TemporaryDirectory() as d:
            store = SeenStateStore(str(Path(d) / "state.json"))
            store.mark_seen("owner/repo", 50)
            store.mark_seen("owner/repo", 10)
            self.assertEqual(store.last_seen("owner/repo"), 50)

    def test_corrupt_file_is_treated_as_empty(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "state.json"
            path.write_text("{not valid json")
            store = SeenStateStore(str(path))
            self.assertIsNone(store.last_seen("owner/repo"))


if __name__ == "__main__":
    unittest.main()
