"""Pure unit tests for plugins/WebPanel/parted.py -- no supybot import,
no plugin test harness needed.
"""
import json

from plugins.WebPanel.parted import PartedTracker


def test_sync_marks_channel_parted_when_absent_from_joined_set(tmp_path):
    tracker = PartedTracker(tmp_path / "parted.json")
    tracker.sync(
        logged_channels=[("libera", "#windrop")],
        joined_channels=[],
        known_networks=["libera"],
    )
    assert tracker.parted_at("libera", "#windrop") is not None


def test_sync_leaves_currently_joined_channel_untracked(tmp_path):
    tracker = PartedTracker(tmp_path / "parted.json")
    tracker.sync(
        logged_channels=[("libera", "#windrop")],
        joined_channels=[("libera", "#windrop")],
        known_networks=["libera"],
    )
    assert tracker.parted_at("libera", "#windrop") is None


def test_sync_ignores_channel_on_unknown_network(tmp_path):
    """A network we're not currently connected to at all must never be
    treated as 'every channel on it just parted' -- that would
    misfire on every temporary disconnect."""
    tracker = PartedTracker(tmp_path / "parted.json")
    tracker.sync(
        logged_channels=[("undernet", "#erdely")],
        joined_channels=[],
        known_networks=["libera"],  # undernet NOT in known_networks
    )
    assert tracker.parted_at("undernet", "#erdely") is None


def test_sync_rejoin_clears_tracking(tmp_path):
    tracker = PartedTracker(tmp_path / "parted.json")
    tracker.mark_parted("libera", "#windrop", when=1000.0)
    assert tracker.parted_at("libera", "#windrop") == 1000.0

    tracker.sync(
        logged_channels=[("libera", "#windrop")],
        joined_channels=[("libera", "#windrop")],
        known_networks=["libera"],
    )
    assert tracker.parted_at("libera", "#windrop") is None


def test_mark_parted_does_not_reset_an_already_tracked_time(tmp_path):
    """Repeated detection (every periodic check) must not keep pushing
    the retention clock forward -- only the FIRST observed part time
    counts."""
    tracker = PartedTracker(tmp_path / "parted.json")
    tracker.mark_parted("libera", "#windrop", when=1000.0)
    tracker.mark_parted("libera", "#windrop", when=2000.0)
    assert tracker.parted_at("libera", "#windrop") == 1000.0


def test_clear_removes_empty_network_entry(tmp_path):
    tracker = PartedTracker(tmp_path / "parted.json")
    tracker.mark_parted("libera", "#windrop", when=1000.0)
    tracker.clear("libera", "#windrop")
    assert tracker.parted_at("libera", "#windrop") is None
    # Internal dict shouldn't leak an empty network key forever.
    assert tracker._parted == {}


def test_due_for_deletion_respects_retention_window(tmp_path):
    import time
    tracker = PartedTracker(tmp_path / "parted.json")
    now = time.time()
    tracker.mark_parted("libera", "#old", when=now - 8 * 86400)
    tracker.mark_parted("libera", "#recent", when=now - 1 * 86400)
    due = tracker.due_for_deletion(retention_secs=7 * 86400)
    assert ("libera", "#old") in due
    assert ("libera", "#recent") not in due


def test_state_persists_across_instances(tmp_path):
    path = tmp_path / "parted.json"
    tracker = PartedTracker(path)
    tracker.mark_parted("undernet", "#erdely", when=500.0)

    reloaded = PartedTracker(path)
    assert reloaded.parted_at("undernet", "#erdely") == 500.0


def test_corrupt_file_loads_as_empty_not_crash(tmp_path):
    path = tmp_path / "parted.json"
    path.write_text("{not valid json")
    tracker = PartedTracker(path)
    assert tracker.parted_at("libera", "#windrop") is None
    # Still writable afterward.
    tracker.mark_parted("libera", "#windrop")
    assert tracker.parted_at("libera", "#windrop") is not None


def test_saved_file_shape_is_nested_by_network(tmp_path):
    path = tmp_path / "parted.json"
    tracker = PartedTracker(path)
    tracker.mark_parted("libera", "#windrop", when=42.0)
    raw = json.loads(path.read_text())
    assert raw == {"libera": {"#windrop": 42.0}}


def test_multiple_channels_and_networks_tracked_independently(tmp_path):
    tracker = PartedTracker(tmp_path / "parted.json")
    tracker.sync(
        logged_channels=[
            ("libera", "#windrop"), ("libera", "#libera"),
            ("undernet", "#erdely"), ("undernet", "#windrop"),
        ],
        joined_channels=[("libera", "#windrop"), ("undernet", "#erdely")],
        known_networks=["libera", "undernet"],
    )
    assert tracker.parted_at("libera", "#windrop") is None
    assert tracker.parted_at("libera", "#libera") is not None
    assert tracker.parted_at("undernet", "#erdely") is None
    assert tracker.parted_at("undernet", "#windrop") is not None
