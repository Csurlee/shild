"""Pure unit tests for plugins/WebPanel/audit.py -- no supybot import,
no plugin test harness needed.
"""
import json
import threading

from plugins.WebPanel.audit import AuditLog


def test_record_appends_one_jsonl_line(tmp_path):
    path = tmp_path / "actions.jsonl"
    log = AuditLog(path)
    log.record(action="killswitch_set", actor="admin", client_ip="10.0.0.5",
               detail={"key": "shild_kill_switch", "value": False})

    lines = path.read_text().splitlines()
    assert len(lines) == 1
    entry = json.loads(lines[0])
    assert entry["action"] == "killswitch_set"
    assert entry["actor"] == "admin"
    assert entry["client_ip"] == "10.0.0.5"
    assert entry["detail"] == {"key": "shild_kill_switch", "value": False}
    assert "ts" in entry


def test_record_defaults_detail_to_empty_dict(tmp_path):
    path = tmp_path / "actions.jsonl"
    log = AuditLog(path)
    log.record(action="term_removed", actor="admin", client_ip="10.0.0.5")
    entry = json.loads(path.read_text().splitlines()[0])
    assert entry["detail"] == {}


def test_multiple_records_append_in_order(tmp_path):
    path = tmp_path / "actions.jsonl"
    log = AuditLog(path)
    log.record(action="a", actor="x", client_ip="1.1.1.1")
    log.record(action="b", actor="x", client_ip="1.1.1.1")
    lines = [json.loads(l) for l in path.read_text().splitlines()]
    assert [e["action"] for e in lines] == ["a", "b"]


def test_never_raises_on_non_json_serializable_detail(tmp_path):
    """Regression, 2026-08-24 (found via a post-ship code review): record()
    promises to never raise, but json.dumps() raises TypeError for a
    non-serializable value -- previously uncaught (only OSError was
    caught). default=str means the entry still gets logged, stringified,
    rather than silently dropped or raising into the caller's real write."""
    path = tmp_path / "actions.jsonl"
    log = AuditLog(path)

    class Unserializable:
        def __str__(self):
            return "<weird-object>"

    log.record(action="x", actor="y", client_ip="1.1.1.1",
               detail={"thing": Unserializable()})  # must not raise
    entry = json.loads(path.read_text().splitlines()[0])
    assert entry["detail"]["thing"] == "<weird-object>"


def test_never_raises_on_unwritable_path():
    # A path under a file (not a directory) can never be created --
    # record() must swallow this, not propagate it into the caller's
    # actual write action.
    log = AuditLog("/dev/null/not-a-real-dir/actions.jsonl")
    log.record(action="x", actor="y", client_ip="1.1.1.1")  # must not raise


def test_creates_parent_directory(tmp_path):
    path = tmp_path / "nested" / "dir" / "actions.jsonl"
    log = AuditLog(path)
    log.record(action="x", actor="y", client_ip="1.1.1.1")
    assert path.exists()


def test_concurrent_records_all_land(tmp_path):
    path = tmp_path / "actions.jsonl"
    log = AuditLog(path)

    def worker(n):
        for i in range(50):
            log.record(action=f"a{n}-{i}", actor="x", client_ip="1.1.1.1")

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = path.read_text().splitlines()
    assert len(lines) == 200
    for line in lines:
        json.loads(line)  # every line is valid, complete JSON -- no interleaving
