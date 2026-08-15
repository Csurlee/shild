"""Unit tests for scripts/record_human_review.py -- the append-only human
review recorder added 2026-08-09 alongside the undernet/#bookz review.
"""
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.record_human_review import main  # noqa: E402


def _read_lines(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def test_records_a_single_review(tmp_path):
    out = tmp_path / "human_reviews.jsonl"
    main([
        "--target-ts", "123.0", "--network", "undernet", "--channel", "#bookz",
        "--nick", "sinsal", "--ident", "~sinsal", "--host", "146.70.237.38",
        "--verdict", "ban", "--original-action", "ban",
        "--reviewer", "csurlee", "--note", "confirmed VPN", "--out", str(out),
    ])
    rows = _read_lines(out)
    assert len(rows) == 1
    row = rows[0]
    assert row["nick"] == "sinsal"
    assert row["host"] == "146.70.237.38"
    assert row["verdict"] == "ban"
    assert row["original_fused_action"] == "ban"
    assert row["reviewer"] == "csurlee"
    assert row["target_ts"] == 123.0
    assert "ts" in row  # review timestamp, distinct from target_ts


def test_appends_without_truncating_earlier_reviews(tmp_path):
    out = tmp_path / "human_reviews.jsonl"
    main(["--target-ts", "1", "--network", "undernet", "--channel", "#bookz",
          "--nick", "a", "--host", "1.1.1.1", "--verdict", "ban",
          "--reviewer", "csurlee", "--out", str(out)])
    main(["--target-ts", "2", "--network", "undernet", "--channel", "#undernet",
          "--nick", "b", "--host", "2.2.2.2", "--verdict", "allow",
          "--reviewer", "csurlee", "--out", str(out)])
    rows = _read_lines(out)
    assert [r["nick"] for r in rows] == ["a", "b"]


def test_optional_fields_default_sensibly(tmp_path):
    out = tmp_path / "human_reviews.jsonl"
    main(["--target-ts", "1", "--network", "undernet", "--channel", "#bookz",
          "--nick", "a", "--host", "1.1.1.1", "--verdict", "warn",
          "--reviewer", "csurlee", "--out", str(out)])
    row = _read_lines(out)[0]
    assert row["ident"] is None
    assert row["original_fused_action"] is None
    assert row["note"] == ""
