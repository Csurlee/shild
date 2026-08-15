"""Unit tests for plugins/WebPanel/stats.py -- the bounded JSONL tail
reader backing /panel/scans, and SummaryCache, the background-refresh
mechanism that keeps expensive whole/large-corpus computations off
Limnoria's serial HTTP request thread (see http.py's module docstring
for why that matters).
"""
import json
import time

from plugins.WebPanel.stats import SummaryCache, gate_report, summarize_tail, tail_records


def _write_jsonl(path, records):
    with open(path, "w") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")


def _row(ts, action="allow", source="classifier", p_ban=0.1, p_warn=0.1, **extra):
    row = {
        "ts": ts, "network": "libera", "channel": "#windrop",
        "nick": "n", "host": "1.2.3.4", "ident": "~n", "account": None,
        "event_type": "join", "label_quality": "ok",
        "fused": {"action": action, "source": source},
        "classifier": {"probs": [1 - p_ban - p_warn, p_warn, p_ban]},
    }
    row.update(extra)
    return row


# ---- tail_records ----

def test_tail_records_reads_valid_rows(tmp_path):
    p = tmp_path / "shadow.jsonl"
    _write_jsonl(p, [_row(1.0), _row(2.0), _row(3.0)])
    records = tail_records(str(p), n=10)
    assert len(records) == 3
    assert records[-1]["ts"] == 3.0


def test_tail_records_skips_malformed_middle_line(tmp_path):
    p = tmp_path / "shadow.jsonl"
    p.write_text(
        json.dumps(_row(1.0)) + "\n"
        + "{not valid json\n"
        + json.dumps(_row(3.0)) + "\n"
    )
    records = tail_records(str(p), n=10)
    assert [r["ts"] for r in records] == [1.0, 3.0]


def test_tail_records_skips_partial_final_line(tmp_path):
    p = tmp_path / "shadow.jsonl"
    with open(p, "wb") as f:
        f.write((json.dumps(_row(1.0)) + "\n").encode())
        f.write(b'{"ts": 2.0, "truncated')  # no trailing newline -- torn write
    records = tail_records(str(p), n=10)
    assert [r["ts"] for r in records] == [1.0]


def test_tail_records_respects_n(tmp_path):
    p = tmp_path / "shadow.jsonl"
    _write_jsonl(p, [_row(float(i)) for i in range(20)])
    records = tail_records(str(p), n=5)
    assert len(records) == 5
    assert records[-1]["ts"] == 19.0


def test_tail_records_missing_file_returns_empty():
    assert tail_records("/does/not/exist.jsonl", n=10) == []


def test_tail_records_n_zero_returns_empty(tmp_path):
    p = tmp_path / "shadow.jsonl"
    _write_jsonl(p, [_row(1.0)])
    assert tail_records(str(p), n=0) == []


# ---- summarize_tail / gate_report (thin wrappers over scripts/*) ----

def test_summarize_tail_produces_expected_shape(tmp_path):
    p = tmp_path / "shadow.jsonl"
    _write_jsonl(p, [_row(1.0, action="allow"), _row(2.0, action="ban")])
    result = summarize_tail(str(p))
    assert result["total_rows"] == 2
    assert result["fused_action"]["allow"] == 1
    assert result["fused_action"]["ban"] == 1


def test_summarize_tail_empty_file(tmp_path):
    p = tmp_path / "shadow.jsonl"
    p.write_text("")
    result = summarize_tail(str(p))
    assert result["total_rows"] == 0


def test_gate_report_produces_expected_shape(tmp_path):
    p = tmp_path / "shadow.jsonl"
    row = _row(1.0)
    row["fused_raw"] = {"action": "ban", "confidence": 0.9, "source": "classifier"}
    row["fused"] = {"action": "warn", "confidence": 0.9, "source": "classifier"}
    row["gate"] = {"applied": True, "rule": "downgrade"}
    _write_jsonl(p, [row])
    result = gate_report(str(p))
    assert result["total_rows"] == 1
    assert result["gated"] == 1


# ---- SummaryCache ----

def test_summary_cache_starts_empty():
    cache = SummaryCache(path_fn=lambda: "/nope", compute=lambda p: {"x": 1},
                          refresh_secs=1)
    result, computed_at, error = cache.get()
    assert result is None
    assert computed_at == 0.0
    assert error is None


def test_summary_cache_computes_on_start(tmp_path):
    p = tmp_path / "data.jsonl"
    p.write_text("")
    calls = {"n": 0}

    def compute(path):
        calls["n"] += 1
        return {"seen": path}

    cache = SummaryCache(path_fn=lambda: str(p), compute=compute, refresh_secs=60)
    try:
        cache.start()
        deadline = time.time() + 2.0
        while calls["n"] == 0 and time.time() < deadline:
            time.sleep(0.01)
        result, computed_at, error = cache.get()
        assert calls["n"] == 1
        assert result == {"seen": str(p)}
        assert computed_at > 0
        assert error is None
    finally:
        cache.stop()


def test_summary_cache_skips_recompute_when_file_unchanged(tmp_path):
    p = tmp_path / "data.jsonl"
    p.write_text("same content")
    calls = {"n": 0}

    def compute(path):
        calls["n"] += 1
        return {"call": calls["n"]}

    cache = SummaryCache(path_fn=lambda: str(p), compute=compute, refresh_secs=0.05)
    try:
        cache.start()
        time.sleep(0.3)  # several refresh intervals, file never changes
        result, _, _ = cache.get()
        # Should have computed once (file unchanged after that), not once
        # per interval tick.
        assert calls["n"] == 1
        assert result == {"call": 1}
    finally:
        cache.stop()


def test_summary_cache_recomputes_when_file_changes(tmp_path):
    p = tmp_path / "data.jsonl"
    p.write_text("v1")
    calls = {"n": 0}

    def compute(path):
        calls["n"] += 1
        return {"call": calls["n"]}

    cache = SummaryCache(path_fn=lambda: str(p), compute=compute, refresh_secs=0.05)
    try:
        cache.start()
        deadline = time.time() + 2.0
        while calls["n"] == 0 and time.time() < deadline:
            time.sleep(0.01)
        assert calls["n"] == 1
        time.sleep(0.1)
        p.write_text("v2, different size")
        deadline = time.time() + 2.0
        while calls["n"] < 2 and time.time() < deadline:
            time.sleep(0.01)
        assert calls["n"] >= 2
    finally:
        cache.stop()


def test_summary_cache_keeps_last_good_result_on_compute_error(tmp_path):
    p = tmp_path / "data.jsonl"
    p.write_text("v1")
    state = {"fail": False}

    def compute(path):
        if state["fail"]:
            raise ValueError("boom")
        return {"ok": True}

    cache = SummaryCache(path_fn=lambda: str(p), compute=compute, refresh_secs=0.05)
    try:
        cache.start()
        deadline = time.time() + 2.0
        while cache.get()[0] is None and time.time() < deadline:
            time.sleep(0.01)
        assert cache.get()[0] == {"ok": True}

        state["fail"] = True
        p.write_text("v2, different size")  # force a recompute attempt
        deadline = time.time() + 2.0
        while cache.get()[2] is None and time.time() < deadline:
            time.sleep(0.01)
        result, _, error = cache.get()
        assert result == {"ok": True}  # previous good result retained
        assert error is not None and "boom" in error
    finally:
        cache.stop()


def test_summary_cache_stop_joins_thread(tmp_path):
    p = tmp_path / "data.jsonl"
    p.write_text("x")
    cache = SummaryCache(path_fn=lambda: str(p), compute=lambda path: {}, refresh_secs=60)
    cache.start()
    cache.stop()
    assert cache._thread is None
