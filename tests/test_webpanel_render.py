"""Unit tests for plugins/WebPanel/render.py -- proves every insertion
point escapes untrusted content (nicks, channel names, log lines can all
carry attacker-controlled text from any IRC user) and that stray '%'
characters -- which show up in normal chat constantly -- never break a
formatter the way httpserver.py's own %-substitution templates would.
"""
from plugins.WebPanel import render


def test_escape_handles_script_tag():
    out = render.escape("<script>alert(1)</script>")
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_page_escapes_title_and_heading():
    body = render.page("<b>title</b>", "<i>heading</i>", "<p>trusted body</p>")
    text = body.decode("utf-8")
    assert "<b>title</b>" not in text
    assert "<i>heading</i>" not in text
    assert "<p>trusted body</p>" in text  # body is passed through as-is


def test_page_percent_in_content_does_not_break_formatting():
    # Reproduces exactly the class of bug httpserver.get_template's bare
    # %-substitution has: content containing a raw "%" must not raise
    # (str.format, unlike %-substitution, treats "%" as an ordinary
    # character -- this test pins that behavior).
    body = render.page("100% uptime", "99% done", "<p>50% off</p>")
    text = body.decode("utf-8")
    assert "100% uptime" in text
    assert "50% off" in text


def test_simple_message_escapes():
    out = render.simple_message("<script>evil()</script>")
    assert "<script>" not in out


def test_logs_index_escapes_channel_and_network_names():
    entries = [("libera", "<script>alert(1)</script>", 123, 1700000000.0, None)]
    html = render.logs_index(entries, retention_days=7)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_logs_index_empty_shows_placeholder():
    html = render.logs_index([], retention_days=7)
    assert "No channel logs" in html


def test_logs_index_builds_safe_urls():
    entries = [("libera", "#foo/bar", 1, 1700000000.0, None)]
    html = render.logs_index(entries, retention_days=7)
    # The slash in the (illegal for a real channel, but defensively
    # tested anyway) channel name must be percent-encoded in the URL,
    # not passed through raw -- otherwise it would look like an extra
    # path segment.
    assert "/panel/log/libera/%23foo%2Fbar" in html


def test_logs_index_active_channel_has_no_parted_annotation():
    entries = [("libera", "#windrop", 1, 1700000000.0, None)]
    html = render.logs_index(entries, retention_days=7)
    assert "Parted" not in html


def test_logs_index_parted_channel_shows_deletion_date():
    # parted_since = a fixed epoch; retention_days=7 -> deletion date is
    # exactly 7*86400 seconds later.
    parted_since = 1700000000.0
    entries = [("libera", "#old", 1, 1700000000.0, parted_since)]
    html = render.logs_index(entries, retention_days=7)
    import datetime
    expected = datetime.datetime.fromtimestamp(
        parted_since + 7 * 86400).strftime("%Y-%m-%d")
    assert "Parted" in html
    assert expected in html


def test_logs_index_parted_channel_name_still_escaped():
    html = render.logs_index(
        [("libera", "<script>x</script>", 1, 1700000000.0, 1700000000.0)],
        retention_days=7,
    )
    assert "<script>x</script>" not in html
    assert "&lt;script&gt;" in html


def test_log_tail_escapes_log_line_content():
    lines = ["<script>document.location='evil'</script>", "normal line"]
    html = render.log_tail("libera", "#windrop", lines, requested_n=2)
    assert "<script>" not in html
    assert "normal line" in html


def test_log_tail_escapes_channel_with_percent():
    # IRC content full of "%" must not raise or corrupt the page.
    html = render.log_tail("libera", "#windrop", ["100% done", "50% off"], requested_n=2)
    assert "100% done" in html
    assert "50% off" in html


def test_plain_text_block_escapes_report_content():
    text = "<img src=x onerror=alert(1)>"
    html = render.plain_text_block("2026-08-06-report.md", text)
    assert "<img" not in html
    assert "&lt;img" in html


def test_plain_text_block_handles_percent_heavy_content():
    text = "100% of 50% is 25%, and %s %d are not format specifiers here."
    html = render.plain_text_block("weird.json", text)
    assert "100%" in html


# ---- page() refresh tag ----

def test_page_no_refresh_by_default():
    body = render.page("t", "h", "<p>x</p>")
    assert b"http-equiv" not in body


def test_page_includes_refresh_tag_when_given():
    body = render.page("t", "h", "<p>x</p>", refresh_secs=10)
    assert b'<meta http-equiv="refresh" content="10">' in body


def test_page_refresh_zero_or_none_omits_tag():
    assert b"http-equiv" not in render.page("t", "h", "<p>x</p>", refresh_secs=0)
    assert b"http-equiv" not in render.page("t", "h", "<p>x</p>", refresh_secs=None)


# ---- live_index / live_channel / live_disabled / live_decisions ----

def test_live_index_empty():
    assert "No channels" in render.live_index([], retention_days=7)


def test_live_index_lists_pairs_and_decision_feed_link():
    html = render.live_index(
        [("libera", "#windrop", None), ("undernet", "#relay", None)], retention_days=7,
    )
    assert "/panel/live/libera/%23windrop" in html
    assert "/panel/live/undernet/%23relay" in html
    assert "/panel/live/decisions" in html


def test_live_index_escapes_malicious_channel_name():
    html = render.live_index(
        [("libera", "<script>alert(1)</script>", None)], retention_days=7,
    )
    assert "<script>alert(1)</script>" not in html


def test_live_index_active_channel_has_no_parted_annotation():
    html = render.live_index([("libera", "#windrop", None)], retention_days=7)
    assert "Parted" not in html


def test_live_index_parted_channel_shows_deletion_date():
    html = render.live_index(
        [("libera", "#old", 1700000000.0)], retention_days=7,
    )
    assert "Parted" in html


def test_live_channel_escapes_lines():
    html = render.live_channel("libera", "#windrop",
                                ["<script>x</script>", "normal"], refresh_secs=10)
    assert "<script>x</script>" not in html
    assert "normal" in html
    assert "10" in html


def test_live_disabled_mentions_channel():
    html = render.live_disabled("libera", "#windrop")
    assert "#windrop" in html
    assert "disabled" in html


def test_live_decisions_empty():
    assert "No events" in render.live_decisions([], refresh_secs=10)


def test_live_decisions_renders_rows_newest_first_as_given():
    events = [
        (2.0, "libera", "#windrop", "join", "bob", "2.2.2.2", ""),
        (1.0, "libera", "#windrop", "join", "alice", "1.1.1.1", ""),
    ]
    html = render.live_decisions(events, refresh_secs=10)
    assert html.index("bob") < html.index("alice")


def test_live_decisions_escapes_detail_field():
    events = [(1.0, "libera", "#windrop", "join", "n", "h", "<script>x</script>")]
    html = render.live_decisions(events, refresh_secs=10)
    assert "<script>x</script>" not in html


# ---- commands_list ----

def test_commands_list_empty():
    assert "No public plugins" in render.commands_list([])


def test_commands_list_groups_by_plugin_and_escapes():
    entries = [
        ("Shild", [
            ("shildstatus", "takes no arguments\n\nReports status."),
            ("shildreport", "[<date>]\n\nShows a report."),
        ]),
        ("<script>evil</script>", [("x", None)]),
    ]
    html = render.commands_list(entries)
    assert "shildstatus" in html
    assert "shildreport" in html
    assert "<script>evil</script>" not in html


def test_commands_list_handles_plugin_with_no_commands():
    html = render.commands_list([("Empty", [])])
    assert "(no commands)" in html


def test_commands_list_shows_syntax_and_description():
    entries = [("Shild", [("shildcheck", "<nick or host/IP>\n\nRuns a manual lookup.")])]
    html = render.commands_list(entries)
    assert "shildcheck &lt;nick or host/IP&gt;" in html
    assert "Runs a manual lookup." in html


def test_commands_list_missing_docstring_shows_placeholder():
    entries = [("Shild", [("mystery", None)])]
    html = render.commands_list(entries)
    assert "no help available" in html


def test_command_syntax_and_help_splits_first_line_from_rest():
    syntax, desc = render._command_syntax_and_help(
        "<a> <b>\n\nDoes a thing.\nAcross two lines."
    )
    assert syntax == "<a> <b>"
    assert desc == "Does a thing. Across two lines."


def test_command_syntax_and_help_empty_doc():
    syntax, desc = render._command_syntax_and_help(None)
    assert syntax == ""
    assert "no help available" in desc


# ---- activity_heatmap ----

def test_activity_heatmap_none_shows_placeholder():
    assert "No timestamped events" in render.activity_heatmap(None)


def test_activity_heatmap_all_zero_shows_placeholder():
    grid = [[0] * 24 for _ in range(7)]
    assert "No timestamped events" in render.activity_heatmap(grid)


def test_activity_heatmap_renders_grid_with_counts():
    grid = [[0] * 24 for _ in range(7)]
    grid[0][3] = 5  # Monday 03:00
    grid[6][23] = 1  # Sunday 23:00
    html = render.activity_heatmap(grid)
    assert "Mon" in html and "Sun" in html
    assert ">5<" in html
    assert 'class="heat-4"' in html  # 5 is the max -> hottest bucket
    assert 'class="heat-1"' in html  # 1 is 20% of max -> coolest non-zero bucket


def test_activity_heatmap_quantizes_by_ratio_to_max():
    grid = [[0] * 24 for _ in range(7)]
    grid[0][0] = 10
    grid[0][1] = 8   # 80% -> heat-4
    grid[0][2] = 5   # 50% -> heat-3
    grid[0][3] = 3   # 30% -> heat-2
    grid[0][4] = 1   # 10% -> heat-1
    html = render.activity_heatmap(grid)
    for level in ("heat-1", "heat-2", "heat-3", "heat-4"):
        assert f'class="{level}"' in html


def test_activity_heatmap_short_grid_does_not_crash():
    # Defensive: a malformed/short grid must degrade, not raise -- this
    # renders from a background-cached dict it doesn't control the shape
    # of any more than aggregate_block does for its own inputs.
    html = render.activity_heatmap([[1, 2, 3]])
    assert "heat-" in html
