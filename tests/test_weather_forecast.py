"""Pure unit tests for plugins/Weather/forecast.py -- no supybot import."""
import locale

from plugins.Weather.forecast import daily_forecast, representative_icon, DayForecast


def _entry(dt, temp, temp_min=None, temp_max=None, icon="01d"):
    return {
        "dt": dt,
        "main": {
            "temp": temp,
            "temp_min": temp_min if temp_min is not None else temp,
            "temp_max": temp_max if temp_max is not None else temp,
        },
        "weather": [{"icon": icon}],
    }


def test_entries_are_bucketed_by_the_targets_local_date_not_utc():
    # tz offset +12:00 -- an entry at UTC 23:00 is already "tomorrow"
    # locally, and must land in tomorrow's bucket, not today's UTC one.
    tz_offset = 12 * 3600
    now_utc = 0  # local: 12:00 on day 0 (epoch day)
    late_utc_entry_dt = 23 * 3600  # UTC 23:00 day 0 -> local 11:00 day 1
    entries = [_entry(late_utc_entry_dt, 20.0)]
    days = daily_forecast(entries, tz_offset, now_utc, days=3)
    assert len(days) == 1  # landed in the (future) local day-1 bucket, not excluded as "today"


def test_today_is_excluded_and_the_next_three_days_are_returned():
    tz_offset = 0
    now_utc = 10 * 3600  # local 10:00 on epoch day 0
    entries = [
        _entry(0 * 86400 + 3600, 15.0),   # today -- excluded
        _entry(1 * 86400 + 3600, 16.0),   # day 1
        _entry(2 * 86400 + 3600, 17.0),   # day 2
        _entry(3 * 86400 + 3600, 18.0),   # day 3
        _entry(4 * 86400 + 3600, 19.0),   # day 4 -- beyond days=3
    ]
    days = daily_forecast(entries, tz_offset, now_utc, days=3)
    assert len(days) == 3
    assert [d.high_c for d in days] == [16.0, 17.0, 18.0]


def test_high_and_low_come_from_temp_max_and_temp_min_across_the_whole_day():
    tz_offset = 0
    now_utc = 0
    entries = [
        _entry(1 * 86400, 20.0, temp_min=18.0, temp_max=22.0),
        _entry(1 * 86400 + 3 * 3600, 25.0, temp_min=24.0, temp_max=30.0),
    ]
    days = daily_forecast(entries, tz_offset, now_utc, days=1)
    assert days[0].high_c == 30.0
    assert days[0].low_c == 18.0


def test_entries_missing_temp_min_max_fall_back_to_temp():
    tz_offset = 0
    now_utc = 0
    entry = {"dt": 1 * 86400, "main": {"temp": 21.0}, "weather": [{"icon": "01d"}]}
    days = daily_forecast([entry], tz_offset, now_utc, days=1)
    assert days[0].high_c == 21.0
    assert days[0].low_c == 21.0


def test_weekday_labels_are_english_under_a_non_english_locale():
    try:
        locale.setlocale(locale.LC_TIME, "hu_HU.UTF-8")
    except locale.Error:
        import pytest
        pytest.skip("hu_HU.UTF-8 locale not installed on this system")
    try:
        tz_offset = 0
        now_utc = 0
        entries = [_entry(1 * 86400 + 3600, 20.0)]
        days = daily_forecast(entries, tz_offset, now_utc, days=1)
        assert days[0].weekday in ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
    finally:
        locale.setlocale(locale.LC_TIME, "C")


def test_representative_symbol_prefers_the_most_significant_daytime_condition():
    tz_offset = 0
    # local hours: 6 (clear), 12 (thunderstorm), 18 (clear) -- all "daytime"
    entries = [
        _entry(6 * 3600, 20.0, icon="01d"),
        _entry(12 * 3600, 22.0, icon="11d"),
        _entry(18 * 3600, 21.0, icon="01d"),
    ]
    icon = representative_icon(entries, tz_offset)
    assert icon == "11d"


def test_night_icons_are_normalised_to_day_variants_in_the_forecast():
    tz_offset = 0
    entries = [_entry(1 * 3600, 20.0, icon="01n")]  # 01:00 local -- outside daytime window
    icon = representative_icon(entries, tz_offset)
    assert icon == "01d"


def test_a_malformed_entry_is_skipped_not_crashed():
    tz_offset = 0
    now_utc = 0
    entries = [
        {"dt": "not-a-number", "main": {"temp": 1.0}},
        {"main": {"temp": 1.0}},  # missing dt
        _entry(1 * 86400 + 3600, 20.0),
    ]
    days = daily_forecast(entries, tz_offset, now_utc, days=1)
    assert len(days) == 1
    assert days[0].high_c == 20.0


def test_representative_icon_returns_none_for_empty_entries():
    assert representative_icon([], 0) is None


def test_representative_icon_falls_back_to_all_entries_when_none_are_daytime():
    tz_offset = 0
    entries = [_entry(1 * 3600, 20.0, icon="03n")]  # 01:00 local, only entry
    icon = representative_icon(entries, tz_offset)
    assert icon == "03d"
