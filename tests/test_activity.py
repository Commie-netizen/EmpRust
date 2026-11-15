from datetime import datetime, timedelta, timezone

from empreinte.activity import compute_activity
from empreinte.testing import InMemoryVault, stepping_clock


def test_growth_dates_and_distinct_documents():
    vault = InMemoryVault(clock=stepping_clock(datetime(2026, 1, 1, 23, 30, tzinfo=timezone.utc)))
    claimed = datetime(2020, 2, 1, 23, 30, tzinfo=timezone.utc)
    v1 = vault.put("g/a.md", b"one", tags=["t"], source_mtime=claimed)
    vault.put("g/a.md", b"one two", tags=["t"], source_mtime=claimed - timedelta(days=1))
    vault.put("g/a.md", b"short", tags=["t"])
    entries = vault.entries()
    versions = {v1.entry_id: vault.versions(v1.entry_id)}
    words = {(v1.entry_id, 1): 10, (v1.entry_id, 2): 14, (v1.entry_id, 3): 5}
    zone = timezone(timedelta(hours=2))
    ledger = compute_activity(entries, versions, words, basis="ledger", tz=zone)
    assert str(ledger.days[0].day) == "2026-01-02"
    assert ledger.days[0].created == 1 and ledger.days[0].updated == 2
    assert ledger.days[0].words == 14
    assert ledger.hour_weekday[4][1] == 3
    assert ledger.groups_by_month == {"2026-01": {"": 1}}
    assert ledger.tags_by_month == {"2026-01": {"t": 1}}
    activity = compute_activity(entries, versions, words, basis="claimed", tz=zone)
    assert [str(d.day) for d in activity.days] == ["2020-02-01", "2020-02-02", "2026-01-02"]
    assert [d.words for d in activity.days] == [4, 10, 0]


def test_activity_shared_folder_groups():
    for paths, expected in [
        (["root.md", "wiki/index.md", "wiki/sources/a.md", "wiki/conversations/b.md", "wiki/meta/c.md"],
         {"": 2, "sources": 1, "conversations": 1, "meta": 1}),
        (["a/one.md", "b/two.md"], {"a": 1, "b": 1}),
    ]:
        vault = InMemoryVault(clock=stepping_clock())
        for path in paths:
            vault.put(path, b"text")
        entries = vault.entries()
        versions = {e.entry_id: vault.versions(e.entry_id) for e in entries}
        activity = compute_activity(entries, versions, {}, basis="ledger", tz=timezone.utc)
        assert list(activity.groups_by_month.values()) == [expected]
