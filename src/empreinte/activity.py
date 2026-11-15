"""Activity aggregation, with explicit ledger and claimed time bases."""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from datetime import tzinfo
from typing import Literal

from .model import Activity, ActivityDay, EntryMeta, Version
from .graph import entry_groups


def compute_activity(entries: Sequence[EntryMeta], versions: Mapping[str, Sequence[Version]],
                     words: Mapping[tuple[str, int], int], *, basis: Literal["claimed", "ledger"],
                     tz: tzinfo | None = None) -> Activity:
    """Count growth in version order, then bucket it by the chosen local time."""
    if basis not in {"claimed", "ledger"}:
        raise ValueError("basis must be claimed or ledger")
    days = {}
    hours = [[0] * 24 for _ in range(7)]
    groups: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    tags: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    path_groups = entry_groups(entries)
    for entry in entries:
        previous = 0
        group = path_groups[entry.entry_id]
        for version in sorted(versions.get(entry.entry_id, ()), key=lambda v: v.version):
            time = version.source_mtime if basis == "claimed" and version.source_mtime else version.timestamp
            local = time.astimezone(tz)
            day = days.setdefault(local.date(), ActivityDay(day=local.date()))
            if version.version == 1:
                day.created += 1
            else:
                day.updated += 1
            current = words.get((entry.entry_id, version.version), 0)
            day.words += max(0, current - previous)
            previous = current
            hours[local.weekday()][local.hour] += 1
            month = local.strftime("%Y-%m")
            groups[month][group].add(entry.entry_id)
            for tag in entry.tags:
                tags[month][tag].add(entry.entry_id)
    return Activity(basis=basis, days=[days[d] for d in sorted(days)], hour_weekday=hours,
        groups_by_month={m: {g: len(ids) for g, ids in sorted(gs.items())} for m, gs in sorted(groups.items())},
        tags_by_month={m: {t: len(ids) for t, ids in sorted(ts.items())} for m, ts in sorted(tags.items())})
