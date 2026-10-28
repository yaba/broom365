"""Tiny datetime helpers. All datetimes in the domain layer are timezone-aware UTC."""
from __future__ import annotations

from datetime import datetime, timezone


def parse_graph_dt(value: str | None) -> datetime | None:
    """Parse a Graph ISO-8601 timestamp ('...Z' or offset) into aware UTC; None passes through."""
    if not value:
        return None
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def days_between(earlier: datetime, later: datetime) -> int:
    """Whole days from `earlier` to `later` (negative if `earlier` is in the future)."""
    return (later - earlier).days
