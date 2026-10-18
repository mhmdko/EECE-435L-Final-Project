"""
Author: Mohammad Kourani
"""
from datetime import datetime, timezone


def utc_now():
    """Current time in UTC, stored without timezone info (SQLite has no timezone type)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def to_text(moment):
    """Format a datetime for JSON responses, or None if it is empty."""
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else None
