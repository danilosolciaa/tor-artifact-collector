"""Extractors for each Windows artifact source.

Each extractor parses raw forensic data and returns a list of dicts
that the normalizers then convert into UnifiedEvent objects.
"""

from .registry import extract_userassist, extract_userassist_live
from .places_sqlite import extract_places_sqlite, extract_bookmarks
from .places_wal import extract_places_wal
from .chrome_history import extract_chrome_history
from .prefetch import extract_prefetch, extract_all_prefetch
from .evtx import extract_evtx

__all__ = [
    "extract_userassist",
    "extract_userassist_live",
    "extract_places_sqlite",
    "extract_bookmarks",
    "extract_places_wal",
    "extract_chrome_history",
    "extract_prefetch",
    "extract_all_prefetch",
    "extract_evtx",
]
