"""
places.sqlite extractor — pulls .onion browsing history from Firefox/Tor Browser.

Schema used:
  moz_places        - URLs, titles, visit counts, last_visit_date
  moz_historyvisits - individual visit timestamps (joined for first visit)

Timestamps are in Firefox format: microseconds since Unix epoch.
"""

import sqlite3
import logging
from typing import List, Dict, Any
from pathlib import Path

from ..logging_utils import extractor, log_extraction_context

logger = logging.getLogger(__name__)


def _validate_places_schema(conn: sqlite3.Connection) -> bool:
    """Check that the database has the expected moz_places table and columns."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='moz_places'")
        if not cursor.fetchone():
            logger.error("moz_places table not found")
            return False

        cursor.execute("PRAGMA table_info(moz_places)")
        columns = {row[1] for row in cursor.fetchall()}
        required = {"id", "url", "title", "visit_count", "last_visit_date"}
        missing = required - columns
        if missing:
            logger.error(f"moz_places missing columns: {missing}")
            return False

        return True
    except sqlite3.Error as e:
        logger.error(f"Schema validation failed: {e}")
        return False


@extractor("places.sqlite", timeout=30.0, required_extensions=[".sqlite", ".db"])
def extract_places_sqlite(db_path: str, include_non_onion: bool = False) -> List[Dict[str, Any]]:
    """
    Extract browsing history from places.sqlite.

    By default only returns .onion URLs. Set include_non_onion=True for full history.
    Opens in immutable read-only mode so we don't interfere with a running browser.

    Returns dicts with: url, title, visit_count, last_visit_date, first_visit_date, places_db_path
    """
    results = []

    try:
        log_extraction_context("places.sqlite", db_path)

        # immutable=1 prevents SQLite from acquiring any locks on the file
        conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True, timeout=10.0)

        if not _validate_places_schema(conn):
            conn.close()
            return []

        cursor = conn.cursor()
        query = """
        SELECT
            p.url,
            p.title,
            p.visit_count,
            p.last_visit_date,
            MIN(h.visit_date) as first_visit_date
        FROM moz_places p
        LEFT JOIN moz_historyvisits h ON p.id = h.place_id
        WHERE p.url IS NOT NULL
        GROUP BY p.id
        ORDER BY p.last_visit_date DESC
        """
        cursor.execute(query)

        while True:
            rows = cursor.fetchmany(1000)
            if not rows:
                break
            for row in rows:
                try:
                    url, title, visit_count, last_visit_date, first_visit_date = row
                    if not url or not isinstance(url, str):
                        continue
                    if not include_non_onion and ".onion" not in url.lower():
                        continue
                    if not visit_count:
                        continue

                    results.append({
                        "url": url,
                        "title": title or None,
                        "visit_count": visit_count,
                        "last_visit_date": last_visit_date or 0,
                        "first_visit_date": first_visit_date or 0,
                        "places_db_path": db_path,
                    })
                except (TypeError, ValueError) as e:
                    logger.debug(f"Skipping malformed row: {e}")
                    continue

        conn.close()
        logger.debug(f"Extracted {len(results)} history entries from {db_path}")

    except sqlite3.DatabaseError as e:
        logger.error(f"Database corruption in {db_path}: {e}")
        return []
    except sqlite3.OperationalError as e:
        if "locked" in str(e).lower():
            logger.error(f"Database locked (browser may be running): {db_path}")
        else:
            logger.error(f"SQLite operational error: {e}")
        return []
    except sqlite3.Error as e:
        logger.error(f"SQLite error reading {db_path}: {type(e).__name__}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error extracting places.sqlite: {type(e).__name__}: {e}")
        return []

    return results


def extract_bookmarks(db_path: str) -> List[Dict[str, Any]]:
    """
    Extract .onion bookmarks from places.sqlite (moz_bookmarks).

    Bookmarks survive "Clear Recent History" in most Firefox configurations,
    making them strong evidence of sustained interest in a site.
    """
    results = []

    if not Path(db_path).exists():
        logger.error(f"places.sqlite not found at {db_path}")
        return []

    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        query = """
        SELECT p.url, b.title, b.dateAdded, b.lastModified
        FROM moz_bookmarks b
        INNER JOIN moz_places p ON b.fk = p.id
        WHERE p.url IS NOT NULL AND b.type = 1
        ORDER BY b.dateAdded DESC
        """
        cursor.execute(query)

        for url, title, date_added, last_modified in cursor.fetchall():
            if ".onion" not in url.lower():
                continue
            results.append({
                "url": url,
                "title": title,
                "date_added": date_added or 0,
                "last_modified": last_modified or 0,
                "places_db_path": db_path,
            })

        conn.close()
        logger.info(f"Extracted {len(results)} .onion bookmarks from {db_path}")

    except sqlite3.Error as e:
        logger.error(f"SQLite error reading bookmarks: {e}", exc_info=True)
    except Exception as e:
        logger.error(f"Unexpected error extracting bookmarks: {e}", exc_info=True)

    return results


def extract_downloads(db_path: str) -> List[Dict[str, Any]]:
    """Download extraction not yet implemented (stored in moz_annos or downloads.json)."""
    logger.warning("Download extraction not implemented")
    return []


def generate_mock_places() -> List[Dict[str, Any]]:
    """Generate mock places.sqlite data for demo mode."""
    mock_sites = [
        {"url": "http://3g2upl4pq6kufc4m.onion", "title": "DuckDuckGo", "visit_count": 42},
        {"url": "http://thehiddenwiki.onion", "title": "The Hidden Wiki", "visit_count": 12},
        {
            "url": "http://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
            "title": "ProtonMail",
            "visit_count": 8,
        },
        {"url": "http://securedrop.onion", "title": "SecureDrop - The Intercept", "visit_count": 5},
    ]

    # Firefox timestamp: microseconds since Unix epoch; base = 2024-12-15 12:00 UTC
    base_timestamp = 1702641600000000

    mock_data = []
    for i, site in enumerate(mock_sites):
        last_visit = base_timestamp + (i * 3600 * 1_000_000)
        first_visit = last_visit - (site["visit_count"] * 86400 * 1_000_000)
        mock_data.append({
            "url": site["url"],
            "title": site["title"],
            "visit_count": site["visit_count"],
            "last_visit_date": last_visit,
            "first_visit_date": first_visit,
            "places_db_path": (
                "C:\\Users\\Alice\\AppData\\Roaming\\Tor Browser\\Browser\\places.sqlite"
            ),
        })

    return mock_data
