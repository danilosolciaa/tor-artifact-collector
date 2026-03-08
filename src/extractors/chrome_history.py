"""
Chromium browser history extractor (Chrome, Edge, Brave).

Unlike Firefox, Chromium uses a different SQLite schema:
  Table: urls (not moz_places)
  Timestamp format: microseconds since 1601-01-01 (WebKit epoch, same as Windows FILETIME)

Forensic note on .onion URLs in Chrome/Edge/Brave:
Without a Tor proxy configured, any .onion URL will fail DNS resolution.
The URL still gets recorded in history though. These entries show intent to
access Tor hidden services even if the attempt didn't succeed, and can
corroborate Tor Browser artifacts found elsewhere.

WAL recovery is generally impractical for Chromium — it aggressively flushes
and often VACUUMs on "Clear browsing data", so deleted rows are gone.
"""

import sqlite3
import logging
from typing import List, Dict, Any
from datetime import datetime

from ..logging_utils import extractor, log_extraction_context

logger = logging.getLogger(__name__)

# Difference in seconds between the WebKit epoch (1601-01-01) and Unix epoch (1970-01-01)
WEBKIT_EPOCH_OFFSET = 11644473600


@extractor("Chromium History", timeout=30.0, required_extensions=[])
def extract_chrome_history(db_path: str, browser_name: str = "Chrome") -> List[Dict[str, Any]]:
    """
    Extract .onion URLs from a Chromium History database.

    Works for Chrome, Edge, Brave, and any Chromium derivative.
    Returns dicts with: url, title, visit_count, last_visit_time, typed_count, browser, history_db_path.
    """
    results = []

    try:
        log_extraction_context(f"{browser_name} History", db_path)

        conn = sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True, timeout=10.0)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
        if not cursor.fetchone():
            logger.error(f"{browser_name} History missing 'urls' table")
            conn.close()
            return []

        query = """
        SELECT url, title, visit_count, last_visit_time, typed_count
        FROM urls
        WHERE url IS NOT NULL
        ORDER BY last_visit_time DESC
        """
        cursor.execute(query)

        while True:
            rows = cursor.fetchmany(1000)
            if not rows:
                break
            for row in rows:
                try:
                    url, title, visit_count, last_visit_time, typed_count = row
                    if not url or not isinstance(url, str):
                        continue
                    if ".onion" not in url.lower():
                        continue
                    if not visit_count:
                        continue

                    results.append({
                        "url": url,
                        "title": title or None,
                        "visit_count": visit_count,
                        "last_visit_time": last_visit_time or 0,
                        "typed_count": typed_count or 0,
                        "browser": browser_name,
                        "history_db_path": db_path,
                    })
                except (TypeError, ValueError) as e:
                    logger.debug(f"Skipping malformed row in {browser_name} History: {e}")
                    continue

        conn.close()
        logger.debug(f"Extracted {len(results)} .onion entries from {browser_name}")

    except sqlite3.DatabaseError as e:
        logger.error(f"Database corruption in {browser_name} History: {e}")
        return []
    except sqlite3.OperationalError as e:
        if "locked" in str(e).lower():
            logger.error(f"{browser_name} History is locked (browser may be running)")
        else:
            logger.error(f"SQLite error in {browser_name}: {e}")
        return []
    except sqlite3.Error as e:
        logger.error(f"SQLite error: {type(e).__name__}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error: {type(e).__name__}: {e}")
        return []

    return results


def webkit_timestamp_to_iso8601(webkit_time: int) -> str:
    """
    Convert a Chrome/WebKit timestamp to ISO 8601.

    Chrome stores timestamps as microseconds since 1601-01-01 (the Windows
    FILETIME epoch). Dividing by 1,000,000 gives seconds, then subtracting
    11644473600 converts to a Unix timestamp.
    """
    try:
        unix_ts = (webkit_time / 1_000_000) - WEBKIT_EPOCH_OFFSET
        return datetime.utcfromtimestamp(unix_ts).isoformat() + "Z"
    except (ValueError, OSError) as e:
        logger.warning(f"Invalid WebKit timestamp {webkit_time}: {e}")
        return datetime.utcnow().isoformat() + "Z"


def extract_chrome_downloads(db_path: str, browser_name: str = "Chrome") -> List[Dict[str, Any]]:
    """Extract download history. Not yet implemented."""
    logger.warning("Chrome download extraction not yet implemented")
    return []


def extract_all_chromium_browsers(
    chrome_paths: List[str] = None,
    edge_paths: List[str] = None,
    brave_paths: List[str] = None,
) -> List[Dict[str, Any]]:
    """Extract .onion history from all provided Chromium browser databases."""
    all_results = []

    for path in (chrome_paths or []):
        all_results.extend(extract_chrome_history(path, browser_name="Chrome"))

    for path in (edge_paths or []):
        all_results.extend(extract_chrome_history(path, browser_name="Edge"))

    for path in (brave_paths or []):
        all_results.extend(extract_chrome_history(path, browser_name="Brave"))

    logger.info(f"Extracted {len(all_results)} total .onion entries from Chromium browsers")
    return all_results


def generate_mock_chrome() -> List[Dict[str, Any]]:
    """Mock Chrome history — simulates failed .onion lookups (Tor not configured)."""
    base_webkit = 13370000000000000
    return [
        {
            "url": "http://3g2upl4pq6kufc4m.onion",
            "title": "This site can't be reached",
            "visit_count": 1,
            "last_visit_time": base_webkit,
            "typed_count": 1,
            "browser": "Chrome",
            "history_db_path": (
                "C:\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
            ),
        },
        {
            "url": "http://thehiddenwiki.onion",
            "title": None,
            "visit_count": 2,
            "last_visit_time": base_webkit + 3600000000,
            "typed_count": 2,
            "browser": "Chrome",
            "history_db_path": (
                "C:\\Users\\Alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\History"
            ),
        },
    ]


def generate_mock_edge() -> List[Dict[str, Any]]:
    """Mock Edge history."""
    base_webkit = 13370000000000000
    return [
        {
            "url": "http://protonmailrmez3lotccipshtkleegetolb73fuirgj7r4o4vfu7ozyd.onion",
            "title": "DNS_PROBE_FINISHED_NXDOMAIN",
            "visit_count": 1,
            "last_visit_time": base_webkit,
            "typed_count": 0,
            "browser": "Edge",
            "history_db_path": (
                "C:\\Users\\Alice\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\History"
            ),
        },
    ]


def generate_mock_brave() -> List[Dict[str, Any]]:
    """Mock Brave browser history — failed .onion lookups (Tor not configured)."""
    base_webkit = 13370000000000000
    return [
        {
            "url": "http://hss3uro2hsxfogfq.onion",
            "title": "ERR_NAME_NOT_RESOLVED",
            "visit_count": 1,
            "last_visit_time": base_webkit + 7200000000,
            "typed_count": 1,
            "browser": "Brave",
            "history_db_path": (
                "C:\\Users\\Alice\\AppData\\Local\\BraveSoftware\\Brave-Browser"
                "\\User Data\\Default\\History"
            ),
        },
    ]
