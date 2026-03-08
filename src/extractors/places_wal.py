"""
places.sqlite-wal extractor — recovers deleted .onion URLs from the WAL file.

SQLite's Write-Ahead Log (WAL) buffers changes before committing them to the
main database. Deleted records can linger in the WAL even after "Clear Recent
History", because SQLite doesn't zero pages on deletion.

WAL file layout:
  Header: 32 bytes (magic, version, page size, checkpoint info)
  Frames: (24-byte header + page_size bytes) repeated

References:
  https://www.sqlite.org/wal.html
"""

import logging
from typing import List, Dict, Any
from pathlib import Path
import re
import struct
from datetime import datetime, timezone

from ..logging_utils import extractor, log_extraction_context, safe_read_file

logger = logging.getLogger(__name__)


def _file_mtime_iso8601(path: str) -> str:
    """Return the file modification time as ISO 8601 UTC."""
    return (
        datetime.fromtimestamp(Path(path).stat().st_mtime, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _datetime_to_iso8601(dt: datetime) -> str:
    """Return a timezone-aware ISO 8601 UTC string."""
    return dt.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


@extractor("places.sqlite-wal", timeout=30.0, required_extensions=["-wal", ".wal", ".WAL"])
def extract_places_wal(wal_path: str) -> List[Dict[str, Any]]:
    """
    Scan a WAL file for .onion URLs.

    Parses WAL frames properly when the header is valid, falls back to a raw
    binary search otherwise. Deduplicates found URLs and tries to extract a
    nearby title from the surrounding bytes.

    Returns dicts with: url, title, wal_offset, wal_path, confidence
    """
    results = []
    seen_urls: set = set()

    try:
        log_extraction_context("places.sqlite-wal", wal_path)
        wal_mtime = _file_mtime_iso8601(wal_path)

        wal_data = safe_read_file(wal_path, mode="rb", max_size=100 * 1024 * 1024)
        if not wal_data:
            logger.warning(f"WAL file empty or too large: {wal_path}")
            return []

        header = parse_wal_header(wal_data)
        page_size = header.get("page_size") if header.get("valid") else None

        if page_size:
            frames = parse_wal_frames(wal_data, page_size)
            logger.debug(f"Parsed {len(frames)} WAL frames")
        else:
            logger.warning("Invalid WAL header, falling back to raw search")
            frames = []

        onion_pattern = rb"https?://[a-z0-9]{16,56}\.onion[^\s\x00-\x1f]*"

        # Search within frame page data if available, otherwise scan the whole file
        search_regions = (
            [("frame", f["offset"], f["page_data"]) for f in frames]
            if frames
            else [("raw", 0, wal_data)]
        )

        for region_type, base_offset, data in search_regions:
            for match in re.finditer(onion_pattern, data):
                try:
                    url = match.group().decode("utf-8", errors="ignore").strip()
                    if not url.startswith(("http://", "https://")):
                        continue
                    if url in seen_urls:
                        continue
                    seen_urls.add(url)

                    # WAL frame data starts 24 bytes into the frame (after the frame header)
                    actual_offset = (
                        base_offset + 24 + match.start()
                        if region_type == "frame"
                        else match.start()
                    )

                    # Heuristic: look at surrounding bytes for a printable title string
                    title = None
                    try:
                        ctx_start = max(0, match.start() - 100)
                        ctx_end = min(len(data), match.start() + 200)
                        context = data[ctx_start:ctx_end]
                        title_matches = re.findall(rb"[\x20-\x7E]{10,100}", context)
                        if title_matches:
                            candidate = max(title_matches, key=len).decode("utf-8", errors="ignore").strip()
                            if candidate and candidate != url:
                                title = candidate
                    except Exception:
                        pass

                    results.append({
                        "url": url,
                        "title": title,
                        "wal_offset": actual_offset,
                        "wal_path": wal_path,
                        "wal_mtime": wal_mtime,
                        "confidence": "high" if region_type == "frame" else "medium",
                    })

                except (UnicodeDecodeError, Exception) as e:
                    logger.debug(f"Error processing WAL match: {e}")
                    continue

        logger.debug(f"Recovered {len(results)} unique .onion URLs from WAL")

    except Exception as e:
        logger.error(f"Failed to parse WAL file {wal_path}: {type(e).__name__}: {e}")
        return []

    return results


def parse_wal_header(wal_data: bytes) -> Dict[str, Any]:
    """
    Parse the 32-byte WAL file header.

    Layout (all big-endian):
      0-3:   magic (0x377f0682 or 0x377f0683)
      4-7:   file format version
      8-11:  database page size
      12-15: checkpoint sequence number
      16-23: salt values
      24-27: checksum 1
      28-31: checksum 2
    """
    if len(wal_data) < 32:
        return {}

    try:
        magic = struct.unpack(">I", wal_data[0:4])[0]
        page_size = struct.unpack(">I", wal_data[8:12])[0]
        checkpoint_seq = struct.unpack(">I", wal_data[12:16])[0]

        if magic not in (0x377F0682, 0x377F0683):
            logger.warning(f"Invalid WAL magic: 0x{magic:08x}")
            return {}

        # Page size must be a power of 2 between 512 and 65536
        if page_size & (page_size - 1) != 0 or not (512 <= page_size <= 65536):
            logger.warning(f"Invalid page size: {page_size}")
            return {}

        return {
            "magic": magic,
            "page_size": page_size,
            "checkpoint_seq": checkpoint_seq,
            "valid": True,
        }

    except struct.error as e:
        logger.error(f"Error parsing WAL header: {e}")
        return {}


def parse_wal_frames(wal_data: bytes, page_size: int) -> List[Dict[str, Any]]:
    """
    Iterate over WAL frames (24-byte header + page_size bytes each).

    Frame header layout (big-endian):
      0-3:   page number
      4-7:   database size after commit
      8-15:  salt values
      16-19: checksum 1
      20-23: checksum 2
    """
    frames = []
    offset = 32  # skip WAL header
    frame_size = 24 + page_size

    while offset + frame_size <= len(wal_data):
        try:
            page_number = struct.unpack(">I", wal_data[offset:offset + 4])[0]
            db_size = struct.unpack(">I", wal_data[offset + 4:offset + 8])[0]
            page_data = wal_data[offset + 24:offset + 24 + page_size]

            frames.append({
                "page_number": page_number,
                "db_size": db_size,
                "page_data": page_data,
                "offset": offset,
            })
            offset += frame_size

        except struct.error as e:
            logger.debug(f"Error parsing frame at offset {offset}: {e}")
            break

    return frames


def generate_mock_wal() -> List[Dict[str, Any]]:
    """Generate mock WAL recovery data for demo mode.

    These URLs are NOT present in the places.sqlite mock — they were deleted
    before the database was checkpointed, which is the whole point of WAL recovery.
    """
    wal_path = "C:\\Users\\Alice\\AppData\\Roaming\\Tor Browser\\places.sqlite-wal"
    wal_mtime = _datetime_to_iso8601(datetime(2024, 12, 15, 14, 40, 0))
    return [
        {
            # Facebook's real .onion — not in places.sqlite mock, user deleted this visit
            "url": "http://facebookwkhpilnemxj7asber7cy.onion",
            "title": "Facebook (DELETED)",
            "wal_offset": 2048,
            "wal_path": wal_path,
            "wal_mtime": wal_mtime,
            "confidence": "medium",
        },
        {
            "url": "http://darknetmarketxyz.onion/products",
            "title": None,
            "wal_offset": 8192,
            "wal_path": wal_path,
            "wal_mtime": wal_mtime,
            "confidence": "low",
        },
    ]
